"""P0-5: webhook secret 可逆存储 + 运行时解密签名。

secret 不能只存 sha256(无法回放签名)。用 Fernet 对称加密,key 从
FUSION_SECURITY_MASTER_KEY 派生(PBKDF2-HMAC-SHA256 -> 32B -> base64)。
Issue #50(config-conventions §3):key 未设置不再回退可猜测默认字面量 ——
dev 用进程级随机 seed(重启后旧密文不可解)+ 醒目警告;prod 直接
RuntimeError(变量名 + 获取方式 + 文档路径三要素)。
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets

logger = logging.getLogger(__name__)

_MASTER_ENV = "FUSION_SECURITY_MASTER_KEY"
_DEV_SEED: str | None = None


def _dev_seed() -> str:
    # 进程级随机 seed:同进程内加解密一致,重启后旧密文不可解 —— 永不落回已知常量。
    global _DEV_SEED
    if _DEV_SEED is None:
        _DEV_SEED = secrets.token_urlsafe(32)
        logger.warning(
            f"[Crypto] {_MASTER_ENV} 未设置 —— dev 模式使用进程级随机 key,"
            f"已存 webhook 密文重启后不可解。生成并导出: "
            f'python -c "import secrets; print(secrets.token_urlsafe(32))";'
            f"见 architecture/config-conventions.md"
        )
    return _DEV_SEED


def _derive_fernet_key() -> bytes:
    seed = os.environ.get(_MASTER_ENV, "").strip()
    if not seed:
        if os.getenv("FUSION_PROFILE", "dev") == "prod":
            raise RuntimeError(
                f"{_MASTER_ENV} not set — 生成方式: "
                f'python -c "import secrets; print(secrets.token_urlsafe(32))", '
                f"启动服务前导出该环境变量;见 architecture/config-conventions.md"
            )
        seed = _dev_seed()
    digest = hashlib.pbkdf2_hmac("sha256", seed.encode("utf-8"), b"fusion-security-webhook-salt", 100_000, dklen=32)
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    # prod 缺 key 在此 RuntimeError,fail-fast 向上传播,不落入下面的静默降级。
    key = _derive_fernet_key()
    try:
        from cryptography.fernet import Fernet

        return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except Exception as e:
        logger.warning(f"[Crypto] 加密 webhook secret 失败,降级为空: {e}")
        return ""


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    key = _derive_fernet_key()
    try:
        from cryptography.fernet import Fernet

        return Fernet(key).decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception as e:
        logger.warning(f"[Crypto] 解密 webhook secret 失败,签名将被跳过: {e}")
        return ""
