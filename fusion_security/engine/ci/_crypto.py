"""P0-5: webhook secret 可逆存储 + 运行时解密签名。

secret 不能只存 sha256(无法回放签名)。用 Fernet 对称加密,key 从
FUSION_SECURITY_MASTER_KEY 派生(PBKDF2-HMAC-SHA256 -> 32B -> base64)。
未设 master key 时派生一个进程级固定 key(单机离线可用,但重启换 key 后旧密文不可解)。
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os

logger = logging.getLogger(__name__)

_MASTER_ENV = "FUSION_SECURITY_MASTER_KEY"
_FALLBACK_SEED = "fusion-security-webhook-default-key"


def _derive_fernet_key() -> bytes:
    seed = os.environ.get(_MASTER_ENV, "").strip() or _FALLBACK_SEED
    digest = hashlib.pbkdf2_hmac("sha256", seed.encode("utf-8"), b"fusion-security-webhook-salt", 100_000, dklen=32)
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    try:
        from cryptography.fernet import Fernet

        token = Fernet(_derive_fernet_key()).encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")
    except Exception as e:
        logger.warning(f"[Crypto] 加密 webhook secret 失败,降级为空: {e}")
        return ""


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        from cryptography.fernet import Fernet

        return Fernet(_derive_fernet_key()).decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception as e:
        logger.warning(f"[Crypto] 解密 webhook secret 失败,签名将被跳过: {e}")
        return ""
