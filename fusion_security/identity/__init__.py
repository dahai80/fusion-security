"""fusion-identity 集成入口 —— verify_jwt 回调 + 配额缓存。

TenantMiddleware 的 verify_jwt 回调由此构造,调用 IdentityVerifyClient.verify_sync,
成功后缓存该租户配额供 enforce_scan_quota 读取。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .client import IdentityVerifyError, cache_tenant_quota, get_identity_client

__all__ = ["IdentityVerifyError", "make_verify_jwt", "looks_like_jwt"]

logger = logging.getLogger(__name__)


def looks_like_jwt(token: str) -> bool:
    # JWT 形状 = header.payload.signature 三段 base64url。gateway shell 代理
    # (Issue #35)上游注入的是 Bearer <模块 API Key>,非 JWT 形状 —— 这类
    # token 不送 identity 校验,交由 get_principal 按 API Key 验证(fail-closed)。
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def make_verify_jwt() -> Callable[[str], dict[str, Any]]:
    # TenantMiddleware 要求 verify_jwt: Callable[[str], dict[str, Any]] —— 同步。
    # 抛异常 → 中间件返回 401 "invalid token"(fail-closed)。
    # 非 JWT 形状的 Bearer(gateway 模块代理注入的 API Key)返回空 claims
    # 放行中间件,由 get_principal 做真正的 key 校验;校验不过仍 401。
    client = get_identity_client()

    def _verify(token: str) -> dict[str, Any]:
        if not looks_like_jwt(token):
            logger.debug("[Identity] Bearer 非 JWT 形状,转 API Key 路径")
            return {}
        claims = client.verify_sync(token)
        tid = claims.get("tid") or claims.get("tenant") or ""
        quota = claims.get("quota") or {}
        cache_tenant_quota(tid, quota)
        logger.debug(f"[Identity] verify ok tid={tid} role={claims.get('role')}")
        return claims

    return _verify
