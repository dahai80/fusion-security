"""fusion-identity 集成入口 —— verify_jwt 回调 + 配额缓存。

TenantMiddleware 的 verify_jwt 回调由此构造,调用 IdentityVerifyClient.verify_sync,
成功后缓存该租户配额供 enforce_scan_quota 读取。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .client import IdentityVerifyError, cache_tenant_quota, get_identity_client

__all__ = ["IdentityVerifyError", "make_verify_jwt"]

logger = logging.getLogger(__name__)


def make_verify_jwt() -> Callable[[str], dict[str, Any]]:
    # TenantMiddleware 要求 verify_jwt: Callable[[str], dict[str, Any]] —— 同步。
    # 抛异常 → 中间件返回 401 "invalid token"(fail-closed)。
    client = get_identity_client()

    def _verify(token: str) -> dict[str, Any]:
        claims = client.verify_sync(token)
        tid = claims.get("tid") or claims.get("tenant") or ""
        quota = claims.get("quota") or {}
        cache_tenant_quota(tid, quota)
        logger.debug(f"[Identity] verify ok tid={tid} role={claims.get('role')}")
        return claims

    return _verify
