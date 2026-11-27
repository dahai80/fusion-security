"""fusion-identity integration entry — verify_jwt callback + quota cache.

TenantMiddleware's verify_jwt callback is constructed here; it calls
IdentityVerifyClient.verify_sync, and on success caches the tenant quota for
enforce_scan_quota to read.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .client import IdentityVerifyError, cache_tenant_quota, get_identity_client

__all__ = ["IdentityVerifyError", "make_verify_jwt", "looks_like_jwt"]

logger = logging.getLogger(__name__)


def looks_like_jwt(token: str) -> bool:
    # JWT shape = header.payload.signature, three base64url segments. The gateway shell proxy
    # (Issue #35) injects Bearer <module API key> upstream, which is not JWT-shaped — such
    # tokens are not sent to identity for verification; they go to get_principal for API-key
    # validation (fail-closed).
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def make_verify_jwt() -> Callable[[str], dict[str, Any]]:
    # TenantMiddleware requires verify_jwt: Callable[[str], dict[str, Any]] — synchronous.
    # Raising -> middleware returns 401 "invalid token" (fail-closed).
    # Non-JWT-shaped Bearer tokens (API keys injected by the gateway module proxy) return empty claims
    # to pass the middleware; get_principal does the real key validation; failure still yields 401.
    client = get_identity_client()

    def _verify(token: str) -> dict[str, Any]:
        if not looks_like_jwt(token):
            logger.debug("[Identity] Bearer token is not JWT-shaped; falling back to the API-key path")
            return {}
        claims = client.verify_sync(token)
        tid = claims.get("tid") or claims.get("tenant") or ""
        quota = claims.get("quota") or {}
        cache_tenant_quota(tid, quota)
        logger.debug(f"[Identity] verify ok tid={tid} role={claims.get('role')}")
        return claims

    return _verify
