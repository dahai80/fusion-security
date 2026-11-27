"""fusion-identity data-plane client — JWT verification + tenant quota + usage reporting.

Calls fusion-identity (port 11470) /api/v1/auth/verify for JWT verification,
carrying FUSION_IDENTITY_SERVICE_TOKEN. Verification failure or unreachability always
raises (fail-closed), which TenantMiddleware converts to 401. Usage reporting is
best-effort; failures only log a warning.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

IDENTITY_URL_ENV = "FUSION_IDENTITY_URL"
IDENTITY_TOKEN_ENV = "FUSION_IDENTITY_SERVICE_TOKEN"
_DEFAULT_URL = "http://127.0.0.1:11470"
_VERIFY_TIMEOUT = 5.0
_USAGE_TIMEOUT = 3.0


def _resolve_url() -> str:
    return os.environ.get(IDENTITY_URL_ENV, "").strip().rstrip("/") or _DEFAULT_URL


def _service_token() -> str:
    return os.environ.get(IDENTITY_TOKEN_ENV, "").strip()


class IdentityVerifyError(Exception):
    """JWT verification failed: invalid token / identity unreachable / non-200."""


class IdentityVerifyClient:
    # Single responsibility: call fusion-identity /verify. No caching (identity owns revocation authority).
    def __init__(self, base_url: str = "", service_token: str = ""):
        self._base_url = base_url or _resolve_url()
        self._service_token = service_token or _service_token()

    def _verify_headers(self) -> dict[str, str]:
        if not self._service_token:
            logger.warning("[Identity] FUSION_IDENTITY_SERVICE_TOKEN not set; JWT verification will fail")
            raise IdentityVerifyError("missing FUSION_IDENTITY_SERVICE_TOKEN")
        return {"Authorization": f"Bearer {self._service_token}", "Content-Type": "application/json"}

    def verify_sync(self, token: str) -> dict[str, Any]:
        # TenantMiddleware's verify_jwt callback is synchronous, so a sync entry point is provided.
        if not token:
            raise IdentityVerifyError("empty token")
        url = f"{self._base_url}/api/v1/auth/verify"
        try:
            resp = httpx.post(url, json={"token": token}, headers=self._verify_headers(), timeout=_VERIFY_TIMEOUT)
        except httpx.HTTPError as e:
            logger.warning(f"[Identity] verify unreachable: {e}")
            raise IdentityVerifyError(f"identity unreachable: {e}") from e
        if resp.status_code != 200:
            logger.warning(f"[Identity] verify non-200: status={resp.status_code} body={resp.text[:200]}")
            raise IdentityVerifyError(f"verify status {resp.status_code}")
        data = resp.json()
        if data.get("revoked"):
            logger.warning(f"[Identity] token revoked tid={data.get('tid')}")
            raise IdentityVerifyError("token revoked")
        return data

    async def report_usage(self, tenant_id: str, payload: dict[str, Any]) -> None:
        # Usage reporting is best-effort: failures only log a warning, never affecting the scan completion flow.
        if not tenant_id:
            return
        if not self._service_token:
            return
        url = f"{self._base_url}/api/v1/tenants/{tenant_id}/usage"
        try:
            async with httpx.AsyncClient(timeout=_USAGE_TIMEOUT) as client:
                resp = await client.post(url, json=payload, headers=self._verify_headers())
            if resp.status_code >= 400:
                logger.warning(f"[Identity] usage report non-2xx: status={resp.status_code} tid={tenant_id}")
        except httpx.HTTPError as e:
            logger.warning(f"[Identity] usage report failed (ignored): tid={tenant_id} err={e}")


_client_singleton: IdentityVerifyClient | None = None


def get_identity_client() -> IdentityVerifyClient:
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = IdentityVerifyClient()
    return _client_singleton


# Tenant quota cache: written by the verify_jwt callback, read by enforce_scan_quota. Populated only on the JWT path.
_tenant_quota: dict[str, dict[str, Any]] = {}


def cache_tenant_quota(tenant_id: str, quota: dict[str, Any]) -> None:
    if tenant_id and quota:
        _tenant_quota[tenant_id] = quota


def get_tenant_quota(tenant_id: str) -> dict[str, Any]:
    return _tenant_quota.get(tenant_id, {})
