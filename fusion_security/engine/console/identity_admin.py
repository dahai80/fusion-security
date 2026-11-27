"""fusion-identity admin aggregation client — data source for the four Admin Console zones (Issue #60/#62).

Only hits identity's service-token surface (/api/v1/admin/*, /api/v1/apps/*). The member/IdP
summary endpoints come from upstream fusion-identity#35; until they ship, this client calls
them per the agreed contract and returns a degraded status (available=False + reason) on
404/403 — the frontend renders a degraded card, never fabricated data. All calls carry a
timeout; identity unreachable = degraded, not a 500.
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
_TIMEOUT = 5.0


class IdentityAdminClient:
    def __init__(self, base_url: str = "", service_token: str = ""):
        self._base_url = (base_url or os.environ.get(IDENTITY_URL_ENV, "").strip().rstrip("/")) or _DEFAULT_URL
        self._service_token = service_token or os.environ.get(IDENTITY_TOKEN_ENV, "").strip()

    def _available(self) -> bool:
        # Without a service token everything degrades (API-key-only deployment), no requests sent.
        if not self._service_token:
            logger.info("[IdentityAdmin] %s not set; member/SSO/key aggregation degrades", IDENTITY_TOKEN_ENV)
            return False
        return True

    def _headers(self, tenant_id: str = "default") -> dict[str, str]:
        # identity's global tenant middleware enforces X-Tenant-Id on every route
        # (including the /admin service surface). Global reads pin "default" to
        # satisfy the middleware; tenant reads pass the real tenant.
        return {"Authorization": f"Bearer {self._service_token}", "X-Tenant-Id": tenant_id or "default"}

    def _get(self, path: str, tenant_id: str = "default") -> httpx.Response | None:
        # Unavailable/network failure returns None; the caller records degraded — nothing raised.
        if not self._available():
            return None
        try:
            return httpx.get(
                f"{self._base_url}{path}",
                headers=self._headers(tenant_id),
                timeout=_TIMEOUT,
            )
        except httpx.HTTPError as e:
            logger.warning(f"[IdentityAdmin] request failed {path}: {e}")
            return None

    def list_tenants(self) -> dict[str, Any]:
        # Data source for the tenant selector. GET /api/v1/admin/tenants (service-token surface, exists).
        resp = self._get("/api/v1/admin/tenants")
        if resp is None:
            return {"available": False, "reason": "identity unreachable or service token not configured", "tenants": []}
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] list_tenants non-200: {resp.status_code}")
            return {"available": False, "reason": f"identity responded with {resp.status_code}", "tenants": []}
        rows = resp.json()
        tenants = [
            {
                "tenant_id": t.get("tenant_id", ""),
                "display_name": t.get("display_name", t.get("tenant_id", "")),
                "status": t.get("status", "active"),
                "plan": t.get("plan", ""),
            }
            for t in rows
            if isinstance(t, dict) and t.get("status") != "deleted"
        ]
        return {"available": True, "tenants": tenants}

    def member_summary(self, tenant_id: str) -> dict[str, Any]:
        # Upstream fusion-identity#35 contract: /admin/tenants/{tid}/members/summary.
        resp = self._get(f"/api/v1/admin/tenants/{tenant_id}/members/summary", tenant_id)
        if resp is None:
            return {"available": False, "reason": "identity unreachable or service token not configured"}
        if resp.status_code == 404:
            return {
                "available": False,
                "reason": "identity does not provide the member aggregation endpoint (fusion-identity#35)",
            }
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] member_summary non-200: {resp.status_code}")
            return {"available": False, "reason": f"identity responded with {resp.status_code}"}
        data = resp.json()
        return {
            "available": True,
            "total": int(data.get("total", 0)),
            "active": int(data.get("active", 0)),
            "disabled": int(data.get("disabled", 0)),
            "locked": int(data.get("locked", 0)),
            "by_role": data.get("by_role", {}),
            "pending": int(data.get("pending", 0)),
        }

    def idp_summary(self, tenant_id: str) -> dict[str, Any]:
        # Upstream fusion-identity#35 contract: /admin/tenants/{tid}/idps/summary.
        # The SSO surface only reads capability status — no secret material of any kind.
        resp = self._get(f"/api/v1/admin/tenants/{tenant_id}/idps/summary", tenant_id)
        if resp is None:
            return {
                "available": False,
                "reason": "identity unreachable or service token not configured",
                "configured": False,
            }
        if resp.status_code == 404:
            return {
                "available": False,
                "reason": "identity does not provide the SSO aggregation endpoint (fusion-identity#35)",
                "configured": False,
            }
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] idp_summary non-200: {resp.status_code}")
            return {"available": False, "reason": f"identity responded with {resp.status_code}", "configured": False}
        data = resp.json()
        return {
            "available": True,
            "configured": bool(data.get("configured", False)),
            "count": int(data.get("count", 0)),
            "types": data.get("types", []),
            "auto_provision": bool(data.get("auto_provision", False)),
        }

    def app_secret_inventory(self) -> dict[str, Any]:
        # Upstream fusion-identity#35 contract: /admin/app-secrets (full key inventory).
        resp = self._get("/api/v1/admin/app-secrets")
        if resp is None:
            return {"available": False, "reason": "identity unreachable or service token not configured", "apps": []}
        if resp.status_code == 404:
            return {
                "available": False,
                "reason": "identity does not provide the full key inventory (fusion-identity#35)",
                "apps": [],
            }
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] app_secret_inventory non-200: {resp.status_code}")
            return {"available": False, "reason": f"identity responded with {resp.status_code}", "apps": []}
        return {"available": True, "apps": resp.json().get("apps", [])}

    def app_secrets(self, app_id: str) -> dict[str, Any]:
        # Existing endpoint (no upstream change needed): /apps/{app_id}/secrets — per-app version detail.
        resp = self._get(f"/api/v1/apps/{app_id}/secrets")
        if resp is None:
            return {
                "available": False,
                "reason": "identity unreachable or service token not configured",
                "versions": [],
            }
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] app_secrets({app_id}) non-200: {resp.status_code}")
            return {"available": False, "reason": f"identity responded with {resp.status_code}", "versions": []}
        return {"available": True, "versions": resp.json()}

    def rotate_app_secret(self, app_id: str, grace_seconds: int = 3600) -> dict[str, Any]:
        # Issue #62: rotation goes through identity /apps/{app_id}/secrets/rotate (the old
        # version enters the grace window); the new secret appears exactly once in this
        # response and is never persisted/logged.
        if not self._available():
            return {"ok": False, "reason": "identity unreachable or service token not configured"}
        try:
            resp = httpx.post(
                f"{self._base_url}/api/v1/apps/{app_id}/secrets/rotate",
                json={"grace_seconds": grace_seconds},
                headers=self._headers("default"),
                timeout=_TIMEOUT,
            )
        except httpx.HTTPError as e:
            logger.warning(f"[IdentityAdmin] rotate({app_id}) failed: {e}")
            return {"ok": False, "reason": f"identity unreachable: {e}"}
        if resp.status_code not in (200, 201):
            logger.warning(f"[IdentityAdmin] rotate({app_id}) non-2xx: {resp.status_code} {resp.text[:200]}")
            return {"ok": False, "reason": f"identity responded with {resp.status_code}"}
        data = resp.json()
        return {
            "ok": True,
            "secret": data.get("secret", ""),
            "version": data.get("version"),
            "previous_version": data.get("previous_version"),
            "created_at": data.get("created_at"),
        }

    def revoke_app_secret(self, app_id: str, version: int) -> dict[str, Any]:
        # Upstream fusion-identity#35 request item 4: DELETE /apps/{app_id}/secrets/{version}.
        # Until it ships, 404 → honestly report unavailable; the frontend disables the
        # button + shows the roadmap note, no fabricated success.
        if not self._available():
            return {"ok": False, "reason": "identity unreachable or service token not configured"}
        try:
            resp = httpx.delete(
                f"{self._base_url}/api/v1/apps/{app_id}/secrets/{version}",
                headers=self._headers("default"),
                timeout=_TIMEOUT,
            )
        except httpx.HTTPError as e:
            logger.warning(f"[IdentityAdmin] revoke({app_id}) failed: {e}")
            return {"ok": False, "reason": f"identity unreachable: {e}"}
        if resp.status_code == 404:
            return {"ok": False, "reason": "identity does not provide the revoke endpoint (fusion-identity#35)"}
        if resp.status_code not in (200, 204):
            logger.warning(f"[IdentityAdmin] revoke({app_id} v{version}) non-2xx: {resp.status_code}")
            return {"ok": False, "reason": f"identity responded with {resp.status_code}"}
        return {"ok": True}


_admin_client: IdentityAdminClient | None = None


def get_identity_admin_client() -> IdentityAdminClient:
    global _admin_client
    if _admin_client is None:
        _admin_client = IdentityAdminClient()
    return _admin_client
