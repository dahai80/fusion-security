"""fusion-identity admin 聚合客户端 —— Admin Console 四分区数据源(Issue #60/#62)。

只走 identity 的 service-token 面(/api/v1/admin/*, /api/v1/apps/*)。成员/IdP
summary 端点由上游 fusion-identity#35 提供;未上线前本客户端按约定契约调用,
404/403 时返回 degraded 状态(available=False + reason),前端显示降级卡,
绝不伪造数据。所有调用带超时,identity 不可达 = degraded 而非 500。
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
        # 无服务令牌时全部走 degraded(API-key-only 部署形态),不发请求。
        if not self._service_token:
            logger.info("[IdentityAdmin] %s 未设置,成员/SSO/密钥聚合降级", IDENTITY_TOKEN_ENV)
            return False
        return True

    def _headers(self, tenant_id: str = "default") -> dict[str, str]:
        # identity 全局租户中间件对所有路由强制 X-Tenant-Id(含 /admin 服务面),
        # 全局读固定 default 满足中间件,租户读传真实租户。
        return {"Authorization": f"Bearer {self._service_token}", "X-Tenant-Id": tenant_id or "default"}

    def _get(self, path: str, tenant_id: str = "default") -> httpx.Response | None:
        # 不可用/网络失败返回 None,由调用方落 degraded;不向上抛。
        if not self._available():
            return None
        try:
            return httpx.get(
                f"{self._base_url}{path}",
                headers=self._headers(tenant_id),
                timeout=_TIMEOUT,
            )
        except httpx.HTTPError as e:
            logger.warning(f"[IdentityAdmin] 请求失败 {path}: {e}")
            return None

    def list_tenants(self) -> dict[str, Any]:
        # 租户选择器数据源。GET /api/v1/admin/tenants(service-token 面,已存在)。
        resp = self._get("/api/v1/admin/tenants")
        if resp is None:
            return {"available": False, "reason": "identity 不可达或未配置服务令牌", "tenants": []}
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] list_tenants 非 200: {resp.status_code}")
            return {"available": False, "reason": f"identity 响应 {resp.status_code}", "tenants": []}
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
        # 上游 fusion-identity#35 契约:/admin/tenants/{tid}/members/summary。
        resp = self._get(f"/api/v1/admin/tenants/{tenant_id}/members/summary", tenant_id)
        if resp is None:
            return {"available": False, "reason": "identity 不可达或未配置服务令牌"}
        if resp.status_code == 404:
            return {"available": False, "reason": "identity 未提供成员聚合端点(fusion-identity#35)"}
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] member_summary 非 200: {resp.status_code}")
            return {"available": False, "reason": f"identity 响应 {resp.status_code}"}
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
        # 上游 fusion-identity#35 契约:/admin/tenants/{tid}/idps/summary。
        # SSO 面只读能力状态,不含任何 secret 材料。
        resp = self._get(f"/api/v1/admin/tenants/{tenant_id}/idps/summary", tenant_id)
        if resp is None:
            return {"available": False, "reason": "identity 不可达或未配置服务令牌", "configured": False}
        if resp.status_code == 404:
            return {
                "available": False,
                "reason": "identity 未提供 SSO 聚合端点(fusion-identity#35)",
                "configured": False,
            }
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] idp_summary 非 200: {resp.status_code}")
            return {"available": False, "reason": f"identity 响应 {resp.status_code}", "configured": False}
        data = resp.json()
        return {
            "available": True,
            "configured": bool(data.get("configured", False)),
            "count": int(data.get("count", 0)),
            "types": data.get("types", []),
            "auto_provision": bool(data.get("auto_provision", False)),
        }

    def app_secret_inventory(self) -> dict[str, Any]:
        # 上游 fusion-identity#35 契约:/admin/app-secrets(全量 key 台账)。
        resp = self._get("/api/v1/admin/app-secrets")
        if resp is None:
            return {"available": False, "reason": "identity 不可达或未配置服务令牌", "apps": []}
        if resp.status_code == 404:
            return {"available": False, "reason": "identity 未提供全量 key 台账(fusion-identity#35)", "apps": []}
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] app_secret_inventory 非 200: {resp.status_code}")
            return {"available": False, "reason": f"identity 响应 {resp.status_code}", "apps": []}
        return {"available": True, "apps": resp.json().get("apps", [])}

    def app_secrets(self, app_id: str) -> dict[str, Any]:
        # 既有端点(无需上游改动):/apps/{app_id}/secrets —— 单 app 版本明细。
        resp = self._get(f"/api/v1/apps/{app_id}/secrets")
        if resp is None:
            return {"available": False, "reason": "identity 不可达或未配置服务令牌", "versions": []}
        if resp.status_code != 200:
            logger.warning(f"[IdentityAdmin] app_secrets({app_id}) 非 200: {resp.status_code}")
            return {"available": False, "reason": f"identity 响应 {resp.status_code}", "versions": []}
        return {"available": True, "versions": resp.json()}

    def rotate_app_secret(self, app_id: str, grace_seconds: int = 3600) -> dict[str, Any]:
        # Issue #62: 轮换走 identity /apps/{app_id}/secrets/rotate(旧版本进
        # grace 窗口);新 secret 只在本响应出现一次,绝不落库/日志。
        if not self._available():
            return {"ok": False, "reason": "identity 不可达或未配置服务令牌"}
        try:
            resp = httpx.post(
                f"{self._base_url}/api/v1/apps/{app_id}/secrets/rotate",
                json={"grace_seconds": grace_seconds},
                headers=self._headers("default"),
                timeout=_TIMEOUT,
            )
        except httpx.HTTPError as e:
            logger.warning(f"[IdentityAdmin] rotate({app_id}) 失败: {e}")
            return {"ok": False, "reason": f"identity 不可达: {e}"}
        if resp.status_code not in (200, 201):
            logger.warning(f"[IdentityAdmin] rotate({app_id}) 非 2xx: {resp.status_code} {resp.text[:200]}")
            return {"ok": False, "reason": f"identity 响应 {resp.status_code}"}
        data = resp.json()
        return {
            "ok": True,
            "secret": data.get("secret", ""),
            "version": data.get("version"),
            "previous_version": data.get("previous_version"),
            "created_at": data.get("created_at"),
        }

    def revoke_app_secret(self, app_id: str, version: int) -> dict[str, Any]:
        # 上游 fusion-identity#35 请求项 4:DELETE /apps/{app_id}/secrets/{version}。
        # 未上线前 404 → 如实返回不可用,前端禁用按钮 + roadmap 说明,不伪造成功。
        if not self._available():
            return {"ok": False, "reason": "identity 不可达或未配置服务令牌"}
        try:
            resp = httpx.delete(
                f"{self._base_url}/api/v1/apps/{app_id}/secrets/{version}",
                headers=self._headers("default"),
                timeout=_TIMEOUT,
            )
        except httpx.HTTPError as e:
            logger.warning(f"[IdentityAdmin] revoke({app_id}) 失败: {e}")
            return {"ok": False, "reason": f"identity 不可达: {e}"}
        if resp.status_code == 404:
            return {"ok": False, "reason": "identity 未提供 revoke 端点(fusion-identity#35)"}
        if resp.status_code not in (200, 204):
            logger.warning(f"[IdentityAdmin] revoke({app_id} v{version}) 非 2xx: {resp.status_code}")
            return {"ok": False, "reason": f"identity 响应 {resp.status_code}"}
        return {"ok": True}


_admin_client: IdentityAdminClient | None = None


def get_identity_admin_client() -> IdentityAdminClient:
    global _admin_client
    if _admin_client is None:
        _admin_client = IdentityAdminClient()
    return _admin_client
