"""fusion-identity 数据面客户端 —— JWT 校验 + 租户配额 + 用量上报。

调用 fusion-identity(端口 11470)的 /api/v1/auth/verify 做 JWT 校验,
承载 FUSION_IDENTITY_SERVICE_TOKEN。校验失败或不可达一律抛异常(fail-closed),
由 TenantMiddleware 转为 401。用量上报为 best-effort,失败仅告警。
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
    """JWT 校验失败:无效 token / identity 不可达 / 非 200。"""


class IdentityVerifyClient:
    # 单一职责:调用 fusion-identity /verify。无缓存(identity 拥有吊销权)。
    def __init__(self, base_url: str = "", service_token: str = ""):
        self._base_url = base_url or _resolve_url()
        self._service_token = service_token or _service_token()

    def _verify_headers(self) -> dict[str, str]:
        if not self._service_token:
            logger.warning("[Identity] FUSION_IDENTITY_SERVICE_TOKEN 未设置,JWT 校验将失败")
            raise IdentityVerifyError("missing FUSION_IDENTITY_SERVICE_TOKEN")
        return {"Authorization": f"Bearer {self._service_token}", "Content-Type": "application/json"}

    def verify_sync(self, token: str) -> dict[str, Any]:
        # TenantMiddleware 的 verify_jwt 回调是同步的,故提供同步入口。
        if not token:
            raise IdentityVerifyError("empty token")
        url = f"{self._base_url}/api/v1/auth/verify"
        try:
            resp = httpx.post(url, json={"token": token}, headers=self._verify_headers(), timeout=_VERIFY_TIMEOUT)
        except httpx.HTTPError as e:
            logger.warning(f"[Identity] verify 不可达: {e}")
            raise IdentityVerifyError(f"identity unreachable: {e}") from e
        if resp.status_code != 200:
            logger.warning(f"[Identity] verify 非 200: status={resp.status_code} body={resp.text[:200]}")
            raise IdentityVerifyError(f"verify status {resp.status_code}")
        data = resp.json()
        if data.get("revoked"):
            logger.warning(f"[Identity] token 已吊销 tid={data.get('tid')}")
            raise IdentityVerifyError("token revoked")
        return data

    async def report_usage(self, tenant_id: str, payload: dict[str, Any]) -> None:
        # 用量上报 best-effort:失败仅告警,不影响扫描完成流程。
        if not tenant_id:
            return
        if not self._service_token:
            return
        url = f"{self._base_url}/api/v1/tenants/{tenant_id}/usage"
        try:
            async with httpx.AsyncClient(timeout=_USAGE_TIMEOUT) as client:
                resp = await client.post(url, json=payload, headers=self._verify_headers())
            if resp.status_code >= 400:
                logger.warning(f"[Identity] usage 上报非 2xx: status={resp.status_code} tid={tenant_id}")
        except httpx.HTTPError as e:
            logger.warning(f"[Identity] usage 上报失败(忽略): tid={tenant_id} err={e}")


_client_singleton: IdentityVerifyClient | None = None


def get_identity_client() -> IdentityVerifyClient:
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = IdentityVerifyClient()
    return _client_singleton


# 租户配额缓存:verify_jwt 回调写入,enforce_scan_quota 读取。仅 JWT 路径填充。
_tenant_quota: dict[str, dict[str, Any]] = {}


def cache_tenant_quota(tenant_id: str, quota: dict[str, Any]) -> None:
    if tenant_id and quota:
        _tenant_quota[tenant_id] = quota


def get_tenant_quota(tenant_id: str) -> dict[str, Any]:
    return _tenant_quota.get(tenant_id, {})
