"""Issue #32 验收测试:fusion-identity 集成 + 多租户 fail-closed 隔离。

覆盖 7 个验收用例:
1. 空 tenant_id 的 API Key → 401(不泄露全量数据)。
2. 缺 X-Tenant-Id 头 → 401(TenantMiddleware 拦截)。
3. Key 租户 ≠ X-Tenant-Id 头 → 401(get_principal fail-closed)。
4. 跨租户访问漏洞 → 404(fail-closed helper 不泄露存在性)。
5. 已吊销 token → 401(verify_jwt 抛异常)。
6. 纯 JWT principal(无 API Key)→ 200,角色取自 JWT。
7. Key 租户 == X-Tenant-Id 头 → 200(happy path)。

中间件用真实 app 栈(TestClient(create_app())),verify_jwt 经 monkeypatch 桩 IdentityVerifyClient.verify_sync。
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from fusion_security.api.app import create_app
from fusion_security.api.auth import APIKey, auth_manager, get_current_key
from fusion_security.db.session import get_session, init_db


@pytest.fixture
def app_with_db():
    # 真实内存 DB + 真实 AuthManager,验证 fail-closed 全链路。
    init_db(":memory:")
    app = create_app()
    yield app
    app.dependency_overrides.clear()
    db = get_session()
    db.close()


def _seed_key(name: str, tenant_id: str, roles: list[str] | None = None) -> str:
    # 经 AuthManager 落库,返回明文 raw key(测试用)。
    return auth_manager.create_api_key(name, roles or ["admin"], tenant_id=tenant_id)


# ===== 用例 1:空 tenant_id Key → 401 =====


def test_key_without_tenant_returns_401(app_with_db):
    # 真实 principal:get_principal 校验落库 key,空 tenant → 401(不覆盖依赖)。
    raw = _seed_key("notenant", tenant_id="")
    client = TestClient(app_with_db, headers={"X-API-Key": raw, "X-Tenant-Id": "t1"})
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 401


# ===== 用例 2:缺 X-Tenant-Id 头 → 401 =====


def test_missing_tenant_header_returns_401(app_with_db):
    raw = _seed_key("k1", tenant_id="t1")
    client = TestClient(app_with_db, headers={"X-API-Key": raw})
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 401


# ===== 用例 3:Key 租户 ≠ 头 → 401 =====


def test_cross_tenant_scan_denied(app_with_db):
    # 真实 principal:key 租户 t1 ≠ 头 t2 → 401。
    raw = _seed_key("k1", tenant_id="t1")
    client = TestClient(app_with_db, headers={"X-API-Key": raw, "X-Tenant-Id": "t2"})
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 401


# ===== 用例 4:跨租户访问漏洞 → 404 =====


def test_cross_tenant_vuln_access_404(app_with_db):
    # 种 t1 的漏洞;用 t2 principal 请求 → 404。
    from fusion_security.db.models import VulnerabilityORM

    db = get_session()
    try:
        db.add(
            VulnerabilityORM(
                id="v_cross",
                title="SQLi",
                severity="high",
                file_path="a.py",
                line_number=1,
                rule_id="SQL001",
                tenant_id="t1",
            )
        )
        db.commit()
    finally:
        db.close()

    app_with_db.dependency_overrides[get_current_key] = lambda: APIKey(
        key_hash="t", name="k2", roles=["admin"], tenant_id="t2"
    )
    client = TestClient(app_with_db, headers={"X-Tenant-Id": "t2"})
    resp = client.get("/api/v1/vulnerabilities/v_cross")
    assert resp.status_code == 404


# ===== 用例 5:已吊销 token → 401 =====


def test_revoked_token_rejected(app_with_db):
    from fusion_security.identity.client import IdentityVerifyClient

    def _raise(token):
        raise RuntimeError("token revoked")

    with patch.object(IdentityVerifyClient, "verify_sync", side_effect=_raise):
        app_with_db.dependency_overrides[get_current_key] = lambda: APIKey(
            key_hash="t", name="jwt", roles=["admin"], tenant_id="t1"
        )
        client = TestClient(app_with_db, headers={"X-Tenant-Id": "t1"})
        resp = client.get("/api/v1/scans", headers={"Authorization": "Bearer revoked.jwt.token"})
        assert resp.status_code == 401


# ===== 用例 6:纯 JWT principal → 200 =====


def test_jwt_only_principal(app_with_db):
    from fusion_security.identity.client import IdentityVerifyClient

    def _ok(token):
        return {"tid": "t1", "role": "admin", "scopes": ["scan:read"], "quota": {}, "revoked": False}

    with patch.object(IdentityVerifyClient, "verify_sync", side_effect=_ok):
        app_with_db.dependency_overrides[get_current_key] = lambda: APIKey(
            key_hash="", name="jwt", roles=["admin"], tenant_id="t1"
        )
        client = TestClient(app_with_db, headers={"X-Tenant-Id": "t1"})
        resp = client.get("/api/v1/scans", headers={"Authorization": "Bearer valid.jwt.token"})
        assert resp.status_code == 200


# ===== 用例 7:Key 租户 == 头 → 200 =====


def test_apikey_matches_header_proceeds(app_with_db):
    raw = _seed_key("k1", tenant_id="t1")
    client = TestClient(app_with_db, headers={"X-API-Key": raw, "X-Tenant-Id": "t1"})
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
