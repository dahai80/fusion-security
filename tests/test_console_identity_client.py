"""IdentityAdminClient unit tests: mock httpx, cover live-call paths + degradation."""

import httpx
import pytest

from fusion_security.engine.console import identity_admin as ia


def _resp(status=200, payload=None, text=""):
    if payload is not None:
        return httpx.Response(status, json=payload, request=httpx.Request("GET", "http://x"))
    return httpx.Response(status, text=text, request=httpx.Request("GET", "http://x"))


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(ia.IDENTITY_URL_ENV, "http://127.0.0.1:19999")
    monkeypatch.setenv(ia.IDENTITY_TOKEN_ENV, "svc-token")
    monkeypatch.setattr(ia, "_admin_client", None)
    c = ia.IdentityAdminClient()
    yield c
    ia._admin_client = None


class TestListTenants:
    def test_ok(self, client, monkeypatch):
        monkeypatch.setattr(
            ia.httpx,
            "get",
            lambda *a, **k: _resp(
                200,
                [
                    {"tenant_id": "t1", "display_name": "T1", "status": "active", "plan": "pro"},
                    {"tenant_id": "t2", "status": "deleted"},
                    "junk",
                ],
            ),
        )
        out = client.list_tenants()
        assert out["available"] is True
        assert [t["tenant_id"] for t in out["tenants"]] == ["t1"]
        assert out["tenants"][0]["display_name"] == "T1"

    def test_non_200(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(500))
        out = client.list_tenants()
        assert out["available"] is False
        assert "500" in out["reason"]

    def test_network_fail(self, client, monkeypatch):
        def boom(*a, **k):
            raise httpx.ConnectError("down")

        monkeypatch.setattr(ia.httpx, "get", boom)
        out = client.list_tenants()
        assert out["available"] is False


class TestMemberSummary:
    def test_ok(self, client, monkeypatch):
        seen = {}

        def fake_get(url, headers=None, timeout=None):
            seen["url"] = url
            seen["headers"] = headers
            return _resp(200, {"total": 8, "active": 7, "disabled": 1, "locked": 0, "by_role": {}, "pending": 2})

        monkeypatch.setattr(ia.httpx, "get", fake_get)
        out = client.member_summary("t9")
        assert out["available"] is True and out["total"] == 8
        assert "/api/v1/admin/tenants/t9/members/summary" in seen["url"]
        # identity 全局中间件要求所有调用带 X-Tenant-Id
        assert seen["headers"]["X-Tenant-Id"] == "t9"
        assert seen["headers"]["Authorization"] == "Bearer svc-token"

    def test_404_upstream_pending(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(404))
        out = client.member_summary("t9")
        assert out["available"] is False
        assert "fusion-identity#35" in out["reason"]

    def test_non_200(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(403))
        out = client.member_summary("t9")
        assert out["available"] is False and "403" in out["reason"]


class TestIdpSummary:
    def test_ok(self, client, monkeypatch):
        monkeypatch.setattr(
            ia.httpx,
            "get",
            lambda *a, **k: _resp(200, {"configured": True, "count": 1, "types": ["oidc"], "auto_provision": True}),
        )
        out = client.idp_summary("t9")
        assert out["available"] is True and out["configured"] is True and out["types"] == ["oidc"]

    def test_404(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(404))
        out = client.idp_summary("t9")
        assert out["available"] is False and out["configured"] is False
        assert "fusion-identity#35" in out["reason"]

    def test_non_200(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(502))
        out = client.idp_summary("t9")
        assert out["available"] is False and "502" in out["reason"]


class TestAppSecrets:
    def test_inventory_ok(self, client, monkeypatch):
        monkeypatch.setattr(
            ia.httpx, "get", lambda *a, **k: _resp(200, {"apps": [{"app_id": "fusion-mlx", "current_version": 2}]})
        )
        out = client.app_secret_inventory()
        assert out["available"] is True and out["apps"][0]["app_id"] == "fusion-mlx"

    def test_inventory_404(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(404))
        out = client.app_secret_inventory()
        assert out["available"] is False and out["apps"] == []
        assert "fusion-identity#35" in out["reason"]

    def test_inventory_non_200(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(500))
        out = client.app_secret_inventory()
        assert out["available"] is False and "500" in out["reason"]

    def test_single_app_ok(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(200, [{"version": 2, "status": "active"}]))
        out = client.app_secrets("fusion-mlx")
        assert out["available"] is True and out["versions"][0]["version"] == 2

    def test_single_app_fail(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "get", lambda *a, **k: _resp(404))
        out = client.app_secrets("nope")
        assert out["available"] is False and out["versions"] == []


class TestRotate:
    def test_ok(self, client, monkeypatch):
        seen = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            seen["url"] = url
            seen["json"] = json
            return httpx.Response(
                200,
                json={"secret": "fms_new", "version": 3, "previous_version": 2, "created_at": "2026-11-01"},
                request=httpx.Request("POST", url),
            )

        monkeypatch.setattr(ia.httpx, "post", fake_post)
        out = client.rotate_app_secret("fusion-mlx", grace_seconds=120)
        assert out["ok"] is True and out["secret"] == "fms_new" and out["version"] == 3
        assert "/api/v1/apps/fusion-mlx/secrets/rotate" in seen["url"]
        assert seen["json"] == {"grace_seconds": 120}

    def test_non_2xx(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "post", lambda *a, **k: _resp(409, text="conflict"))
        out = client.rotate_app_secret("fusion-mlx")
        assert out["ok"] is False and "409" in out["reason"]

    def test_network_fail(self, client, monkeypatch):
        def boom(*a, **k):
            raise httpx.ConnectError("down")

        monkeypatch.setattr(ia.httpx, "post", boom)
        out = client.rotate_app_secret("fusion-mlx")
        assert out["ok"] is False


class TestRevoke:
    def test_no_content(self, client, monkeypatch):
        seen = {}

        def fake_delete(url, headers=None, timeout=None):
            seen["url"] = url
            return httpx.Response(204, request=httpx.Request("DELETE", url))

        monkeypatch.setattr(ia.httpx, "delete", fake_delete)
        out = client.revoke_app_secret("fusion-mlx", 2)
        assert out["ok"] is True
        assert "/api/v1/apps/fusion-mlx/secrets/2" in seen["url"]

    def test_404_upstream_pending(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "delete", lambda *a, **k: _resp(404))
        out = client.revoke_app_secret("fusion-mlx", 2)
        assert out["ok"] is False and "fusion-identity#35" in out["reason"]

    def test_non_2xx(self, client, monkeypatch):
        monkeypatch.setattr(ia.httpx, "delete", lambda *a, **k: _resp(500))
        out = client.revoke_app_secret("fusion-mlx", 2)
        assert out["ok"] is False and "500" in out["reason"]

    def test_network_fail(self, client, monkeypatch):
        def boom(*a, **k):
            raise httpx.ConnectError("down")

        monkeypatch.setattr(ia.httpx, "delete", boom)
        out = client.revoke_app_secret("fusion-mlx", 2)
        assert out["ok"] is False


class TestDegradedWithoutToken:
    def test_no_token_no_request(self, monkeypatch):
        monkeypatch.delenv(ia.IDENTITY_TOKEN_ENV, raising=False)
        calls = []

        def fail(*a, **k):
            calls.append(1)
            raise AssertionError("must not call identity without token")

        monkeypatch.setattr(ia.httpx, "get", fail)
        monkeypatch.setattr(ia.httpx, "post", fail)
        monkeypatch.setattr(ia.httpx, "delete", fail)
        c = ia.IdentityAdminClient()
        assert c.list_tenants()["available"] is False
        assert c.member_summary("t")["available"] is False
        assert c.idp_summary("t")["available"] is False
        assert c.app_secret_inventory()["available"] is False
        assert c.app_secrets("a")["available"] is False
        assert c.rotate_app_secret("a")["ok"] is False
        assert c.revoke_app_secret("a", 1)["ok"] is False
        assert calls == []

    def test_singleton(self, monkeypatch):
        monkeypatch.setattr(ia, "_admin_client", None)
        monkeypatch.setenv(ia.IDENTITY_TOKEN_ENV, "x")
        c1 = ia.get_identity_admin_client()
        c2 = ia.get_identity_admin_client()
        assert c1 is c2
        ia._admin_client = None
