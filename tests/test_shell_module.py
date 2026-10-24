"""Issue #35 验收测试:union-web shell 模块接入。

覆盖:
A. shell_registry —— 开关门控 / manifest 加载 / 注册往返 / 心跳循环(含失败限频与恢复)。
B. looks_like_jwt + make_verify_jwt —— 非 JWT 形状 Bearer(gateway 模块代理注入的
   API Key)不送 identity,交由 get_principal 校验。
C. E2E —— Bearer 模块 key 走真实 app 栈鉴权(有效 200 / 无效 401 / 空租户 401 / 租户不匹配 401)。
D. lifespan —— 注册任务启停(env 门控)。
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from fusion_security import shell_registry
from fusion_security.api.app import create_app
from fusion_security.api.auth import auth_manager
from fusion_security.db.session import get_session, init_db
from fusion_security.identity import looks_like_jwt, make_verify_jwt


@pytest.fixture
def app_with_db():
    init_db(":memory:")
    app = create_app()
    yield app
    app.dependency_overrides.clear()
    db = get_session()
    db.close()


# ---------- A. shell_registry ----------


def test_registration_disabled_without_env(monkeypatch):
    monkeypatch.delenv(shell_registry.GATEWAY_URL_ENV, raising=False)
    monkeypatch.delenv(shell_registry.ADMIN_KEY_ENV, raising=False)
    assert shell_registry.shell_registration_enabled() is False
    monkeypatch.setenv(shell_registry.GATEWAY_URL_ENV, "http://127.0.0.1:11432")
    assert shell_registry.shell_registration_enabled() is False
    monkeypatch.setenv(shell_registry.ADMIN_KEY_ENV, "fg-admin-key")
    assert shell_registry.shell_registration_enabled() is True


def test_default_manifest_exists_and_valid():
    manifest = shell_registry._load_manifest()
    assert manifest["id"] == "fusion-security"
    assert manifest["category"] == "domain"
    assert manifest["entry"] == "/shell/fusion-security/"
    assert "desktop" in manifest["devices"]
    assert set(manifest["devices"]) <= {"desktop", "mobile-ready", "mobile-readonly", "desktop-only"}


def test_load_manifest_env_override(monkeypatch, tmp_path):
    custom = tmp_path / "m.json"
    custom.write_text(json.dumps({"id": "x-mod", "title": "X"}), encoding="utf-8")
    monkeypatch.setenv(shell_registry.MANIFEST_PATH_ENV, str(custom))
    assert shell_registry._load_manifest()["id"] == "x-mod"


def test_load_manifest_missing_file_raises(monkeypatch, tmp_path):
    monkeypatch.setenv(shell_registry.MANIFEST_PATH_ENV, str(tmp_path / "nope.json"))
    with pytest.raises(FileNotFoundError):
        shell_registry._load_manifest()


def test_load_manifest_missing_id_raises(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"title": "no-id"}), encoding="utf-8")
    monkeypatch.setenv(shell_registry.MANIFEST_PATH_ENV, str(bad))
    with pytest.raises(ValueError):
        shell_registry._load_manifest()


@pytest.mark.asyncio
async def test_register_once_success(monkeypatch):
    monkeypatch.setenv(shell_registry.GATEWAY_URL_ENV, "http://127.0.0.1:11432")
    monkeypatch.setenv(shell_registry.ADMIN_KEY_ENV, "fg-admin-key")

    class _Resp:
        status_code = 201
        text = ""

    class _Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json=None, headers=None):
            _Client.last = (url, json, headers)
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    ok, reason = await shell_registry.register_once()
    assert ok is True and reason == ""
    url, body, headers = _Client.last
    assert url == "http://127.0.0.1:11432/api/v1/shell/manifests"
    assert body["id"] == "fusion-security"
    assert headers["Authorization"] == "Bearer fg-admin-key"


@pytest.mark.asyncio
async def test_register_once_rejects_non_2xx(monkeypatch):
    monkeypatch.setenv(shell_registry.GATEWAY_URL_ENV, "http://gw")
    monkeypatch.setenv(shell_registry.ADMIN_KEY_ENV, "k")

    class _Resp:
        status_code = 403
        text = "forbidden"

    class _Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json=None, headers=None):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    ok, reason = await shell_registry.register_once()
    assert ok is False
    assert "403" in reason and "forbidden" in reason


@pytest.mark.asyncio
async def test_run_registry_heartbeats_and_recovers(monkeypatch):
    calls = {"n": 0}

    async def _fake_register():
        calls["n"] += 1
        if calls["n"] % 2 == 1:
            return False, "synthetic failure"
        return True, ""

    monkeypatch.setattr(shell_registry, "register_once", _fake_register)
    monkeypatch.setattr(shell_registry, "REGISTER_INTERVAL_SECONDS", 0.01)
    task = asyncio.create_task(shell_registry.run_shell_registry())
    await asyncio.sleep(0.08)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls["n"] >= 3


@pytest.mark.asyncio
async def test_run_registry_survives_exceptions(monkeypatch):
    calls = {"n": 0}

    async def _boom():
        calls["n"] += 1
        raise RuntimeError("gateway down")

    monkeypatch.setattr(shell_registry, "register_once", _boom)
    monkeypatch.setattr(shell_registry, "REGISTER_INTERVAL_SECONDS", 0.01)
    task = asyncio.create_task(shell_registry.run_shell_registry())
    await asyncio.sleep(0.05)
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls["n"] >= 2


# ---------- B. 非 JWT Bearer 容忍 ----------


def test_looks_like_jwt():
    assert looks_like_jwt("eyJhb.eyJjbGFpbXMi.sig") is True
    assert looks_like_jwt("fs-shell-module-key-123") is False
    assert looks_like_jwt("two.parts") is False
    assert looks_like_jwt("") is False
    assert looks_like_jwt("a..c") is False


def test_verify_jwt_short_circuits_non_jwt():
    from fusion_security.identity.client import IdentityVerifyClient

    def _must_not_call(self, token):
        raise AssertionError("identity must not be called for non-JWT bearer")

    with patch.object(IdentityVerifyClient, "verify_sync", _must_not_call):
        verify = make_verify_jwt()
        assert verify("fs-shell-module-key-123") == {}


def test_verify_jwt_still_calls_identity_for_jwt_shape():
    from fusion_security.identity.client import IdentityVerifyClient

    with patch.object(
        IdentityVerifyClient, "verify_sync", lambda self, token: {"tid": "t1", "role": "viewer", "quota": {}}
    ):
        verify = make_verify_jwt()
        assert verify("eyJhb.eyJ0aWQiOiJ0MSJ9.sig")["tid"] == "t1"


# ---------- C. E2E: gateway 模块代理注入的 Bearer key ----------


def _seed_key(name: str, tenant_id: str, roles: list[str] | None = None) -> str:
    return auth_manager.create_api_key(name, roles or ["admin"], tenant_id=tenant_id)


def test_bearer_module_key_happy_path(app_with_db):
    raw = _seed_key("shell-module", "tenant-a")
    # 非 lifespan 栈(与既有 test_tenant_isolation 同法):中间件在 create_app 已装好。
    client = TestClient(app_with_db)
    resp = client.get("/api/v1/projects", headers={"Authorization": f"Bearer {raw}", "X-Tenant-Id": "tenant-a"})
    assert resp.status_code == 200


def test_bearer_module_key_invalid_rejected(app_with_db):
    client = TestClient(app_with_db)
    resp = client.get("/api/v1/projects", headers={"Authorization": "Bearer not-a-real-key", "X-Tenant-Id": "t"})
    assert resp.status_code == 401


def test_bearer_module_key_without_tenant_rejected(app_with_db):
    # Bearer key 校验走 auth_manager;空租户 key fail-closed。
    raw = auth_manager.create_api_key("no-tenant-key", ["admin"])
    client = TestClient(app_with_db)
    resp = client.get("/api/v1/projects", headers={"Authorization": f"Bearer {raw}", "X-Tenant-Id": "t"})
    assert resp.status_code == 401


def test_bearer_module_key_tenant_mismatch_rejected(app_with_db):
    raw = _seed_key("shell-module-2", "tenant-a")
    client = TestClient(app_with_db)
    resp = client.get("/api/v1/projects", headers={"Authorization": f"Bearer {raw}", "X-Tenant-Id": "tenant-b"})
    assert resp.status_code == 401


# ---------- D. lifespan 注册任务启停 ----------


def test_lifespan_starts_registry_task_when_enabled(monkeypatch, app_with_db, tmp_path):
    # lifespan 会再调一次无参 init_db() —— 用 FUSION_DB_PATH 指到临时文件,
    # 避免测试写真实 ~/.fusion-security DB。
    monkeypatch.setenv("FUSION_DB_PATH", str(tmp_path / "lifespan.db"))
    monkeypatch.setenv(shell_registry.GATEWAY_URL_ENV, "http://127.0.0.1:11432")
    monkeypatch.setenv(shell_registry.ADMIN_KEY_ENV, "fg-admin-key")
    calls = {"n": 0}

    async def _fake_run():
        calls["n"] += 1
        await asyncio.Event().wait()

    with patch.object(shell_registry, "run_shell_registry", _fake_run), TestClient(app_with_db) as client:
        assert client.get("/api/v1/system/health").status_code == 200
        assert calls["n"] == 1
    # 退出 lifespan 后任务已被取消(cancel 不抛错即通过)。


def test_lifespan_skips_registry_task_when_disabled(monkeypatch, app_with_db, tmp_path):
    monkeypatch.setenv("FUSION_DB_PATH", str(tmp_path / "lifespan.db"))
    monkeypatch.delenv(shell_registry.GATEWAY_URL_ENV, raising=False)
    monkeypatch.delenv(shell_registry.ADMIN_KEY_ENV, raising=False)

    async def _must_not_run():
        raise AssertionError("registry must not run when disabled")

    with patch.object(shell_registry, "run_shell_registry", _must_not_run), TestClient(app_with_db) as client:
        assert client.get("/api/v1/system/health").status_code == 200
