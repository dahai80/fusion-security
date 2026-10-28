"""Issue #52 / #53 回归:fusion_core 单点配置解析 + shell 模块 key 落库。"""

from __future__ import annotations

import inspect
import logging

import pytest
from fastapi.testclient import TestClient

from fusion_security.api.app import create_app, set_process_title
from fusion_security.api.auth import auth_manager
from fusion_security.db.session import get_session, init_db
from fusion_security.engine.ai import analyzer as analyzer_mod
from fusion_security.engine.ai.analyzer import AIAnalyzer
from fusion_security.shell_registry import MODULE_KEY_ENV


@pytest.fixture
def clean_key_env(monkeypatch):
    # client_key 别名链清零,避免宿主环境泄漏进断言。
    for var in ("FUSION_CLIENT_KEY", "FUSION_MLX_API_KEY", "MLX_API_KEY", "FUSION_PROFILE"):
        monkeypatch.delenv(var, raising=False)


class TestAnalyzerClientKey:
    def test_reads_fusion_client_key(self, clean_key_env, monkeypatch):
        monkeypatch.setenv("FUSION_CLIENT_KEY", "ck-test-1")
        assert AIAnalyzer()._api_key == "ck-test-1"

    def test_legacy_alias_still_resolves(self, clean_key_env, monkeypatch, caplog):
        monkeypatch.setenv("FUSION_MLX_API_KEY", "legacy-key")
        with caplog.at_level(logging.WARNING):
            assert AIAnalyzer()._api_key == "legacy-key"
        assert any("FUSION_CLIENT_KEY" in r.message for r in caplog.records)

    def test_prod_missing_key_raises(self, clean_key_env, monkeypatch):
        monkeypatch.setenv("FUSION_PROFILE", "prod")
        with pytest.raises(RuntimeError, match="FUSION_CLIENT_KEY"):
            AIAnalyzer()

    def test_dev_missing_key_empty(self, clean_key_env):
        assert AIAnalyzer()._api_key == ""

    def test_no_local_key_resolver_in_source(self):
        # Issue #52 验收镜像:解析函数不得回潮(grep 'def _resolve.*key' 须为空)。
        assert "def _resolve_mlx_api_key" not in inspect.getsource(analyzer_mod)


class TestServicePortTitle:
    def test_invalid_port_env_no_raise(self, monkeypatch):
        setproctitle = pytest.importorskip("setproctitle")
        calls = []
        monkeypatch.setattr(setproctitle, "setproctitle", lambda t: calls.append(t))
        monkeypatch.setenv("FUSION_SECURITY_PORT", "not-a-number")
        set_process_title()  # 非整数端口:记警告,不抛异常,不设置错误标题
        assert calls == []


class TestEnsureModuleKey:
    def test_upsert_admin_role_and_tenant(self):
        init_db(":memory:")
        auth_manager.ensure_module_key("fs-shell-upsert-1", "t1")
        key = auth_manager.validate_key("fs-shell-upsert-1")
        assert key is not None
        assert key.roles == ["admin"]
        assert key.tenant_id == "t1"
        # 幂等:同 key 再落库(租户变化)只更新,不产生第二行。
        auth_manager.ensure_module_key("fs-shell-upsert-1", "t2")
        key2 = auth_manager.validate_key("fs-shell-upsert-1")
        assert key2.tenant_id == "t2"
        db = get_session()
        try:
            from fusion_security.db.models import ApiKeyORM

            rows = db.query(ApiKeyORM).filter(ApiKeyORM.name == "shell-module").all()
            assert len(rows) == 1
            assert rows[0].role == "admin"
        finally:
            db.close()


class TestLifespanModuleKeyProvisioning:
    # lifespan 内 init_db() 无参调用会重新解析 DB URL —— 必须 monkeypatch
    # FUSION_DB_PATH 到临时文件,否则全局 engine 被重定向到真实
    # ~/.fusion-security/fusion_security.db(测试写脏生产库)。
    def test_provisioned_key_passes_health_detailed(self, monkeypatch, tmp_path):
        # Issue #53 E2E:lifespan 落库模块 key(admin + 租户对齐),
        # 经 shell 同款注入路径(Bearer 非 JWT 形状)调 system:manage 端点 → 200。
        monkeypatch.setenv("FUSION_DB_PATH", str(tmp_path / "e2e.db"))
        monkeypatch.setenv(MODULE_KEY_ENV, "fs-shell-e2e-key")
        monkeypatch.setenv("FUSION_SECURITY_SHELL_TENANT", "default")
        app = create_app()
        with TestClient(app) as client:
            resp = client.get(
                "/api/v1/system/health/detailed",
                headers={"X-Tenant-Id": "default", "Authorization": "Bearer fs-shell-e2e-key"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] in ("ok", "degraded")

    def test_no_env_skips_provisioning(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FUSION_DB_PATH", str(tmp_path / "noenv.db"))
        monkeypatch.delenv(MODULE_KEY_ENV, raising=False)
        app = create_app()
        with TestClient(app):
            db = get_session()
            try:
                from fusion_security.db.models import ApiKeyORM

                assert db.query(ApiKeyORM).filter(ApiKeyORM.name == "shell-module").count() == 0
            finally:
                db.close()


class TestErrorEnvelope:
    def test_401_body_has_top_level_message(self, monkeypatch):
        # 双重回归:(1) 只带 X-Tenant-Id 的匿名请求必须 401 —— 此前
        # TenantMiddleware(require_jwt=False)构造无凭证 TenantContext,
        # get_principal 末分支兜底发 viewer,fail-open;(2) Issue #53:web-shell
        # 宿主只读顶层 message,缺失时 RBAC 真实原因被泛化。
        init_db(":memory:")
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/v1/scans", headers={"X-Tenant-Id": "default"})
        assert resp.status_code == 401
        body = resp.json()
        assert body.get("message")
        assert body.get("detail") == body["message"]

    def test_403_body_has_top_level_message(self):
        init_db(":memory:")
        raw = auth_manager.create_api_key("viewer-only", ["viewer"], tenant_id="default")
        app = create_app()
        client = TestClient(app)
        resp = client.get(
            "/api/v1/system/health/detailed",
            headers={"X-API-Key": raw, "X-Tenant-Id": "default"},
        )
        assert resp.status_code == 403
        assert "system:manage" in resp.json()["message"]
