"""Issue #60 acceptance tests: Admin Console home — four-zone aggregation + high-risk strip."""

import time

from fastapi.testclient import TestClient

from fusion_security.api.app import create_app
from fusion_security.api.auth import auth_manager
from fusion_security.db import init_db
from fusion_security.engine.console.audit_store import AuditStore
from fusion_security.engine.tenant import audit as audit_mod
from fusion_security.engine.tenant.audit import AuditLogger, get_audit_logger


def _reset_audit(monkeypatch, tmp_path):
    # 审计目录重定向到临时目录:清 per-tenant 单例缓存 + 改默认目录。
    monkeypatch.setattr(audit_mod, "_audit_default_dir", str(tmp_path / "audit"))
    monkeypatch.setattr(audit_mod, "_audit_loggers", {})
    return str(tmp_path / "audit")


class TestAuditStore:
    def test_query_search_and_filters(self, tmp_path):
        log_dir = str(tmp_path / "audit")
        al = AuditLogger(log_dir=log_dir, tenant_id="t1")
        al.log("auth.invalid_key", actor="anonymous", resource_type="auth", risk_level="high")
        al.log("key.create", actor="admin", resource_type="api_key", resource_id="k1", risk_level="medium")
        al.log("scan.create", actor="op", resource_type="scan", resource_id="s1", risk_level="low")
        store = AuditStore(log_dir)

        entries, total = store.query("t1")
        assert total == 3

        entries, total = store.query("t1", search="admin")
        assert total == 1
        assert entries[0]["action"] == "key.create"

        entries, total = store.query("t1", action="key.")
        assert total == 1

        entries, total = store.query("t1", risk_levels=("high", "critical"))
        assert total == 1
        assert entries[0]["action"] == "auth.invalid_key"

        # 分页:limit=2/offset=1 取中间页,total 不变。
        entries, total = store.query("t1", limit=2, offset=1)
        assert total == 3
        assert len(entries) == 2

    def test_time_window_filter(self, tmp_path):
        log_dir = str(tmp_path / "audit")
        al = AuditLogger(log_dir=log_dir, tenant_id="t1")
        old_ts = time.time() - 86400 * 3
        al.log("old.event", risk_level="info")
        al.entries[-1].timestamp = old_ts
        # 手动重写文件模拟旧时间戳条目。
        import json
        from pathlib import Path

        path = Path(log_dir) / "audit_t1.jsonl"
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        lines[-1]["timestamp"] = old_ts
        path.write_text("\n".join(json.dumps(line) for line in lines) + "\n")
        store = AuditStore(log_dir)
        counts = store.today_counts("t1")
        assert counts == {"total": 0, "high_risk": 0}
        entries, total = store.query("t1", start_ts=old_ts - 1, end_ts=old_ts + 1)
        assert total == 1
        assert entries[0]["action"] == "old.event"

    def test_old_lines_without_new_fields_tolerated(self, tmp_path):
        # 旧 jsonl 行缺 risk_level/trace_id —— 读取侧兜底 info/""。
        import json

        log_dir = tmp_path / "audit"
        log_dir.mkdir()
        rec = {"action": "legacy.event", "actor": "x", "timestamp": time.time()}
        (log_dir / "audit_t1.jsonl").write_text(json.dumps(rec) + "\n")
        store = AuditStore(str(log_dir))
        entries, total = store.query("t1")
        assert total == 1
        assert entries[0]["risk_level"] == "info"
        assert entries[0]["trace_id"] == ""

    def test_latest_high_risk(self, tmp_path):
        log_dir = str(tmp_path / "audit")
        al = AuditLogger(log_dir=log_dir, tenant_id="t1")
        al.log("a.first", risk_level="critical")
        time.sleep(0.01)
        al.log("b.second", risk_level="high")
        al.log("c.info", risk_level="info")
        store = AuditStore(log_dir)
        high = store.latest_high_risk("t1", limit=3)
        assert [e["action"] for e in high] == ["b.second", "a.first"]


class TestConsoleSummary:
    def _fake_identity(self, monkeypatch, members=None, idp=None, inventory=None):
        from fusion_security.engine.console import summary as summary_mod

        class FakeClient:
            def __init__(self):
                self.members = members or {"available": False, "reason": "upstream pending"}
                self.idp = idp or {"available": False, "reason": "upstream pending", "configured": False}
                self.inventory = inventory or {"available": False, "reason": "upstream pending", "apps": []}

            def member_summary(self, tenant_id):
                return dict(self.members)

            def idp_summary(self, tenant_id):
                return dict(self.idp)

            def app_secret_inventory(self):
                return dict(self.inventory)

        fake = FakeClient()
        monkeypatch.setattr(summary_mod, "get_identity_admin_client", lambda: fake)
        return fake

    def test_summary_degraded_identity(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        init_db(":memory:")
        self._fake_identity(monkeypatch)
        get_audit_logger("default").log("auth.invalid_key", risk_level="high")

        from fusion_security.engine.console.summary import build_console_summary

        s = build_console_summary("default")
        assert s["members"]["available"] is False
        assert "reason" in s["members"]
        assert s["audit"]["today_total"] == 1
        assert s["audit"]["today_high_risk"] == 1
        assert len(s["high_risk_events"]) == 1
        assert s["high_risk_events"][0]["action"] == "auth.invalid_key"
        assert s["keys"]["route"] == "/keys"
        assert s["posture"]["available"] is True
        # SSO 不可读时如实落 todo_roadmap,不伪造 ok。
        sso = [c for c in s["posture"]["items"] if c["id"] == "sso"][0]
        assert sso["state"] == "todo_roadmap"

    def test_summary_live_identity(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        init_db(":memory:")
        self._fake_identity(
            monkeypatch,
            members={
                "available": True,
                "total": 8,
                "active": 7,
                "disabled": 1,
                "locked": 0,
                "by_role": {},
                "pending": 2,
            },
            idp={"available": True, "configured": True, "count": 1, "types": ["oidc"], "auto_provision": True},
            inventory={"available": True, "apps": [{"app_id": "fusion-mlx", "versions": 2}]},
        )
        from fusion_security.engine.console.summary import build_console_summary

        s = build_console_summary("default")
        assert s["members"]["total"] == 8
        assert s["members"]["pending"] == 2
        sso = [c for c in s["posture"]["items"] if c["id"] == "sso"][0]
        assert sso["state"] == "ok"
        assert "oidc" in sso["detail"]
        assert s["keys"]["identity_inventory"]["apps"][0]["app_id"] == "fusion-mlx"


class TestConsoleRoutes:
    def _client(self):
        init_db(":memory:")
        app = create_app()
        return TestClient(app)

    def test_summary_requires_system_manage(self):
        client = self._client()
        raw = auth_manager.create_api_key("viewer-only", ["viewer"], tenant_id="default")
        resp = client.get("/api/v1/console/summary", headers={"X-API-Key": raw, "X-Tenant-Id": "default"})
        assert resp.status_code == 403
        assert "system:manage" in resp.json()["message"]

    def test_summary_admin_ok(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = self._client()
        raw = auth_manager.create_api_key("admin-key", ["admin"], tenant_id="default")
        resp = client.get("/api/v1/console/summary", headers={"X-API-Key": raw, "X-Tenant-Id": "default"})
        assert resp.status_code == 200
        body = resp.json()
        for zone in ("members", "audit", "keys", "posture"):
            assert zone in body
        assert "high_risk_events" in body

    def test_tenants_endpoint_passthrough(self, monkeypatch):
        from fusion_security.api.routes import console as console_mod

        class FakeClient:
            def list_tenants(self):
                return {
                    "available": True,
                    "tenants": [{"tenant_id": "default", "display_name": "默认", "status": "active", "plan": ""}],
                }

        monkeypatch.setattr(console_mod, "get_identity_admin_client", lambda: FakeClient())
        client = self._client()
        raw = auth_manager.create_api_key("admin-key", ["admin"], tenant_id="default")
        resp = client.get("/api/v1/console/tenants", headers={"X-API-Key": raw, "X-Tenant-Id": "default"})
        assert resp.status_code == 200
        assert resp.json()["tenants"][0]["tenant_id"] == "default"

    def test_anonymous_401_audited(self, monkeypatch, tmp_path):
        # Issue #60: 鉴权拒绝进审计流 —— 匿名(只带 X-Tenant-Id)请求 401 后,
        # 审计文件应有 auth.no_credential 高风险条目。
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        client = self._client()
        resp = client.get("/api/v1/console/summary", headers={"X-Tenant-Id": "default"})
        assert resp.status_code == 401
        store = AuditStore(audit_dir)
        entries, total = store.query("default", action="auth.no_credential")
        assert total == 1
        assert entries[0]["risk_level"] == "high"
