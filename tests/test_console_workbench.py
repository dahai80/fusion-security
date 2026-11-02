"""Issue #61/#62 acceptance tests: audit workbench (search/CSV/saved queries/alerts/notifications) + key console."""

import csv
import io
import json

from fastapi.testclient import TestClient

from fusion_security.api.app import create_app
from fusion_security.api.auth import auth_manager
from fusion_security.db import init_db
from fusion_security.engine.tenant import audit as audit_mod
from fusion_security.engine.tenant.audit import AuditLogger


def _reset_audit(monkeypatch, tmp_path):
    monkeypatch.setattr(audit_mod, "_audit_default_dir", str(tmp_path / "audit"))
    monkeypatch.setattr(audit_mod, "_audit_loggers", {})
    return str(tmp_path / "audit")


def _client():
    init_db(":memory:")
    app = create_app()
    return TestClient(app)


def _admin_headers(tenant="default"):
    raw = auth_manager.create_api_key("admin-key", ["admin"], tenant_id=tenant)
    return {"X-API-Key": raw, "X-Tenant-Id": tenant}


class TestAuditEvents:
    def test_search_filter_and_saved_query_replay(self, monkeypatch, tmp_path):
        # 验收:保存查询重放结果集 == 定义的手输过滤结果集。
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        al = AuditLogger(log_dir=audit_dir, tenant_id="default")
        al.log("auth.invalid_key", actor="anonymous", risk_level="high")
        al.log("auth.tenant_mismatch", actor="anonymous", risk_level="high")
        al.log("key.create", actor="admin", risk_level="medium")
        client = _client()
        h = _admin_headers()

        manual = client.get(
            "/api/v1/console/audit/events",
            params={"search": "anonymous", "risk": "high"},
            headers=h,
        )
        assert manual.status_code == 200
        assert manual.json()["total"] == 2

        created = client.post(
            "/api/v1/console/audit/saved-queries",
            json={"name": "高风险匿名事件", "search": "anonymous", "risk": "high"},
            headers=h,
        )
        assert created.status_code == 200
        qid = created.json()["id"]

        replay = client.get(
            "/api/v1/console/audit/events",
            params={"saved_query_id": qid},
            headers=h,
        )
        assert replay.status_code == 200
        assert replay.json()["total"] == manual.json()["total"]
        assert {e["action"] for e in replay.json()["items"]} == {e["action"] for e in manual.json()["items"]}

        listed = client.get("/api/v1/console/audit/saved-queries", headers=h)
        assert listed.status_code == 200
        assert listed.json()["items"][0]["name"] == "高风险匿名事件"

        deleted = client.delete(f"/api/v1/console/audit/saved-queries/{qid}", headers=h)
        assert deleted.status_code == 200
        replay404 = client.get(
            "/api/v1/console/audit/events",
            params={"saved_query_id": qid},
            headers=h,
        )
        assert replay404.status_code == 404

    def test_csv_export_exact_filtered_rows_with_header(self, monkeypatch, tmp_path):
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        al = AuditLogger(log_dir=audit_dir, tenant_id="default")
        al.log("auth.invalid_key", actor="anonymous", risk_level="high")
        al.log("key.create", actor="admin", risk_level="medium", trace_id="tr-1")
        client = _client()
        h = _admin_headers()

        resp = client.get(
            "/api/v1/console/audit/export",
            params={"risk": "high"},
            headers=h,
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        text = resp.text
        assert text.startswith("﻿")  # BOM:Excel 中文兼容
        rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
        assert len(rows) == 1  # 恰好 = 过滤后的行数
        assert rows[0]["action"] == "auth.invalid_key"
        assert rows[0]["risk_level"] == "high"

    def test_invalid_risk_rejected(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        resp = client.get(
            "/api/v1/console/audit/events",
            params={"risk": "extreme"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 400


class TestAlertSubscriptions:
    def test_subscription_fires_into_notifications_with_dedup(self, monkeypatch, tmp_path):
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        al = AuditLogger(log_dir=audit_dir, tenant_id="default")
        client = _client()
        h = _admin_headers()

        created = client.post(
            "/api/v1/console/alerts/subscriptions",
            json={"name": "越权告警", "event_class": "auth.", "risk_levels": "high,critical"},
            headers=h,
        )
        assert created.status_code == 200

        # 订阅创建后新事件到达 → 轮询即触发,条目进 shell 🔔 契约形状。
        al.log("auth.permission_denied", actor="viewer-only", risk_level="high")
        first = client.get("/api/v1/console/notifications", headers=h)
        assert first.status_code == 200
        body = first.json()
        assert body["count"] >= 1
        item = body["items"][0]
        assert item["title"]
        assert item["level"] in ("info", "warning", "error")
        assert item["route"] == "/audit"
        assert "auth.permission_denied" in item["title"] or "安全告警" in item["title"]

        # 第二次轮询不重复(dedup + 游标)。
        second = client.get("/api/v1/console/notifications", headers=h)
        titles = [i["title"] for i in second.json()["items"]]
        assert titles.count(item["title"]) == 1

        # 低风险事件不触发该订阅。
        al.log("auth.note", actor="x", risk_level="info")
        third = client.get("/api/v1/console/notifications", headers=h)
        assert third.json()["count"] == second.json()["count"]

    def test_subscription_requires_class_or_query(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        resp = client.post(
            "/api/v1/console/alerts/subscriptions",
            json={"name": "空订阅"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 400

    def test_key_expiry_alert_reaches_notifications(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        init_db(":memory:")
        client = _client()
        h = _admin_headers()
        from datetime import datetime, timedelta

        from fusion_security.db.models import ApiKeyORM
        from fusion_security.db.session import get_session

        db = get_session()
        try:
            db.add(
                ApiKeyORM(
                    key_hash="h" * 64,
                    name="expiring-key",
                    role="viewer",
                    tenant_id="default",
                    enabled=True,
                    expires_at=datetime.utcnow() + timedelta(days=3),
                )
            )
            db.commit()
        finally:
            db.close()

        resp = client.get("/api/v1/console/notifications", headers=h)
        titles = [i["title"] for i in resp.json()["items"]]
        assert any("expiring-key" in t for t in titles)
        assert any(i["level"] == "warning" and i["route"] == "/keys" for i in resp.json()["items"])


class TestKeyConsole:
    def _fake_identity(self, monkeypatch, rotate=None, revoke=None, inventory=None, idp=None):
        from fusion_security.api.routes import console as console_mod

        class FakeClient:
            def __init__(self):
                self.rotate_result = rotate or {"ok": False, "reason": "identity 不可达"}
                self.revoke_result = revoke or {
                    "ok": False,
                    "reason": "identity 未提供 revoke 端点(fusion-identity#35)",
                }
                self.inventory = inventory or {"available": False, "reason": "upstream pending", "apps": []}
                self.idp = idp or {"available": False, "reason": "upstream pending", "configured": False}

            def app_secret_inventory(self):
                return dict(self.inventory)

            def rotate_app_secret(self, app_id, grace_seconds=3600):
                return dict(self.rotate_result)

            def revoke_app_secret(self, app_id, version):
                return dict(self.revoke_result)

            def idp_summary(self, tenant_id):
                return dict(self.idp)

        fake = FakeClient()
        monkeypatch.setattr(console_mod, "get_identity_admin_client", lambda: fake)
        return fake

    def test_inventory_lists_local_keys_tenant_scoped(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        self._fake_identity(monkeypatch)
        client = _client()
        _admin_headers("default")
        auth_manager.create_api_key("other-tenant-key", ["admin"], tenant_id="other")
        resp = client.get("/api/v1/console/keys", headers=_admin_headers())
        assert resp.status_code == 200
        names = [k["name"] for k in resp.json()["local"]]
        assert "other-tenant-key" not in names

    def test_rotate_success_and_audit(self, monkeypatch, tmp_path):
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        self._fake_identity(
            monkeypatch, rotate={"ok": True, "secret": "fms_new_secret", "version": 3, "previous_version": 2}
        )
        client = _client()
        h = _admin_headers()
        resp = client.post(
            "/api/v1/console/keys/rotate", json={"app_id": "fusion-mlx", "grace_seconds": 3600}, headers=h
        )
        assert resp.status_code == 200
        assert resp.json()["secret"] == "fms_new_secret"
        assert resp.json()["version"] == 3
        # 轮换本身进审计流(密钥绝不落审计)。
        from fusion_security.engine.console.audit_store import AuditStore

        entries, total = AuditStore(audit_dir).query("default", action="key.rotate")
        assert total == 1
        assert "fms_new_secret" not in json.dumps(entries[0]["details"])

    def test_rotate_failure_502_with_reason(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        self._fake_identity(monkeypatch, rotate={"ok": False, "reason": "identity 未提供轮换"})
        client = _client()
        resp = client.post("/api/v1/console/keys/rotate", json={"app_id": "fusion-mlx"}, headers=_admin_headers())
        assert resp.status_code == 502
        assert "identity" in resp.json()["detail"]

    def test_revoke_upstream_pending_is_502_not_fake_success(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        self._fake_identity(
            monkeypatch, revoke={"ok": False, "reason": "identity 未提供 revoke 端点(fusion-identity#35)"}
        )
        client = _client()
        resp = client.post(
            "/api/v1/console/keys/revoke", json={"app_id": "fusion-mlx", "version": 2}, headers=_admin_headers()
        )
        assert resp.status_code == 502
        assert "fusion-identity#35" in resp.json()["detail"]

    def test_local_key_expiry_patch(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        self._fake_identity(monkeypatch)
        client = _client()
        h = _admin_headers()
        raw = auth_manager.create_api_key("patch-target", ["viewer"], tenant_id="default")
        from fusion_security.db.models import ApiKeyORM
        from fusion_security.db.session import get_session

        db = get_session()
        try:
            row = db.query(ApiKeyORM).filter(ApiKeyORM.name == "patch-target").first()
            key_id = row.id
        finally:
            db.close()
        resp = client.patch(
            f"/api/v1/console/keys/local/{key_id}",
            json={"expires_at": "2027-01-01T00:00:00"},
            headers=h,
        )
        assert resp.status_code == 200
        db = get_session()
        try:
            row = db.query(ApiKeyORM).filter(ApiKeyORM.id == key_id).first()
            assert row.expires_at is not None
        finally:
            db.close()
        assert raw  # key 明文仅创建时可见,patch 不返回

    def test_sso_states(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        h = _admin_headers()

        self._fake_identity(monkeypatch, idp={"available": False, "reason": "upstream pending", "configured": False})
        resp = client.get("/api/v1/console/sso", headers=h)
        assert resp.json()["state"] == "unavailable"
        assert "fusion-identity#35" in resp.json()["detail"]

        self._fake_identity(monkeypatch, idp={"available": True, "configured": False})
        resp = client.get("/api/v1/console/sso", headers=h)
        assert resp.json()["state"] == "not_configured"

        self._fake_identity(
            monkeypatch,
            idp={"available": True, "configured": True, "count": 1, "types": ["oidc"], "auto_provision": True},
        )
        resp = client.get("/api/v1/console/sso", headers=h)
        assert resp.json()["state"] == "configured"
        assert resp.json()["types"] == ["oidc"]


class TestWorkbenchRBAC:
    def test_viewer_403_on_all_console_endpoints(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        raw = auth_manager.create_api_key("viewer-only", ["viewer"], tenant_id="default")
        h = {"X-API-Key": raw, "X-Tenant-Id": "default"}
        for method, path in [
            ("GET", "/api/v1/console/audit/events"),
            ("GET", "/api/v1/console/audit/export"),
            ("GET", "/api/v1/console/audit/saved-queries"),
            ("POST", "/api/v1/console/audit/saved-queries"),
            ("GET", "/api/v1/console/alerts/subscriptions"),
            ("POST", "/api/v1/console/alerts/subscriptions"),
            ("GET", "/api/v1/console/notifications"),
            ("GET", "/api/v1/console/keys"),
            ("POST", "/api/v1/console/keys/rotate"),
            ("GET", "/api/v1/console/sso"),
        ]:
            resp = client.request(
                method, path, json={"name": "x", "app_id": "a"} if method == "POST" else None, headers=h
            )
            assert resp.status_code == 403, f"{method} {path} -> {resp.status_code}"


class TestAuditMarks:
    # Issue #65:标记复核 持久化 + 过滤 + 审计留痕;关联事件按 trace_id/resource_id。

    def test_mark_round_trip_and_filter(self, monkeypatch, tmp_path):
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        al = AuditLogger(log_dir=audit_dir, tenant_id="default")
        al.log("auth.invalid_key", actor="anonymous", risk_level="high", trace_id="tr-1")
        al.log("key.create", actor="admin", risk_level="medium")
        client = _client()
        h = _admin_headers()

        listed = client.get("/api/v1/console/audit/events", headers=h)
        assert listed.status_code == 200
        items = listed.json()["items"]
        assert len(items) == 2
        target = next(i for i in items if i["action"] == "auth.invalid_key")
        assert target["marked"] is False
        assert target["event_key"]

        marked = client.post(
            "/api/v1/console/audit/marks", json={"event_key": target["event_key"], "marked": True}, headers=h
        )
        assert marked.status_code == 200 and marked.json()["marked"] is True
        # 幂等:重复标记不建立第二条
        client.post("/api/v1/console/audit/marks", json={"event_key": target["event_key"]}, headers=h)

        # 重新查询(模拟刷新)—— 标记持久化
        again = client.get("/api/v1/console/audit/events", headers=h)
        tgt = next(i for i in again.json()["items"] if i["event_key"] == target["event_key"])
        assert tgt["marked"] is True

        only = client.get("/api/v1/console/audit/events", params={"marked_only": "true"}, headers=h)
        assert only.status_code == 200
        assert only.json()["total"] == 1
        assert only.json()["items"][0]["event_key"] == target["event_key"]

        # 审计留痕:标记动作本身进审计流
        log_text = (tmp_path / "audit" / "audit_default.jsonl").read_text()
        assert "audit.mark_review" in log_text

        unmarked = client.post(
            "/api/v1/console/audit/marks", json={"event_key": target["event_key"], "marked": False}, headers=h
        )
        assert unmarked.status_code == 200
        empty = client.get("/api/v1/console/audit/events", params={"marked_only": "true"}, headers=h)
        assert empty.json()["total"] == 0
        assert "audit.unmark_review" in (tmp_path / "audit" / "audit_default.jsonl").read_text()

    def test_mark_tenant_isolated(self, monkeypatch, tmp_path):
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        AuditLogger(log_dir=audit_dir, tenant_id="default").log(
            "auth.invalid_key", actor="anonymous", risk_level="high"
        )
        client = _client()
        h = _admin_headers("default")
        key = client.get("/api/v1/console/audit/events", headers=h).json()["items"][0]["event_key"]
        client.post("/api/v1/console/audit/marks", json={"event_key": key}, headers=h)

        # 另一租户看不到该标记(即使 event_key 相同)
        raw = auth_manager.create_api_key("other-admin", ["admin"], tenant_id="other")
        h2 = {"X-API-Key": raw, "X-Tenant-Id": "other"}
        AuditLogger(log_dir=audit_dir, tenant_id="other").log("auth.invalid_key", actor="anonymous", risk_level="high")
        other = client.get("/api/v1/console/audit/events", params={"marked_only": "true"}, headers=h2)
        assert other.status_code == 200 and other.json()["total"] == 0

    def test_related_events_by_trace_and_resource(self, monkeypatch, tmp_path):
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        al = AuditLogger(log_dir=audit_dir, tenant_id="default")
        al.log("auth.invalid_key", actor="anonymous", risk_level="high", trace_id="tr-9")
        al.log("auth.permission_denied", actor="viewer", risk_level="high", trace_id="tr-9")
        al.log("key.create", actor="admin", risk_level="medium", trace_id="tr-other")
        al.log("key.update", actor="admin", resource_type="api_key", resource_id="k-42")
        client = _client()
        h = _admin_headers()

        by_trace = client.get("/api/v1/console/audit/events", params={"trace_id": "tr-9"}, headers=h)
        assert by_trace.status_code == 200
        assert by_trace.json()["total"] == 2
        assert {i["action"] for i in by_trace.json()["items"]} == {"auth.invalid_key", "auth.permission_denied"}

        by_resource = client.get("/api/v1/console/audit/events", params={"resource_id": "k-42"}, headers=h)
        assert by_resource.status_code == 200
        assert by_resource.json()["total"] == 1
        assert by_resource.json()["items"][0]["action"] == "key.update"

        # 导出同样支持 trace 过滤
        exp = client.get("/api/v1/console/audit/export", params={"trace_id": "tr-9"}, headers=h)
        rows = list(csv.DictReader(io.StringIO(exp.text.lstrip("﻿"))))
        assert len(rows) == 2


class TestConsoleEdgePaths:
    # 边缘路径补测:非法时间参数、损坏保存查询、空导出、订阅列表/删除、
    # 本地 key 404/非法 ISO、吊销成功路径、保存查询订阅的 search/action 回退。

    def test_bad_time_param_400(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        resp = client.get("/api/v1/console/audit/events", params={"start": "abc"}, headers=_admin_headers())
        assert resp.status_code == 400 and "epoch" in resp.json()["detail"]

    def test_corrupt_saved_query_definition_400(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        from fusion_security.db.models import SavedQueryORM
        from fusion_security.db.session import get_session

        db = get_session()
        row = SavedQueryORM(tenant_id="default", name="损坏", definition="{bad json", created_by="t")
        db.add(row)
        db.commit()
        qid = row.id
        db.close()
        resp = client.get("/api/v1/console/audit/events", params={"saved_query_id": qid}, headers=_admin_headers())
        assert resp.status_code == 400

    def test_export_zero_rows_header_only(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        resp = client.get(
            "/api/v1/console/audit/export",
            params={"search": "nothing-matches"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 200
        text = resp.text.lstrip("﻿")
        assert text.splitlines()[0].startswith("timestamp")
        assert len(text.strip().splitlines()) == 1

    def test_saved_query_delete_404(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        resp = client.delete("/api/v1/console/audit/saved-queries/nope", headers=_admin_headers())
        assert resp.status_code == 404

    def test_subscriptions_list_delete_and_404(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        h = _admin_headers()
        created = client.post(
            "/api/v1/console/alerts/subscriptions",
            json={"name": "s1", "event_class": "auth.", "risk_levels": "high,critical"},
            headers=h,
        )
        assert created.status_code == 200
        sid = created.json()["id"]
        listed = client.get("/api/v1/console/alerts/subscriptions", headers=h)
        assert listed.status_code == 200
        assert [s["id"] for s in listed.json()["items"]] == [sid]
        assert listed.json()["items"][0]["event_class"] == "auth."
        assert client.delete(f"/api/v1/console/alerts/subscriptions/{sid}", headers=h).status_code == 200
        assert client.delete("/api/v1/console/alerts/subscriptions/nope", headers=h).status_code == 404

    def test_saved_query_subscription_search_fallback(self, monkeypatch, tmp_path):
        # 订阅绑定保存查询(无 event_class)—— 按定义里的 search/action 过滤。
        audit_dir = _reset_audit(monkeypatch, tmp_path)
        al = AuditLogger(log_dir=audit_dir, tenant_id="default")
        al.log("auth.invalid_key", actor="anonymous", risk_level="high")
        al.log("key.create", actor="cron", risk_level="medium")
        client = _client()
        h = _admin_headers()
        q = client.post(
            "/api/v1/console/audit/saved-queries",
            json={"name": "匿名高危", "search": "anonymous", "risk": "high"},
            headers=h,
        )
        qid = q.json()["id"]
        created = client.post(
            "/api/v1/console/alerts/subscriptions",
            json={"name": "绑定查询", "saved_query_id": qid},
            headers=h,
        )
        assert created.status_code == 200
        resp = client.get("/api/v1/console/notifications", headers=h)
        items = resp.json()["items"]
        assert any("auth.invalid_key" in i["title"] for i in items)
        assert not any("key.create" in i["title"] for i in items)
        # 保存查询被删后,订阅按空过滤兜底 —— 轮询不 500。
        client.delete(f"/api/v1/console/audit/saved-queries/{qid}", headers=h)
        resp2 = client.get("/api/v1/console/notifications", headers=h)
        assert resp2.status_code == 200

    def test_local_key_patch_404_and_bad_iso(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        client = _client()
        h = _admin_headers()
        assert client.patch("/api/v1/console/keys/local/nope", json={"enabled": False}, headers=h).status_code == 404
        from fusion_security.db.models import ApiKeyORM
        from fusion_security.db.session import get_session

        db = get_session()
        key_id = db.query(ApiKeyORM).filter(ApiKeyORM.name == "admin-key").first().id
        db.close()
        assert (
            client.patch(
                f"/api/v1/console/keys/local/{key_id}", json={"expires_at": "not-a-date"}, headers=h
            ).status_code
            == 400
        )

    def test_revoke_success(self, monkeypatch, tmp_path):
        _reset_audit(monkeypatch, tmp_path)
        TestKeyConsole._fake_identity(self, monkeypatch, revoke={"ok": True})
        client = _client()
        resp = client.post(
            "/api/v1/console/keys/revoke",
            json={"app_id": "fusion-mlx", "version": 2},
            headers=_admin_headers(),
        )
        assert resp.status_code == 200 and resp.json()["ok"] is True
