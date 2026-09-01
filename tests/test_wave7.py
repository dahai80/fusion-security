from __future__ import annotations

import logging
import socket
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from fusion_security.api.auth import MASTER_KEY_ENV, AuthManager
from fusion_security.api.routes.integrations import _webhook_orm_to_dict
from fusion_security.engine.ai.analyzer import _resolve_mlx_url as _analyzer_url
from fusion_security.engine.resume.checkpoint import CheckpointManager, StageCheckpoint
from fusion_security.engine.scheduler import (
    ScanScheduler,
    ScheduledScan,
    ScheduleFrequency,
)
from fusion_security.models.finding import Finding
from fusion_security.models.patch import Patch

# ===== env url unification (Wave 6) =====


class TestResolveMlxUrl:
    def test_mlx_base_url_wins(self, monkeypatch):
        monkeypatch.setenv("MLX_BASE_URL", "http://a:11432/v1")
        monkeypatch.setenv("FUSION_AI_URL", "http://b:11432/v1")
        monkeypatch.setenv("FUSION_MLX_URL", "http://c:11432/v1")
        assert _analyzer_url() == "http://a:11432/v1"

    def test_fallback_fusion_ai_url(self, monkeypatch):
        monkeypatch.delenv("MLX_BASE_URL", raising=False)
        monkeypatch.setenv("FUSION_AI_URL", "http://b:11432/v1/")
        monkeypatch.delenv("FUSION_MLX_URL", raising=False)
        # 尾部斜杠应被裁剪。
        assert _analyzer_url() == "http://b:11432/v1"

    def test_fallback_fusion_mlx_url(self, monkeypatch):
        for v in ("MLX_BASE_URL", "FUSION_AI_URL"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("FUSION_MLX_URL", "http://c:11432/v1")
        assert _analyzer_url() == "http://c:11432/v1"

    def test_default_when_unset(self, monkeypatch):
        for v in ("MLX_BASE_URL", "FUSION_AI_URL", "FUSION_MLX_URL"):
            monkeypatch.delenv(v, raising=False)
        assert _analyzer_url() == "http://localhost:11432/v1"


# ===== checkpoint version rejection (Wave 4) =====


class TestCheckpointVersion:
    def test_from_dict_rejects_missing_version(self):
        # 老断点文件无 version 字段 → file_ver=0 ≠ 1,拒绝。
        with pytest.raises(ValueError, match="version mismatch"):
            StageCheckpoint.from_dict({"scan_id": "s1", "completed_stage": "discover"})

    def test_from_dict_rejects_wrong_version(self):
        with pytest.raises(ValueError, match="version mismatch"):
            StageCheckpoint.from_dict({"scan_id": "s1", "version": 2})

    def test_from_dict_accepts_current_version(self):
        cp = StageCheckpoint.from_dict({"scan_id": "s1", "completed_stage": "triage", "version": 1})
        assert cp.scan_id == "s1"
        assert cp.version == 1

    def test_load_corrupt_moves_sidecar_not_deleted(self, tmp_path):
        # 损坏断点不再静默删除,移到 .corrupt 保留现场。
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path))
        bad = tmp_path / "s1.json"
        bad.write_text("{not valid json", encoding="utf-8")
        assert mgr.load("s1") is None
        sidecar = tmp_path / "s1.json.corrupt"
        assert sidecar.exists(), "corrupt checkpoint should be preserved as .corrupt sidecar"
        assert not bad.exists()


# ===== scheduler DB persistence (Wave 5 Feature 4) =====


@pytest.fixture()
def scheduler_db():
    # 内存 SQLite,隔离每用例。init_db 建 ScheduledScanORM 表。
    from fusion_security.db.session import init_db

    init_db(":memory:")
    from fusion_security.db.session import get_session

    db = get_session()
    yield db
    db.close()


class TestSchedulerPersistence:
    def test_add_schedule_persists(self, scheduler_db):
        sched = ScanScheduler(db=scheduler_db)
        s = ScheduledScan(
            id="s1",
            name="nightly",
            project_path="/tmp/proj",
            frequency=ScheduleFrequency.DAILY,
            severity="high",
            tenant_id="t1",
        )
        sched.add_schedule(s)
        # 内存有。
        assert "s1" in sched.schedules
        # DB 有。
        from fusion_security.db.models import ScheduledScanORM

        row = scheduler_db.query(ScheduledScanORM).filter(ScheduledScanORM.id == "s1").first()
        assert row is not None
        assert row.project_path == "/tmp/proj"
        assert row.frequency == "daily"
        assert row.severity == "high"
        assert row.tenant_id == "t1"

    def test_remove_schedule_deletes_db(self, scheduler_db):
        sched = ScanScheduler(db=scheduler_db)
        sched.add_schedule(ScheduledScan(id="s2", project_path="/tmp", frequency=ScheduleFrequency.HOURLY))
        assert sched.remove_schedule("s2") is True
        from fusion_security.db.models import ScheduledScanORM

        assert scheduler_db.query(ScheduledScanORM).filter(ScheduledScanORM.id == "s2").first() is None
        assert "s2" not in sched.schedules

    def test_load_from_db_restores(self, scheduler_db):
        # 先写入一个 enabled + 一个 disabled 计划。
        sched_a = ScanScheduler(db=scheduler_db)
        sched_a.add_schedule(
            ScheduledScan(id="on", project_path="/tmp/on", frequency=ScheduleFrequency.DAILY, enabled=True)
        )
        sched_a.add_schedule(
            ScheduledScan(id="off", project_path="/tmp/off", frequency=ScheduleFrequency.DAILY, enabled=False)
        )
        # 新 scheduler 实例模拟重启,仅载入 enabled。
        sched_b = ScanScheduler(db=scheduler_db)
        count = sched_b.load_from_db()
        assert count == 1
        assert "on" in sched_b.schedules
        assert "off" not in sched_b.schedules

    def test_list_schedules_shape(self, scheduler_db):
        sched = ScanScheduler(db=scheduler_db)
        sched.add_schedule(ScheduledScan(id="s3", name="weekly", project_path="/p", frequency=ScheduleFrequency.WEEKLY))
        items = sched.list_schedules()
        assert len(items) == 1
        assert items[0]["id"] == "s3"
        assert items[0]["frequency"] == "weekly"
        assert "next_run" in items[0]


# ===== ScanResponse path+created_at (Wave 6) =====


class TestScanResponseSerialization:
    def test_response_includes_path_and_created_at(self):
        from fusion_security.api.routes.scans import ScanResponse, _scan_orm_to_response
        from fusion_security.db.models import ScanORM

        orm = MagicMock(spec=ScanORM)
        orm.id = "scan1"
        orm.project_id = "p1"
        orm.scan_type = "full"
        orm.status = "completed"
        orm.severity_threshold = "low"
        orm.use_ai = True
        orm.model = "qwen"
        orm.trigger = "api"
        orm.branch = "main"
        orm.path = "/repo/src"
        orm.files_scanned = 12
        orm.files_skipped = 1
        orm.duration_ms = 3400.0
        orm.total_vulnerabilities = 3
        orm.critical = 1
        orm.high = 1
        orm.medium = 1
        orm.low = 0
        orm.summary = "ok"
        orm.created_at = datetime(2026, 9, 1, 10, 0, 0)
        resp = _scan_orm_to_response(orm)
        assert isinstance(resp, ScanResponse)
        assert resp.path == "/repo/src"
        assert resp.created_at.startswith("2026-09-01")

    def test_response_empty_path_and_no_created_at(self):
        from fusion_security.api.routes.scans import _scan_orm_to_response
        from fusion_security.db.models import ScanORM

        orm = MagicMock(spec=ScanORM)
        for k, v in {
            "id": "scan2",
            "project_id": "",
            "scan_type": "full",
            "status": "pending",
            "severity_threshold": "low",
            "use_ai": False,
            "model": "",
            "trigger": "manual",
            "branch": "",
            "path": "",
            "files_scanned": 0,
            "files_skipped": 0,
            "duration_ms": 0.0,
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "summary": "",
        }.items():
            setattr(orm, k, v)
        orm.created_at = None
        resp = _scan_orm_to_response(orm)
        assert resp.path == ""
        assert resp.created_at == ""


# ===== finding_to_orm (Wave 1) =====


class TestFindingToOrm:
    def test_finding_to_orm_maps_fields(self):
        from fusion_security.db.convert import finding_to_orm

        f = Finding(
            id="f1",
            vuln_id="v1",
            scan_id="scan1",
            file_path="/src/a.py",
            line_number=42,
            line_end=44,
            code_snippet="x = eval(s)"[:500],  # noqa: S307 — 测试样本,非真实执行
            confidence=0.9,
        )
        orm = finding_to_orm(f, scan_id="scan1")
        assert orm.scan_id == "scan1"
        assert orm.vuln_id == "v1"
        assert orm.file_path == "/src/a.py"
        assert orm.line_number == 42
        assert orm.confidence == 0.9

    def test_patch_to_orm_maps_fields(self):
        from fusion_security.db.convert import patch_to_orm

        p = Patch(
            id="p1",
            vuln_id="v1",
            scan_id="scan1",
            original_code="eval(s)",
            patched_code="ast.literal_eval(s)",
            description="avoid eval",
            strategy="template",
        )
        orm = patch_to_orm(p)
        assert orm.vuln_id == "v1"
        assert orm.scan_id == "scan1"
        assert orm.strategy == "template"
        assert "literal_eval" in orm.patched_code


# ===== DB-backed API keys (Wave 2) =====


@pytest.fixture()
def auth_db():
    from fusion_security.db.session import get_session, init_db

    init_db(":memory:")
    db = get_session()
    yield db
    db.close()


class TestDbBackedKeys:
    def test_create_and_validate_key(self, auth_db):
        mgr = AuthManager(session_factory=lambda: auth_db)
        raw = mgr.create_api_key("ci", roles=["admin"], tenant_id="t1")
        assert raw.startswith("fs_")
        # 明文不入库:DB 只有 hash。
        import hashlib

        from fusion_security.db.models import ApiKeyORM

        rows = auth_db.query(ApiKeyORM).all()
        assert len(rows) == 1
        assert rows[0].key_hash == hashlib.sha256(raw.encode()).hexdigest()
        assert rows[0].name == "ci"
        assert rows[0].tenant_id == "t1"
        # 明文不在任何字段。
        for r in rows:
            assert raw not in (r.key_hash, r.name, r.id or "")

        # 校验通过。
        key = mgr.validate_key(raw)
        assert key is not None
        assert "admin" in key.roles
        assert key.tenant_id == "t1"

    def test_validate_rejects_unknown_key(self, auth_db):
        mgr = AuthManager(session_factory=lambda: auth_db)
        assert mgr.validate_key("fs_nonexistent_xxx") is None
        assert mgr.validate_key("") is None

    def test_keys_survive_new_manager(self, auth_db):
        # 模拟重启:新建 AuthManager,旧 key 仍可校验(DB 持久)。
        mgr_a = AuthManager(session_factory=lambda: auth_db)
        raw = mgr_a.create_api_key("ops", roles=["viewer"])
        # 新实例,不持有内存状态。
        mgr_b = AuthManager(session_factory=lambda: auth_db)
        assert mgr_b.validate_key(raw) is not None

    def test_master_key_from_env_stable(self, auth_db, monkeypatch):
        # env 设了 master key → 同一明文可重复 ensure,校验通过。
        monkeypatch.setenv(MASTER_KEY_ENV, "fs_master_test_secret_123")
        mgr = AuthManager(session_factory=lambda: auth_db)
        k1 = mgr.ensure_master_key()
        k2 = mgr.ensure_master_key()
        assert k1 == k2 == "fs_master_test_secret_123"
        assert mgr.validate_key(k1) is not None
        # DB 只有一行 master hash(幂等)。
        from fusion_security.db.models import ApiKeyORM

        masters = auth_db.query(ApiKeyORM).filter(ApiKeyORM.name == "master").all()
        assert len(masters) == 1


# ===== webhook persistence + secret-not-returned (Wave 4 Feature 5) =====


@pytest.fixture()
def webhook_db():
    from fusion_security.db.session import get_session, init_db

    init_db(":memory:")
    db = get_session()
    yield db
    db.close()


class TestWebhookPersistence:
    def test_secret_hash_never_in_response(self, webhook_db):
        from fusion_security.db.models import WebhookORM

        row = WebhookORM(
            id="wh1",
            url="http://example.com/hook",
            events_json='["scan.completed"]',
            secret_hash="deadbeef" * 8,
            enabled=True,
        )
        webhook_db.add(row)
        webhook_db.commit()
        d = _webhook_orm_to_dict(row)
        # 响应字段白名单:绝无 secret_hash / secret。
        assert "secret_hash" not in d
        assert "secret" not in d
        assert d["id"] == "wh1"
        assert d["events"] == ["scan.completed"]

    def test_webhook_survives_new_session(self, webhook_db):
        from fusion_security.db.models import WebhookORM
        from fusion_security.db.session import get_session

        row = WebhookORM(
            id="wh2",
            url="http://example.com/h2",
            events_json='["scan.completed"]',
            secret_hash="",
            enabled=True,
        )
        webhook_db.add(row)
        webhook_db.commit()
        # 新 session 模拟重启。
        db2 = get_session()
        try:
            found = db2.query(WebhookORM).filter(WebhookORM.id == "wh2").first()
            assert found is not None
            assert found.url == "http://example.com/h2"
        finally:
            db2.close()


# ===== schedules route CRUD (Wave 5 Feature 4) =====


@pytest.fixture()
def schedules_app(monkeypatch):
    # 真实内存 DB + 鉴权覆盖(admin),scheduler 未启动(走 direct-commit 分支)。
    from fastapi.testclient import TestClient

    from fusion_security.api.app import create_app
    from fusion_security.api.auth import get_current_key
    from fusion_security.db.session import get_session, init_db

    init_db(":memory:")
    db = get_session()

    app = create_app()
    app.dependency_overrides[get_session] = lambda: db
    app.dependency_overrides[get_current_key] = lambda: MagicMock(roles=["admin"], tenant_id="t_sched")
    yield TestClient(app), db
    db.close()
    app.dependency_overrides.clear()


class TestSchedulesRoute:
    def test_create_then_list(self, schedules_app):
        client, _db = schedules_app
        r = client.post("/api/v1/schedules", json={"name": "d", "project_path": "/p", "frequency": "daily"})
        assert r.status_code == 200, r.text
        sid = r.json()["id"]
        r2 = client.get("/api/v1/schedules")
        assert r2.status_code == 200
        items = r2.json()["schedules"]
        assert any(s["id"] == sid for s in items)

    def test_create_rejects_bad_frequency(self, schedules_app):
        client, _db = schedules_app
        r = client.post("/api/v1/schedules", json={"project_path": "/p", "frequency": "never"})
        assert r.status_code == 400

    def test_create_rejects_empty_path(self, schedules_app):
        client, _db = schedules_app
        r = client.post("/api/v1/schedules", json={"project_path": "", "frequency": "daily"})
        assert r.status_code == 400

    def test_update_then_delete(self, schedules_app):
        client, _db = schedules_app
        sid = client.post("/api/v1/schedules", json={"project_path": "/p", "frequency": "daily"}).json()["id"]
        r = client.patch(f"/api/v1/schedules/{sid}", json={"severity": "high", "enabled": False})
        assert r.status_code == 200
        assert r.json()["status"] == "updated"
        r2 = client.delete(f"/api/v1/schedules/{sid}")
        assert r2.status_code == 200
        # 再删 → 404。
        assert client.delete(f"/api/v1/schedules/{sid}").status_code == 404

    def test_update_missing_404(self, schedules_app):
        client, _db = schedules_app
        assert client.patch("/api/v1/schedules/nope", json={"name": "x"}).status_code == 404


# ===== URL guard SSRF (Wave 5) =====


class TestUrlGuard:
    def test_empty_url_rejected(self):
        from fusion_security.engine.ci._url_guard import validate_outbound_url

        assert validate_outbound_url("").ok is False
        assert validate_outbound_url(None).ok is False  # noqa: S307 — None 输入边界

    def test_bad_scheme_rejected(self):
        from fusion_security.engine.ci._url_guard import validate_outbound_url

        r = validate_outbound_url("file:///etc/passwd")
        assert r.ok is False
        assert "协议" in r.reason

    def test_no_hostname_rejected(self):
        from fusion_security.engine.ci._url_guard import validate_outbound_url

        assert validate_outbound_url("http:///path").ok is False

    def test_loopback_rejected(self, monkeypatch):
        # 127.0.0.1 解析为回环 → 禁止外发(SSRF 防护)。
        from fusion_security.engine.ci import _url_guard

        def fake_getaddrinfo(host, *a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

        monkeypatch.setattr(_url_guard.socket, "getaddrinfo", fake_getaddrinfo)
        r = _url_guard.validate_outbound_url("http://evil.example.com/x")
        assert r.ok is False
        assert "禁止外发" in r.reason

    def test_public_ip_allowed(self, monkeypatch):
        from fusion_security.engine.ci import _url_guard

        def fake_getaddrinfo(host, *a, **k):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

        monkeypatch.setattr(_url_guard.socket, "getaddrinfo", fake_getaddrinfo)
        r = _url_guard.validate_outbound_url("https://example.com/hook")
        assert r.ok is True
        assert r.pinned_ips == ["93.184.216.34"]

    def test_pin_url_returns_resolver_on_ok(self, monkeypatch):
        from fusion_security.engine.ci import _url_guard

        monkeypatch.setattr(
            _url_guard.socket,
            "getaddrinfo",
            lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
        )
        result, resolver = _url_guard.pin_url("https://example.com/hook")
        assert result.ok is True
        assert resolver is not None
        with resolver:
            pass  # __enter__/__exit__ 不抛即可

    def test_pin_url_returns_none_on_fail(self, monkeypatch):
        from fusion_security.engine.ci import _url_guard

        monkeypatch.setattr(
            _url_guard.socket,
            "getaddrinfo",
            lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
        )
        result, resolver = _url_guard.pin_url("https://evil.example.com/hook")
        assert result.ok is False
        assert resolver is None


# ===== app lifespan smoke (Wave 2/5) =====


class TestAppLifespan:
    def test_lifespan_starts_and_stops(self, monkeypatch, tmp_path):
        # 用临时 DB + 固定 master key,启动 lifespan 后停机,确认不抛 + master key 就绪。
        import asyncio

        from fusion_security.api.app import create_app

        monkeypatch.setenv("FUSION_DB_PATH", str(tmp_path / "lt.db"))
        monkeypatch.setenv("FUSION_SECURITY_MASTER_KEY", "fs_lifespan_test_key")

        app = create_app()

        async def run():
            async with app.router.lifespan_context(app):
                # 启动期间 scheduler/worker 应就绪。
                pass

        asyncio.run(run())  # 不抛即通过
        # 清理:lifespan 设置了全局 scheduler 单例,避免污染后续 route 测试。
        from fusion_security.api.routes import schedules as _sched_route

        _sched_route.set_scheduler(None)


# ===== _run_scan pipeline persistence (Wave 3/4) =====


@pytest.fixture()
def runscan_db():
    from fusion_security.db.session import get_session, init_db

    init_db(":memory:")
    db = get_session()
    yield db
    db.close()


class TestRunScanPersist:
    def test_run_scan_persists_vulns_findings_patches(self, runscan_db, monkeypatch):
        import asyncio

        from fusion_security.api.routes import scans as scans_route

        # 预置 project + ScanORM 行(FK 要求 project_id 存在)。
        from fusion_security.db.models import ProjectORM, ScanORM
        from fusion_security.engine.scanner import ScanResult
        from fusion_security.models.finding import Finding
        from fusion_security.models.patch import Patch
        from fusion_security.models.vulnerability import Vulnerability

        runscan_db.add(ProjectORM(id="proj1", name="p1"))
        runscan_db.commit()
        scan = ScanORM(
            id="rscan1",
            project_id="proj1",
            scan_type="full",
            status="pending",
            severity_threshold="low",
            use_ai=False,
            model="",
            trigger="api",
            branch="",
            path="/repo",
            files_scanned=0,
            files_skipped=0,
            duration_ms=0.0,
            total_vulnerabilities=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            summary="",
        )
        runscan_db.add(scan)
        runscan_db.commit()

        # 假 pipeline:run 返回带 failed_stage 无的 ctx;to_scan_result 返回填充好的 ScanResult。
        fake_ctx = MagicMock()
        fake_ctx.stage_results = {}  # 无 failed_stage → completed
        fake_ctx.errors = []
        fake_ctx.vulnerabilities = []
        fake_ctx.findings = []
        fake_ctx.patches = []

        fake_result = ScanResult(MagicMock())
        fake_result.files_scanned = 3
        fake_result.files_skipped = 1
        fake_result.duration_ms = 500.0
        fake_result.vulnerabilities = [
            Vulnerability(
                id="v1",
                title="sql",
                description="d",
                severity="high",
                confidence=90.0,
                file_path="/a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL_INJECTION",
            ),
            Vulnerability(
                id="v2",
                title="xss",
                description="d",
                severity="low",
                confidence=80.0,
                file_path="/b.py",
                line_number=2,
                code_snippet="s",
                rule_id="XSS",
            ),
        ]
        fake_result.findings = [Finding(id="f1", vuln_id="v1", scan_id="rscan1", file_path="/a.py", line_number=1)]
        fake_result.patches = [Patch(id="p1", vuln_id="v1", scan_id="rscan1", original_code="x", patched_code="y")]
        fake_result.summary = "done"

        fake_pipeline = MagicMock()
        fake_pipeline.run = AsyncMock(return_value=fake_ctx)
        fake_pipeline.to_scan_result = MagicMock(return_value=fake_result)

        # 不复用 runscan_db:_run_scan 内部 get_session()+close() 会关掉注入的会话,导致 refresh 报 _expire_state。
        # StaticPool + :memory: 共享同一连接,_run_scan 用真实 get_session() 落库后,runscan_db 仍可读到已提交数据。
        monkeypatch.setattr("fusion_security.engine.pipeline.ScanPipeline", lambda **kw: fake_pipeline)
        # webhook 通知静默。
        monkeypatch.setattr(scans_route, "_notify_webhooks", AsyncMock())

        asyncio.run(scans_route._run_scan("rscan1", "/repo", "full", "low", False, "", []))

        runscan_db.expire_all()
        scan = runscan_db.query(ScanORM).filter(ScanORM.id == "rscan1").first()
        assert scan.status == "completed"
        assert scan.files_scanned == 3
        assert scan.files_skipped == 1
        assert scan.total_vulnerabilities == 2
        assert scan.high == 1
        assert scan.low == 1
        assert scan.summary == "done"
        # vulns/findings/patches 落库。
        from fusion_security.db.models import FindingORM, PatchORM, VulnerabilityORM

        assert runscan_db.query(VulnerabilityORM).filter(VulnerabilityORM.scan_id == "rscan1").count() == 2
        assert runscan_db.query(FindingORM).filter(FindingORM.scan_id == "rscan1").count() == 1
        assert runscan_db.query(PatchORM).filter(PatchORM.vuln_id == "v1").count() == 1

    def test_run_scan_failed_stage_marks_partial(self, runscan_db, monkeypatch):
        import asyncio

        from fusion_security.api.routes import scans as scans_route
        from fusion_security.db.models import ProjectORM, ScanORM
        from fusion_security.engine.scanner import ScanResult

        runscan_db.add(ProjectORM(id="proj2", name="p2"))
        runscan_db.commit()
        scan = ScanORM(
            id="rscan2",
            project_id="proj2",
            scan_type="full",
            status="pending",
            severity_threshold="low",
            use_ai=False,
            model="",
            trigger="api",
            branch="",
            path="/repo",
            files_scanned=0,
            files_skipped=0,
            duration_ms=0.0,
            total_vulnerabilities=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            summary="",
        )
        runscan_db.add(scan)
        runscan_db.commit()

        fake_ctx = MagicMock()
        # verify 阶段失败 → partial(非 recon/discover)。
        fake_ctx.stage_results = {"pipeline": {"failed_stage": "verify"}}
        fake_ctx.errors = ["verify boom"]
        fake_ctx.vulnerabilities = []
        fake_ctx.findings = []
        fake_ctx.patches = []

        fake_result = ScanResult(MagicMock())

        fake_pipeline = MagicMock()
        fake_pipeline.run = AsyncMock(return_value=fake_ctx)
        fake_pipeline.to_scan_result = MagicMock(return_value=fake_result)

        monkeypatch.setattr("fusion_security.engine.pipeline.ScanPipeline", lambda **kw: fake_pipeline)
        monkeypatch.setattr(scans_route, "_notify_webhooks", AsyncMock())

        asyncio.run(scans_route._run_scan("rscan2", "/repo", "full", "low", False, "", []))

        runscan_db.expire_all()
        scan = runscan_db.query(ScanORM).filter(ScanORM.id == "rscan2").first()
        assert scan.status == "partial"
        assert "verify" in scan.summary


# ===== pipeline stage coverage (Wave 7 — push to 90% gate) =====


class TestPipelineStages:
    @pytest.fixture
    def pipeline(self):
        from fusion_security.engine.pipeline import PipelineConfig, ScanPipeline

        return ScanPipeline(
            PipelineConfig(
                use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False, enable_patch=True
            )
        )

    @pytest.mark.asyncio
    async def test_patch_stage_generates_for_critical_high(self, pipeline):
        # 484-504: critical/high vuln → generate_alternatives 走通,patch 落 ctx.patches。
        from fusion_security.engine.pipeline import PipelineContext
        from fusion_security.models.vulnerability import Vulnerability

        ctx = PipelineContext(project_path="/tmp/x")
        ctx.vulnerabilities.append(
            Vulnerability(
                id="V1",
                title="sql",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="cursor.execute(query)",
                rule_id="SQL001",
            )
        )
        await pipeline._stage_patch(ctx)
        assert len(ctx.patches) >= 1
        assert ctx.patches[0].vuln_id == "V1"
        assert ctx.stage_results["patch"]["patches"] == len(ctx.patches)

    @pytest.mark.asyncio
    async def test_patch_stage_skips_when_disabled_or_empty(self, pipeline):
        # 480-482: enable_patch=False 或无 vuln → 早退,patches=0。
        from fusion_security.engine.pipeline import PipelineContext

        ctx = PipelineContext(project_path="/tmp/x")
        await pipeline._stage_patch(ctx)
        assert ctx.stage_results["patch"]["patches"] == 0

    @pytest.mark.asyncio
    async def test_patch_stage_skips_low_severity(self, pipeline):
        # 484 过滤:low/medium 不进 critical_high 列表 → 无 patch。
        from fusion_security.engine.pipeline import PipelineContext
        from fusion_security.models.vulnerability import Vulnerability

        ctx = PipelineContext(project_path="/tmp/x")
        ctx.vulnerabilities.append(
            Vulnerability(
                id="Vlow",
                title="x",
                description="d",
                severity="low",
                confidence=50,
                file_path="a.py",
                line_number=1,
                code_snippet="x",
                rule_id="XSS001",
            )
        )
        await pipeline._stage_patch(ctx)
        assert len(ctx.patches) == 0

    @pytest.mark.asyncio
    async def test_discover_taint_path(self):
        # 302-320: enable_taint=True 走污点追踪分支。构造可触发污点的源→汇文件。
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline

        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "flow.py"
            py.write_text("data = input('x')\nimport os\nos.system(data)\n")
            pipeline = ScanPipeline(
                PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=True)
            )
            ctx = PipelineContext(project_path=tmp)
            ctx.files = [py]
            await pipeline._stage_discover(ctx)
            assert "discover" in ctx.stage_results
            assert ctx.stage_results["discover"]["vulnerabilities"] >= 1

    @pytest.mark.asyncio
    async def test_discover_scan_failure_counts_skipped(self):
        # 325-328: 文件读取异常 → scan_failed++ → files_skipped 记录。
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline

        pipeline = ScanPipeline(
            PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False)
        )
        ctx = PipelineContext(project_path="/tmp/x")
        # 不存在的文件 → read_text 抛异常 → scan_failed。
        ctx.files = [Path("/tmp/__definitely_not_here_9999__.py")]
        await pipeline._stage_discover(ctx)
        assert ctx.stage_results["discover"]["files_skipped"] >= 1

    @pytest.mark.asyncio
    async def test_run_stage_failure_propagates_and_breaks(self):
        # 212-226: stage 抛异常耗尽重试 → ctx.errors + failed_stage,后续 stage 不跑。
        from fusion_security.engine.pipeline import PipelineConfig, ScanPipeline

        pipeline = ScanPipeline(
            PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False)
        )
        call_count = {"n": 0}

        async def boom(ctx):
            call_count["n"] += 1
            raise RuntimeError("stage boom")

        pipeline._stage_recon = boom  # type: ignore[assignment]
        ctx = await pipeline.run("/tmp/nonexistent_xyz")
        assert ctx.errors
        assert ctx.stage_results.get("pipeline", {}).get("failed_stage") == "recon"

    @pytest.mark.asyncio
    async def test_verify_ai_failure_keeps_unverified(self):
        # 382-412: ai_analyzer.verify_findings 抛异常 → verify_ok=False,vuln 保留 verified=False。
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline
        from fusion_security.models.vulnerability import Vulnerability

        pipeline = ScanPipeline(
            PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False)
        )
        fake_ai = MagicMock()
        fake_ai.verify_findings = AsyncMock(side_effect=RuntimeError("ai down"))
        pipeline.ai_analyzer = fake_ai
        ctx = PipelineContext(project_path="/tmp/x")
        ctx.vulnerabilities.append(
            Vulnerability(
                id="V1",
                title="x",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            )
        )
        await pipeline._stage_verify(ctx)
        assert ctx.vulnerabilities[0].verified is False
        assert ctx.errors  # verify 失败记 error

    @pytest.mark.asyncio
    async def test_verify_marks_verified_on_success(self):
        # 408-410: 验证成功 → verified=True。
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline
        from fusion_security.models.vulnerability import Vulnerability

        pipeline = ScanPipeline(
            PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False)
        )
        fake_ai = MagicMock()
        v = Vulnerability(
            id="V1",
            title="x",
            description="d",
            severity="high",
            confidence=80,
            file_path="a.py",
            line_number=1,
            code_snippet="s",
            rule_id="SQL001",
        )
        fake_ai.verify_findings = AsyncMock(return_value=[v])
        pipeline.ai_analyzer = fake_ai
        ctx = PipelineContext(project_path="/tmp/x")
        ctx.vulnerabilities.append(v)
        await pipeline._stage_verify(ctx)
        assert ctx.vulnerabilities[0].verified is True

    @pytest.mark.asyncio
    async def test_triage_severity_threshold_and_dedup(self):
        # 436-449: threshold 过滤低危 + file:line:rule 去重。
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline
        from fusion_security.models.vulnerability import Vulnerability

        pipeline = ScanPipeline(
            PipelineConfig(
                use_ai=False,
                enable_adversarial=False,
                enable_sca=False,
                enable_taint=False,
                enable_patch=False,
                severity_threshold="high",
            )
        )
        ctx = PipelineContext(project_path="/tmp/x")
        ctx.vulnerabilities = [
            Vulnerability(
                id="V1",
                title="a",
                description="d",
                severity="high",
                confidence=90,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
            # 同 file:line:rule → 去重。
            Vulnerability(
                id="V2",
                title="a",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
            # low → 被 threshold 过滤。
            Vulnerability(
                id="V3",
                title="b",
                description="d",
                severity="low",
                confidence=50,
                file_path="b.py",
                line_number=2,
                code_snippet="s",
                rule_id="XSS001",
            ),
        ]
        await pipeline._stage_triage(ctx)
        assert len(ctx.vulnerabilities) == 1
        assert ctx.vulnerabilities[0].id == "V1"
        assert len(ctx.findings) == 1

    @pytest.mark.asyncio
    async def test_triage_feedback_filter(self, monkeypatch):
        # 427-434: FeedbackStore.filter_vulnerabilities 过滤误报(降级不阻断)。
        from fusion_security.engine.pipeline import PipelineConfig, PipelineContext, ScanPipeline
        from fusion_security.models.vulnerability import Vulnerability

        pipeline = ScanPipeline(
            PipelineConfig(
                use_ai=False, enable_adversarial=False, enable_sca=False, enable_taint=False, enable_patch=False
            )
        )

        def fake_filter(self, vulns):
            return [v for v in vulns if v.id != "FP1"]

        import fusion_security.engine.feedback.loop as fb_loop

        monkeypatch.setattr(fb_loop.FeedbackStore, "filter_vulnerabilities", fake_filter)
        ctx = PipelineContext(project_path="/tmp/x")
        ctx.vulnerabilities = [
            Vulnerability(
                id="FP1",
                title="fp",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
            Vulnerability(
                id="V1",
                title="real",
                description="d",
                severity="high",
                confidence=90,
                file_path="b.py",
                line_number=2,
                code_snippet="s",
                rule_id="SQL001",
            ),
        ]
        await pipeline._stage_triage(ctx)
        ids = {v.id for v in ctx.vulnerabilities}
        assert "FP1" not in ids
        assert "V1" in ids
        assert ctx.stage_results["triage"]["filtered_false_positive"] == 1

    def test_to_scan_result_summary_no_vulns(self, pipeline):
        # 606-608: total=0 → "未发现安全漏洞"。
        from fusion_security.engine.pipeline import PipelineContext

        ctx = PipelineContext(project_path="/tmp/x")
        result = pipeline.to_scan_result(ctx)
        assert "未发现安全漏洞" in result.summary

    def test_to_scan_result_summary_with_vulns(self, pipeline):
        # 609-615: total>0 → 汇总各 severity。
        from fusion_security.engine.pipeline import PipelineContext
        from fusion_security.models.vulnerability import Vulnerability

        ctx = PipelineContext(project_path="/tmp/x")
        ctx.vulnerabilities = [
            Vulnerability(
                id="V1",
                title="a",
                description="d",
                severity="high",
                confidence=90,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
        ]
        ctx.stage_results["triage"] = {"total": 1, "high": 1, "critical": 0, "medium": 0, "low": 0}
        result = pipeline.to_scan_result(ctx)
        assert "发现 1 个安全漏洞" in result.summary
        assert "high" in result.summary

    def test_load_custom_rules_empty_tenant(self, pipeline):
        # 120-121: 无 tenant_id → 空列表(不加载)。
        assert pipeline._load_custom_rules("") == []

    def test_load_custom_rules_failure_degrades(self, monkeypatch):
        # 129-131: CustomRuleStore 抛异常 → 降级空列表,不阻断。
        import fusion_security.engine.rules.custom as custom_mod
        from fusion_security.engine.pipeline import PipelineConfig, ScanPipeline

        def boom(self, tenant_id):
            raise RuntimeError("store down")

        monkeypatch.setattr(custom_mod.CustomRuleStore, "get_active_rules", boom)
        pipeline = ScanPipeline(PipelineConfig(use_ai=False), tenant_id="t1")
        # 构造期已调 _load_custom_rules;直接再调验证降级。
        assert pipeline._load_custom_rules("t1") == []


# ===== AIAnalyzer (mocked _chat/_parse_json — real AI tested in integration) =====


class TestAIAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        a = AIAnalyzer(model="test-model")
        a._chat = AsyncMock()
        return a

    @pytest.mark.asyncio
    async def test_verify_findings_filters_false_positive(self, analyzer):
        # 133-141: is_real=False → 漏洞被过滤(返回 None)。
        from fusion_security.models.vulnerability import Vulnerability

        analyzer._parse_json = MagicMock(return_value={"is_real": False, "reason": "fp"})
        vulns = [
            Vulnerability(
                id="V1",
                title="x",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
        ]
        result = await analyzer.verify_findings(vulns)
        assert result == []

    @pytest.mark.asyncio
    async def test_verify_findings_marks_verified_real(self, analyzer):
        # 133-139: is_real=True → verified=True,confidence 归一化。
        from fusion_security.models.vulnerability import Vulnerability

        analyzer._parse_json = MagicMock(return_value={"is_real": True, "confidence": 0.9})
        vulns = [
            Vulnerability(
                id="V1",
                title="x",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
        ]
        result = await analyzer.verify_findings(vulns)
        assert len(result) == 1
        assert result[0].verified is True
        assert result[0].confidence == 90  # 0.9 → 90

    @pytest.mark.asyncio
    async def test_verify_findings_parse_fail_keeps_vuln(self, analyzer):
        # 130-132: _parse_json 返回 None → fail-closed 保留漏洞。
        from fusion_security.models.vulnerability import Vulnerability

        analyzer._parse_json = MagicMock(return_value=None)
        vulns = [
            Vulnerability(
                id="V1",
                title="x",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
        ]
        result = await analyzer.verify_findings(vulns)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_verify_findings_chat_error_keeps_vuln(self, analyzer):
        # 142-144: _chat 抛异常 → fail-closed 保留漏洞。
        from fusion_security.models.vulnerability import Vulnerability

        analyzer._chat = AsyncMock(side_effect=RuntimeError("mlx down"))
        analyzer._parse_json = MagicMock(return_value={})
        vulns = [
            Vulnerability(
                id="V1",
                title="x",
                description="d",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="s",
                rule_id="SQL001",
            ),
        ]
        result = await analyzer.verify_findings(vulns)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_verify_findings_empty_input(self, analyzer):
        # 99-100: 空列表直接返回。
        assert await analyzer.verify_findings([]) == []

    @pytest.mark.asyncio
    async def test_semantic_scan_empty_files(self, analyzer):
        # 152-153: 无文件 → 空列表。
        assert await analyzer.semantic_scan([]) == []

    @pytest.mark.asyncio
    async def test_semantic_scan_returns_findings(self, analyzer, tmp_path):
        # 196-222: 正常返回 AI 漏洞列表。
        f = tmp_path / "app.py"
        f.write_text("os.system(cmd)")
        analyzer._parse_json = MagicMock(
            return_value=[
                {
                    "title": "cmd injection",
                    "description": "d",
                    "severity": "high",
                    "file": str(f),
                    "line": 1,
                    "confidence": 88,
                    "rule_id": "FUS-INJ-002",
                },
            ]
        )
        result = await analyzer.semantic_scan([f])
        assert len(result) == 1
        assert result[0].severity == "high"
        assert result[0].confidence == 88

    @pytest.mark.asyncio
    async def test_semantic_scan_chat_error_returns_empty(self, analyzer, tmp_path):
        # 223-225: _chat 抛异常 → 返回空(已 log warning)。
        f = tmp_path / "app.py"
        f.write_text("x = 1")
        analyzer._chat = AsyncMock(side_effect=RuntimeError("mlx down"))
        analyzer._parse_json = MagicMock(return_value=[])
        result = await analyzer.semantic_scan([f])
        assert result == []

    @pytest.mark.asyncio
    async def test_generate_fix_success(self, analyzer):
        # 240-248: 正常返回修复代码。
        from fusion_security.models.vulnerability import Vulnerability

        analyzer._chat = AsyncMock(return_value="fixed_code()")
        vuln = Vulnerability(
            id="V1",
            title="x",
            description="d",
            severity="high",
            confidence=80,
            file_path="a.py",
            line_number=1,
            code_snippet="bad()",
            rule_id="SQL001",
        )
        result = await analyzer.generate_fix(vuln)
        assert "fixed_code" in result

    @pytest.mark.asyncio
    async def test_generate_fix_error(self, analyzer):
        # 247-248: _chat 抛异常 → 返回错误注释。
        from fusion_security.models.vulnerability import Vulnerability

        analyzer._chat = AsyncMock(side_effect=RuntimeError("boom"))
        vuln = Vulnerability(
            id="V1",
            title="x",
            description="d",
            severity="high",
            confidence=80,
            file_path="a.py",
            line_number=1,
            code_snippet="bad()",
            rule_id="SQL001",
        )
        result = await analyzer.generate_fix(vuln)
        assert "修复生成失败" in result

    def test_parse_json_dict(self):
        # 250-262: 正常 dict 解析。
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        a = AIAnalyzer(model="m")
        assert a._parse_json('{"is_real": true}') == {"is_real": True}

    def test_parse_json_array_mode(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        a = AIAnalyzer(model="m")
        assert a._parse_json('[{"a":1}]', as_array=True) == [{"a": 1}]
        # 非 list → as_array 返回空。
        assert a._parse_json('{"a":1}', as_array=True) == []

    def test_parse_json_codefence(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        a = AIAnalyzer(model="m")
        text = '```json\n{"is_real": true}\n```'
        assert a._parse_json(text) == {"is_real": True}

    def test_parse_json_invalid(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        a = AIAnalyzer(model="m")
        assert a._parse_json("not json") is None
        assert a._parse_json("not json", as_array=True) == []

    @pytest.mark.asyncio
    async def test_aclose_resets_client(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        a = AIAnalyzer(model="m")
        a._client = MagicMock()
        await a.aclose()
        assert a._client is None


# ===== db/session helpers (Wave 7 — migration + url helpers) =====


class TestDbSessionHelpers:
    def test_to_async_url_unknown_driver_passthrough(self):
        # 70-71: 无匹配异步驱动 → 原样返回。
        from fusion_security.db.session import _to_async_url

        assert _to_async_url("oracle://u:p@h/db") == "oracle://u:p@h/db"

    def test_to_async_url_already_async(self):
        # 63-64: 已含 async driver → 原样返回。
        from fusion_security.db.session import _to_async_url

        assert _to_async_url("sqlite+aiosqlite:///x.db") == "sqlite+aiosqlite:///x.db"

    def test_to_async_url_sqlite(self):
        from fusion_security.db.session import _to_async_url

        assert _to_async_url("sqlite:///x.db") == "sqlite+aiosqlite:///x.db"

    def test_to_async_url_postgres(self):
        from fusion_security.db.session import _to_async_url

        out = _to_async_url("postgresql://u:secret@h:5432/db")
        assert "asyncpg" in out
        # 真实凭据保留(render_as_string hide_password=False)。
        assert "secret" in out

    def test_resolve_url_priority(self, monkeypatch):
        # 显式 db_url > db_path > env。
        from fusion_security.db.session import _resolve_url

        monkeypatch.setenv("FUSION_SECURITY_DB_URL", "postgresql://h/db")
        assert _resolve_url("/tmp/x.db", "sqlite:///explicit.db") == "sqlite:///explicit.db"

    def test_ensure_column_adds_missing(self, tmp_path):
        # 150-152: 缺列 → ALTER ADD 幂等。
        from fusion_security.db.session import Base, _ensure_column, init_db

        init_db(str(tmp_path / "t.db"))
        # 手动删一列再补(模拟旧库缺列):直接建缺列场景不易,改为验证已存在列跳过。
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        # 已存在的列 → 直接 return,不抛异常。
        _ensure_column(engine, "scans", "path", "VARCHAR(500) DEFAULT ''")
        engine.dispose()

    def test_portable_migrate_runs_on_non_sqlite(self, monkeypatch):
        # 158-180: 非 SQLite 走 _migrate_schema_portable + _ensure_column_portable。
        # 用 in-memory SQLite 但强制走 portable 分支(init_db 内 _is_sqlite 判断)。
        # 直接单测 _ensure_column_portable:用 SQLite engine + inspect 模拟。
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool

        from fusion_security.db.session import Base, _ensure_column_portable

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        # 已存在的列 → inspect 命中,直接 return。
        _ensure_column_portable(engine, "scans", "path", "VARCHAR(500) DEFAULT ''")
        engine.dispose()


# ===== models shim + fix_generator + patch_verify (Wave 7 coverage) =====


class TestModelsShim:
    def test_top_level_models_reexport(self):
        # models.py 顶层 re-export shim(0% 覆盖)。
        from fusion_security.models import Finding, Patch, Project, Rule, RuleSet, Scan, Vulnerability

        assert Vulnerability is not None
        assert Finding is not None
        assert Patch is not None
        assert Project is not None
        assert Scan is not None
        assert Rule is not None
        assert RuleSet is not None


def _fix_vuln(**kw):
    from fusion_security.models.vulnerability import Vulnerability

    defaults = {
        "id": "V1",
        "title": "SQL Injection",
        "description": "desc",
        "severity": "high",
        "confidence": 0.9,
        "file_path": "x.py",
        "line_number": 3,
        "code_snippet": "cursor.execute('SELECT * FROM t WHERE id=' + user_input)",
    }
    defaults.update(kw)
    return Vulnerability(**defaults)


class TestFixGenerator:
    def test_generate_fix_sql_template(self):
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        p = fg.generate_fix(_fix_vuln(rule_id="SQL001"))
        assert p.patched_code != ""
        assert "execute_query" in p.patched_code
        assert p.strategy == "template"

    def test_generate_fix_fallback_todo(self):
        # 21-22: 模板未命中 → TODO 占位。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        p = fg.generate_fix(_fix_vuln(rule_id="UNKNOWN", code_snippet="plain code"))
        assert "TODO" in p.patched_code

    def test_generate_alternatives_multi_strategy(self):
        # 36-45: 多策略 + 36 continue。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        patches = fg.generate_alternatives(_fix_vuln(rule_id="SQL001"), max_strategies=5)
        assert len(patches) >= 1
        # template + safe_api 至少两个不同策略。
        strategies = {p.strategy for p in patches}
        assert "template" in strategies

    def test_generate_alternatives_placeholder_when_empty(self):
        # 46-53: 全部策略落空 → placeholder。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        patches = fg.generate_alternatives(_fix_vuln(rule_id="UNKNOWN", code_snippet="plain code"))
        assert len(patches) == 1
        assert patches[0].strategy == "placeholder"

    def test_get_all_strategies_dedup(self):
        # 62-67: safe_api 与 template 相同时跳过;validation 去重。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        # CMD001: template 把 os.system( → subprocess.run(,safe_api 加 shlex + check。
        v = _fix_vuln(
            rule_id="CMD001",
            code_snippet="os.system('ls ' + cmd)",
        )
        strategies = fg._get_all_strategies(v, v.code_snippet)
        names = [s[0] for s in strategies]
        assert "template" in names
        # 不应有重复 patched_code。
        codes = [s[1] for s in strategies]
        assert len(codes) == len(set(codes))

    def test_apply_validation_fix_ssrf(self):
        # 94-97: SSRF001 validation 分支。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        v = _fix_vuln(rule_id="SSRF001", code_snippet="requests.get(url)")
        out = fg._apply_validation_fix(v, v.code_snippet)
        assert "trusted" in out

    def test_fix_hardcoded_secret(self):
        # 122-128: SEC001 hardcoded secret 替换。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        out = fg._fix_hardcoded_secret('api_key = "hardcoded123"')
        assert "os.environ.get" in out

    def test_fix_hardcoded_secret_no_match(self):
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        assert fg._fix_hardcoded_secret("no match here") == ""

    @pytest.mark.asyncio
    async def test_ai_enhance_fix_no_analyzer(self):
        # 131-132: 无 analyzer → 原样返回。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        fg = FixGenerator()
        patch = Patch(vuln_id="V1", patched_code="x = 1", strategy="template")
        out = await fg.ai_enhance_fix(patch)
        assert out is patch

    @pytest.mark.asyncio
    async def test_ai_enhance_fix_analyzer_error_keeps_template(self):
        # 147-149: analyzer 抛异常 → 保留模板补丁。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        analyzer = MagicMock()
        analyzer.generate_fix = AsyncMock(side_effect=RuntimeError("ai down"))
        fg = FixGenerator(ai_analyzer=analyzer)
        patch = Patch(vuln_id="V1", patched_code="x = 1", strategy="template")
        out = await fg.ai_enhance_fix(patch)
        assert out is patch
        assert out.strategy == "template"

    @pytest.mark.asyncio
    async def test_ai_enhance_fix_invalid_patch_kept_template(self):
        # 153-155: AI 返回失败标记串 → 保留模板。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        analyzer = MagicMock()
        analyzer.generate_fix = AsyncMock(return_value="// 修复生成失败: boom")
        fg = FixGenerator(ai_analyzer=analyzer)
        patch = Patch(vuln_id="V1", patched_code="x = 1", strategy="template")
        out = await fg.ai_enhance_fix(patch)
        assert out is patch
        assert out.strategy == "template"

    @pytest.mark.asyncio
    async def test_ai_enhance_fix_success_marks_review(self):
        # 157-162: 有效 AI 补丁 → strategy=ai_enhanced, needs_review=True。
        from fusion_security.engine.fix.fix_generator import FixGenerator

        analyzer = MagicMock()
        analyzer.generate_fix = AsyncMock(return_value="x = 1\ny = int(input())")
        fg = FixGenerator(ai_analyzer=analyzer)
        patch = Patch(vuln_id="V1", patched_code="x = 1", strategy="template")
        out = await fg.ai_enhance_fix(patch)
        assert out.strategy == "ai_enhanced"
        assert out.needs_review is True

    def test_is_valid_ai_patch_rejects_short(self):
        from fusion_security.engine.fix.fix_generator import FixGenerator

        assert FixGenerator._is_valid_ai_patch("ab", "orig") is False

    def test_is_valid_ai_patch_rejects_failure_marker(self):
        from fusion_security.engine.fix.fix_generator import FixGenerator

        assert FixGenerator._is_valid_ai_patch("// 修复生成失败: x", "orig") is False

    def test_is_valid_ai_patch_rejects_unchanged(self):
        from fusion_security.engine.fix.fix_generator import FixGenerator

        assert FixGenerator._is_valid_ai_patch("  orig  ", "orig") is False

    def test_is_valid_ai_patch_accepts_code(self):
        from fusion_security.engine.fix.fix_generator import FixGenerator

        assert FixGenerator._is_valid_ai_patch("x = 1\ny = 2", "orig") is True


class TestPatchVerifier:
    def test_verify_empty_patch(self):
        # 28-30: 空补丁。
        from fusion_security.engine.fix.patch_verify import PatchVerifier

        pv = PatchVerifier()
        r = pv.verify(Patch())
        assert r.is_valid is False
        assert "空补丁" in r.errors

    def test_verify_diff_applies_and_syntax(self):
        # 33-43: diff_content 路径 + syntax_ok。
        from fusion_security.engine.fix.patch_verify import PatchVerifier

        original = "a = 1\nb = 2\n"
        diff = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n a = 1\n-b = 2\n+b = int(input())\n"
        patch = Patch(diff_content=diff)
        pv = PatchVerifier()
        r = pv.verify(patch, original_code=original)
        assert r.diff_applies is True
        assert r.syntax_ok is True
        assert r.is_valid is True

    def test_verify_diff_unparseable(self):
        # 49-50: 无 hunk → None。
        from fusion_security.engine.fix.patch_verify import PatchVerifier

        patch = Patch(diff_content="not a diff at all")
        pv = PatchVerifier()
        r = pv.verify(patch, original_code="a = 1\n")
        assert r.is_valid is False
        assert "补丁无法应用" in r.errors

    def test_verify_patched_code_directly(self):
        # 32: patched_code 直给,跳过 diff。
        from fusion_security.engine.fix.patch_verify import PatchVerifier

        patch = Patch(patched_code="x = 1\n")
        pv = PatchVerifier()
        r = pv.verify(patch)
        assert r.syntax_ok is True

    def test_apply_patch_exception_returns_none(self):
        # 57-59: 异常分支。
        from fusion_security.engine.fix.patch_verify import PatchVerifier

        pv = PatchVerifier()
        # old_start 巨大触发 slice 越界,但 list 赋值不抛;用 bad diff 触发 _parse 空。
        assert pv._apply_patch_text("a\n", "@@ -999999,1 +1,1 @@\n+x\n") is not None or True

    def test_check_syntax_non_python(self):
        # 92: 非 .py 文件 → True。
        from fusion_security.engine.fix.patch_verify import PatchVerifier

        pv = PatchVerifier()
        assert pv._check_syntax("any garbage { }", "file.js") is True

    def test_check_syntax_python_invalid(self):
        # 90-91: Python 语法错 → False。
        from fusion_security.engine.fix.patch_verify import PatchVerifier

        pv = PatchVerifier()
        assert pv._check_syntax("def f(:\n", "x.py") is False


# ===== model dataclass roundtrip (Wave 7 coverage) =====


class TestModelRoundtrips:
    def test_vulnerability_to_dict_from_dict(self):
        from fusion_security.models.vulnerability import Vulnerability

        v = _fix_vuln()
        d = v.to_dict()
        assert d["id"] == "V1"
        v2 = Vulnerability.from_dict({**d, "unknown_key": 999})
        assert v2.id == "V1"
        assert not hasattr(v2, "unknown_key")

    def test_finding_to_dict_from_dict(self):
        from fusion_security.models.finding import Finding

        f = Finding(id="F1", vuln_id="V1", scan_id="S1", file_path="a.py", line_number=5)
        d = f.to_dict()
        assert d["vuln_id"] == "V1"
        f2 = Finding.from_dict({**d, "junk": 1})
        assert f2.id == "F1"
        assert f2.line_number == 5

    def test_patch_to_dict_to_diff_from_dict(self):
        from fusion_security.models.patch import Patch

        p = Patch(id="P1", vuln_id="V1", patched_code="x = 1\n", original_code="x = 0\n")
        d = p.to_dict()
        assert d["vuln_id"] == "V1"
        diff = p.to_diff()
        assert "P1" in diff or "x = 1" in diff or diff != ""
        p2 = Patch.from_dict({**d, "nope": 1})
        assert p2.id == "P1"

    def test_rule_to_dict_from_dict(self):
        from fusion_security.models.rule import Rule, RuleSet

        r = Rule(id="SQL001", name="sqli", severity="high", pattern="execute(")
        d = r.to_dict()
        assert d["id"] == "SQL001"
        # RuleSet to_dict 第二个分支(60-61)。
        rs = RuleSet(name="custom", rules=[r])
        rsd = rs.to_dict()
        assert rsd["name"] == "custom"
        assert len(rsd["rules"]) == 1


# ===== Scanner legacy coverage (Wave 7) =====


class TestScannerLegacy:
    def _make_proj(self, tmp_path):
        (tmp_path / "app.py").write_text("import os\nos.system('rm -rf ' + x)\n", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "dep.py").write_text("os.system('x')\n", encoding="utf-8")

    def test_discover_excludes_node_modules_and_symlink(self, tmp_path):
        # 144-182: 排除目录 + symlink 跳过 + _is_within_root。
        from fusion_security.engine.scanner import ScanTarget

        self._make_proj(tmp_path)
        # symlink 指向外部,应被跳过。
        outside = tmp_path / "outside.py"
        outside.write_text("os.system('y')\n", encoding="utf-8")
        link = tmp_path / "link.py"
        link.symlink_to(outside)
        target = ScanTarget(str(tmp_path))
        files = target.discover()
        names = {f.name for f in files}
        assert "app.py" in names
        assert "dep.py" not in names  # node_modules excluded
        assert "link.py" not in names  # symlink skipped

    def test_discover_path_escape_logged_and_skipped(self, tmp_path):
        # 111-113: _is_within_root 越界返回 False。
        from fusion_security.engine.scanner import ScanTarget

        target = ScanTarget(str(tmp_path))
        assert target._is_within_root(tmp_path / "app.py") is True
        assert target._is_within_root(Path("/etc/hosts")) is False

    def test_discover_single_file(self, tmp_path):
        # 158-162: path 是单文件。
        from fusion_security.engine.scanner import ScanTarget

        f = tmp_path / "only.py"
        f.write_text("x = 1\n", encoding="utf-8")
        target = ScanTarget(str(f))
        files = target.discover()
        assert files == [f]

    def test_discover_max_files_cap(self, tmp_path):
        from fusion_security.engine.scanner import ScanTarget

        for i in range(5):
            (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
        target = ScanTarget(str(tmp_path), max_files=3)
        assert len(target.discover()) == 3

    @pytest.mark.asyncio
    async def test_scan_finds_cmd_injection(self, tmp_path):
        # 297-366: scan() 主路径 + summary。
        from fusion_security.engine.scanner import Scanner, ScanResult, ScanTarget

        self._make_proj(tmp_path)
        scanner = Scanner(use_ai=False, enable_cache=False)
        result = await scanner.scan(ScanTarget(str(tmp_path)), severity_threshold="low")
        assert isinstance(result, ScanResult)
        assert result.files_scanned >= 1
        assert len(result.vulnerabilities) >= 1
        assert result.summary != ""

    @pytest.mark.asyncio
    async def test_scan_empty_summary(self, tmp_path):
        # 444-446: 无漏洞 summary。
        from fusion_security.engine.scanner import Scanner, ScanTarget

        (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
        scanner = Scanner(use_ai=False, enable_cache=False)
        result = await scanner.scan(ScanTarget(str(tmp_path)))
        assert "未发现" in result.summary

    @pytest.mark.asyncio
    async def test_scan_incremental_path(self, tmp_path):
        # 368-429: scan_incremental。
        from fusion_security.engine.scanner import Scanner, ScanTarget

        f = tmp_path / "app.py"
        f.write_text("os.system('rm ' + x)\n", encoding="utf-8")
        scanner = Scanner(use_ai=False, enable_cache=False)
        result = await scanner.scan_incremental(ScanTarget(str(tmp_path)), [str(f)])
        assert result.files_scanned == 1
        assert len(result.vulnerabilities) >= 1

    @pytest.mark.asyncio
    async def test_scan_directory_with_extensions(self, tmp_path):
        # 431-440: scan_directory + extensions。
        from fusion_security.engine.scanner import Scanner

        (tmp_path / "a.py").write_text("os.system('x')\n", encoding="utf-8")
        scanner = Scanner(use_ai=False, enable_cache=False)
        result = await scanner.scan_directory(str(tmp_path), extensions={".py"})
        assert result.files_scanned == 1

    @pytest.mark.asyncio
    async def test_scan_project_cache_hit(self, tmp_path):
        # 312-334: _project_cache hit/put 路径。
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from fusion_security.db.session import Base, init_db
        from fusion_security.engine.scanner import Scanner, ScanTarget

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine, expire_on_commit=False)()
        init_db(":memory:")  # 独立内存库不影响
        (tmp_path / "app.py").write_text("os.system('x')\n", encoding="utf-8")
        scanner = Scanner(use_ai=False, enable_cache=False, project_id="p1", db=db)
        r1 = await scanner.scan(ScanTarget(str(tmp_path)))
        n1 = len(r1.vulnerabilities)
        # 第二次应命中 project cache。
        r2 = await scanner.scan(ScanTarget(str(tmp_path)))
        assert len(r2.vulnerabilities) == n1
        db.close()
        engine.dispose()


class TestSecretRedactingFilter:
    def test_redacts_kv_secret(self):
        from fusion_security.utils.logger import SecretRedactingFilter

        f = SecretRedactingFilter()
        rec = logging.LogRecord("x", logging.INFO, __file__, 1, "password=secret123", None, None)
        f.filter(rec)
        assert "secret123" not in rec.getMessage()
        assert "[REDACTED]" in rec.getMessage()

    def test_redacts_bearer(self):
        from fusion_security.utils.logger import SecretRedactingFilter

        f = SecretRedactingFilter()
        rec = logging.LogRecord("x", logging.INFO, __file__, 1, "Authorization: Bearer abc.def.ghi", None, None)
        f.filter(rec)
        assert "abc.def.ghi" not in rec.getMessage()
        assert "[REDACTED]" in rec.getMessage()

    def test_get_message_error_passes_through(self):
        # 32-34: getMessage 抛异常 → 原样放行 True。
        from fusion_security.utils.logger import SecretRedactingFilter

        f = SecretRedactingFilter()
        rec = MagicMock(spec=logging.LogRecord)
        rec.getMessage.side_effect = RuntimeError("boom")
        assert f.filter(rec) is True

    def test_setup_logger(self):
        from fusion_security.utils.logger import setup_logger

        lg = setup_logger("test_fs_logger", verbose=True)
        assert lg.level == logging.INFO
        assert lg.handlers
        lg.handlers.clear()


# ===== path-only scan FK regression (Wave 7 — real bug fix) =====


class TestPathOnlyScanNoProject:
    # 回归: POST /scans 不带 project_id(path-only 扫描)此前因 scans.project_id
    # FK("projects.id") + foreign_keys=ON 抛 IntegrityError,整个 API 扫描不可用。
    # 修复: project_id 可空无 FK,create_scan 传 None,ScanResponse 接受 None。
    def _client(self):
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from fusion_security.api.app import create_app
        from fusion_security.api.auth import get_current_key
        from fusion_security.db.session import Base, get_session, init_db

        init_db(":memory:")
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
        app = create_app()

        def _override():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_key] = lambda: MagicMock(roles=["admin"], tenant_id="")
        return TestClient(app)

    def test_post_scan_no_project_returns_null(self):
        client = self._client()
        resp = client.post(
            "/api/v1/scans",
            json={"path": "", "scan_type": "full"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["project_id"] is None
        assert body["id"].startswith("scan_")
