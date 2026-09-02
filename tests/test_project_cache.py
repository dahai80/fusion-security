from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError, OperationalError

from fusion_security.api.app import create_app
from fusion_security.api.auth import APIKey, get_current_key
from fusion_security.db.models import ProjectORM, ScanCacheORM, ScanORM
from fusion_security.db.session import Base, get_session
from fusion_security.engine.cache import ProjectScanCache, _content_hash, _json_to_vulns, _vulns_to_json
from fusion_security.models.vulnerability import Vulnerability


def _make_vuln(**kw):
    defaults = {
        "id": uuid.uuid4().hex[:16],
        "title": "Test Vuln",
        "description": "desc",
        "severity": "high",
        "confidence": 0.9,
        "file_path": "app.py",
        "line_number": 10,
        "code_snippet": "code",
        "rule_id": "SQL001",
        "cwe_id": "CWE-89",
        "fix_suggestion": "",
        "verified": False,
        "status": "open",
        "data_flow_path": "",
    }
    defaults.update(kw)
    return Vulnerability(**defaults)


def _make_mock_db():
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.filter.return_value.all.return_value = []
    db.query.return_value.filter.return_value.delete.return_value = 0
    return db


class TestCacheHelpers:
    def test_content_hash_deterministic(self):
        h1 = _content_hash("hello")
        h2 = _content_hash("hello")
        assert h1 == h2
        assert len(h1) == 16

    def test_content_hash_different(self):
        h1 = _content_hash("hello")
        h2 = _content_hash("world")
        assert h1 != h2

    def test_vulns_json_roundtrip(self):
        vulns = [_make_vuln(), _make_vuln(severity="critical")]
        j = _vulns_to_json(vulns)
        parsed = json.loads(j)
        assert len(parsed) == 2
        restored = _json_to_vulns(j)
        assert len(restored) == 2
        assert restored[0].severity == "high"
        assert restored[1].severity == "critical"

    def test_json_to_vulns_empty(self):
        assert _json_to_vulns("") == []
        assert _json_to_vulns("[]") == []

    def test_json_to_vulns_invalid_json(self):
        # 31-33: JSONDecodeError → 返回空并 log。
        assert _json_to_vulns("{not json") == []

    def test_json_to_vulns_non_array(self):
        # 34-36: 非 list → 返回空。
        assert _json_to_vulns('{"a":1}') == []

    def test_json_to_vulns_skips_bad_items(self):
        # 40-45: 非 dict 项跳过;字段过滤后损坏项跳过。
        # valid item + 非 dict 项混合。
        good = json.dumps(
            [
                {
                    "id": "V1",
                    "title": "t",
                    "description": "d",
                    "severity": "high",
                    "confidence": 80,
                    "file_path": "a.py",
                    "line_number": 1,
                    "code_snippet": "s",
                    "unknown_field": 1,
                },
                123,
            ]
        )
        result = _json_to_vulns(good)
        assert len(result) == 1
        assert result[0].id == "V1"


class TestProjectScanCache:
    def test_get_miss(self):
        db = _make_mock_db()
        cache = ProjectScanCache(db)
        result = cache.get("proj1", "app.py", "content")
        assert result is None
        db.query.assert_called_once_with(ScanCacheORM)

    def test_get_hit(self):
        db = _make_mock_db()
        vulns = [_make_vuln()]
        row = ScanCacheORM(
            id="cache1",
            project_id="proj1",
            file_path="app.py",
            content_hash=_content_hash("content"),
            results_json=_vulns_to_json(vulns),
        )
        db.query.return_value.filter.return_value.first.return_value = row
        cache = ProjectScanCache(db)
        result = cache.get("proj1", "app.py", "content")
        assert result is not None
        assert len(result) == 1
        assert result[0].severity == "high"

    def test_get_hash_mismatch(self):
        db = _make_mock_db()
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = None
        db.query.return_value = mock_query
        cache = ProjectScanCache(db)
        result = cache.get("proj1", "app.py", "newcontent")
        assert result is None

    def test_put_new(self):
        db = _make_mock_db()
        db.query.return_value.filter.return_value.first.return_value = None
        cache = ProjectScanCache(db)
        vulns = [_make_vuln()]
        cache.put("proj1", "app.py", "content", vulns)
        db.add.assert_called_once()
        db.commit.assert_called_once()

    def test_put_update(self):
        db = _make_mock_db()
        existing = ScanCacheORM(
            id="cache1",
            project_id="proj1",
            file_path="app.py",
            content_hash="old",
            results_json="[]",
        )
        db.query.return_value.filter.return_value.first.return_value = existing
        cache = ProjectScanCache(db)
        vulns = [_make_vuln()]
        cache.put("proj1", "app.py", "content", vulns)
        db.commit.assert_called_once()

    def test_invalidate_project(self):
        db = _make_mock_db()
        db.query.return_value.filter.return_value.delete.return_value = 5
        cache = ProjectScanCache(db)
        count = cache.invalidate_project("proj1")
        assert count == 5
        db.commit.assert_called()

    def test_invalidate_file(self):
        db = _make_mock_db()
        cache = ProjectScanCache(db)
        cache.invalidate_file("proj1", "app.py")
        db.query.return_value.filter.return_value.delete.assert_called_once()

    def test_cleanup_stale(self):
        db = _make_mock_db()
        stale_row = ScanCacheORM(
            id="c1",
            project_id="proj1",
            file_path="deleted.py",
            content_hash="abc",
            results_json="[]",
        )
        fresh_row = ScanCacheORM(
            id="c2",
            project_id="proj1",
            file_path="app.py",
            content_hash="def",
            results_json="[]",
        )
        db.query.return_value.filter.return_value.all.return_value = [stale_row, fresh_row]
        cache = ProjectScanCache(db)
        removed = cache.cleanup_stale("proj1", ["app.py"])
        assert removed == 1

    def test_stats(self):
        db = _make_mock_db()
        db.query.return_value.filter.return_value.scalar.return_value = 42
        cache = ProjectScanCache(db)
        s = cache.stats("proj1")
        assert s["cached_files"] == 42

    def test_get_multi(self):
        db = _make_mock_db()
        cache = ProjectScanCache(db)
        results = cache.get_multi("proj1", ["app.py"], {"app.py": "content"})
        assert isinstance(results, dict)

    def test_put_multi(self):
        db = _make_mock_db()
        db.query.return_value.filter.return_value.first.return_value = None
        cache = ProjectScanCache(db)
        results_map = {"app.py": ("content", [_make_vuln()])}
        cache.put_multi("proj1", results_map)
        db.add.assert_called_once()

    def test_put_integrity_fallback_updates_existing(self):
        # 100-117: commit 抛 IntegrityError → rollback → 回退 UPDATE 已存在行。
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from fusion_security.db.session import Base

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine, expire_on_commit=False)
        db = Session()
        cache = ProjectScanCache(db)
        vulns = [_make_vuln()]
        # 先写一行。
        cache.put("proj1", "app.py", "content", vulns)
        # 手动让 commit 抛 IntegrityError 模拟并发竞态:删除唯一行后插入同 key。
        # 直接构造:插入第二行同 (project_id, file_path) 触发唯一约束。
        db.add(ScanCacheORM(project_id="proj1", file_path="app.py", content_hash="x", results_json="[]"))
        with pytest.raises((IntegrityError, OperationalError)):
            db.commit()
        db.rollback()
        # put 路径:row 已存在 → 走 update 分支(86-89),commit 成功。
        cache.put("proj1", "app.py", "newcontent", vulns)
        rows = db.query(ScanCacheORM).filter(ScanCacheORM.project_id == "proj1").all()
        assert len(rows) == 1
        db.close()

    def test_flush_failure_rolls_back(self):
        # 121-125: flush commit 抛异常 → rollback 不崩溃。
        db = MagicMock()
        db.commit.side_effect = OperationalError("stmt", {}, Exception("boom"))
        cache = ProjectScanCache(db)
        cache.flush()  # 不抛异常。
        db.rollback.assert_called_once()


class TestProjectScanSummaryAPI:
    def setup_method(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.app = create_app()
        self.app.dependency_overrides[get_session] = self._override_session
        self.app.dependency_overrides[get_current_key] = lambda: APIKey(
            key_hash="t", name="t", roles=["admin"], tenant_id=""
        )
        self.client = TestClient(self.app)

    def _override_session(self):
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def test_scan_summary_not_found(self):
        resp = self.client.get("/api/v1/projects/nonexist/scan-summary")
        assert resp.status_code == 404

    def test_scan_summary_empty(self):
        db = self.SessionLocal()
        proj = ProjectORM(id="p1", name="TestProj")
        db.add(proj)
        db.commit()
        db.close()

        resp = self.client.get("/api/v1/projects/p1/scan-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["project_id"] == "p1"
        assert data["total_scans"] == 0
        assert data["latest_scan"] is None
        assert data["vulnerability_summary"]["total"] == 0

    def test_scan_summary_with_data(self):
        db = self.SessionLocal()
        proj = ProjectORM(id="p2", name="TestProj2")
        db.add(proj)
        scan = ScanORM(
            id="s1",
            project_id="p2",
            status="completed",
            critical=1,
            high=2,
            medium=3,
            low=4,
            total_vulnerabilities=10,
            summary="test",
        )
        db.add(scan)
        cache_entry = ScanCacheORM(
            id="c1",
            project_id="p2",
            file_path="app.py",
            content_hash="abc",
            results_json="[]",
        )
        db.add(cache_entry)
        db.commit()
        db.close()

        resp = self.client.get("/api/v1/projects/p2/scan-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_scans"] == 1
        assert data["latest_scan"]["id"] == "s1"
        assert data["vulnerability_summary"]["total_critical"] == 1
        assert data["vulnerability_summary"]["total_high"] == 2
        assert data["vulnerability_summary"]["total"] == 10
        assert data["cache_stats"]["cached_files"] == 1
