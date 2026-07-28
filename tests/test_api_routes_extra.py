from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from fusion_security.api.app import create_app
from fusion_security.db import get_session


def _make_project_orm(**overrides):
    defaults = {
        "id": "proj001",
        "name": "test-project",
        "repo_url": "",
        "tech_stack": "",
        "default_branch": "main",
        "ruleset_id": "",
        "local_path": "",
        "status": "active",
    }
    defaults.update(overrides)
    orm = MagicMock()
    for k, v in defaults.items():
        setattr(orm, k, v)
    return orm


def _make_scan_orm(**overrides):
    defaults = {
        "id": "scan001",
        "project_id": "proj1",
        "scan_type": "full",
        "status": "pending",
        "severity_threshold": "low",
        "use_ai": True,
        "model": "",
        "trigger": "manual",
        "branch": "",
        "base_commit": "",
        "head_commit": "",
        "files_scanned": 0,
        "files_skipped": 0,
        "duration_ms": 0.0,
        "total_vulnerabilities": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "summary": "",
    }
    defaults.update(overrides)
    orm = MagicMock()
    for k, v in defaults.items():
        setattr(orm, k, v)
    orm.findings = []
    return orm


def _make_vuln_orm(**overrides):
    defaults = {
        "id": "v001",
        "title": "SQL Injection",
        "description": "test",
        "severity": "high",
        "confidence": 0.9,
        "file_path": "test.py",
        "line_number": 10,
        "code_snippet": "code",
        "rule_id": "SQL001",
        "cwe_id": "CWE-89",
        "fix_suggestion": "fix it",
        "verified": False,
        "status": "open",
        "data_flow_path": "",
    }
    defaults.update(overrides)
    orm = MagicMock()
    for k, v in defaults.items():
        setattr(orm, k, v)
    return orm


def _make_patch_orm(**overrides):
    defaults = {
        "id": "patch001",
        "vuln_id": "v001",
        "scan_id": "scan001",
        "diff_content": "diff",
        "original_code": "orig",
        "patched_code": "patched",
        "description": "desc",
        "status": "pending",
        "strategy": "template",
        "verified": False,
    }
    defaults.update(overrides)
    orm = MagicMock()
    for k, v in defaults.items():
        setattr(orm, k, v)
    return orm


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture
def mock_db():
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    session.query.return_value.filter.return_value.all.return_value = []
    session.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
    session.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
    session.query.return_value.filter.return_value.offset.return_value.limit.return_value.all.return_value = []
    session.query.return_value.offset.return_value.limit.return_value.all.return_value = []
    session.query.return_value.all.return_value = []
    session.query.return_value.scalar.return_value = 0
    session.query.return_value.group_by.return_value.all.return_value = []
    session.add = MagicMock()
    session.commit = MagicMock()
    session.delete = MagicMock()
    session.refresh = MagicMock()
    session.close = MagicMock()
    return session


@pytest.fixture
def override_client(mock_db):
    app = create_app()
    app.dependency_overrides[get_session] = lambda: mock_db
    tc = TestClient(app)
    tc._app = app
    return tc


# ===== Scans routes =====


class TestScansCreate:
    @patch("fusion_security.api.routes.scans._run_scan")
    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_create_scan_no_path(self, mock_scan_to_orm, mock_run, override_client, mock_db):
        mock_orm = _make_scan_orm()
        mock_scan_to_orm.return_value = mock_orm
        resp = override_client.post(
            "/api/v1/scans",
            json={
                "project_id": "proj1",
                "path": "",
                "scan_type": "full",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["project_id"] == "proj1"

    @patch("fusion_security.api.routes.scans._run_scan")
    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_create_scan_with_path(self, mock_scan_to_orm, mock_run, override_client, mock_db):
        mock_orm = _make_scan_orm()
        mock_scan_to_orm.return_value = mock_orm
        resp = override_client.post(
            "/api/v1/scans",
            json={
                "project_id": "proj1",
                "path": "/tmp/test_project",
                "scan_type": "full",
            },
        )
        assert resp.status_code == 200

    @patch("fusion_security.api.routes.scans._run_scan")
    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_create_scan_with_all_fields(self, mock_scan_to_orm, mock_run, override_client, mock_db):
        mock_orm = _make_scan_orm()
        mock_scan_to_orm.return_value = mock_orm
        resp = override_client.post(
            "/api/v1/scans",
            json={
                "project_id": "proj1",
                "path": "/tmp/test",
                "scan_type": "incremental",
                "severity_threshold": "high",
                "use_ai": False,
                "model": "qwen3",
                "trigger": "api",
                "branch": "dev",
                "changed_files": ["a.py", "b.py"],
            },
        )
        assert resp.status_code == 200


class TestScansListAndGet:
    def test_list_scans_empty(self, override_client, mock_db):
        mock_db.query.return_value.order_by.return_value.all.return_value = []
        resp = override_client.get("/api/v1/scans")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_scans_with_project_filter(self, override_client, mock_db):
        mock_orm = _make_scan_orm()
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [mock_orm]
        resp = override_client.get("/api/v1/scans", params={"project_id": "proj1"})
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_list_scans_with_status_filter(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
        resp = override_client.get("/api/v1/scans", params={"status": "completed"})
        assert resp.status_code == 200

    def test_list_scans_both_filters(self, override_client, mock_db):
        mock_orm = _make_scan_orm()
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [mock_orm]
        resp = override_client.get("/api/v1/scans", params={"project_id": "proj1", "status": "pending"})
        assert resp.status_code == 200

    def test_get_scan_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.get("/api/v1/scans/nonexistent")
        assert resp.status_code == 404

    def test_get_scan_found(self, override_client, mock_db):
        mock_orm = _make_scan_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.get("/api/v1/scans/scan001")
        assert resp.status_code == 200
        assert resp.json()["id"] == "scan001"

    def test_delete_scan_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.delete("/api/v1/scans/nonexistent")
        assert resp.status_code == 404

    def test_delete_scan_found(self, override_client, mock_db):
        mock_orm = _make_scan_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.delete("/api/v1/scans/scan001")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"


class TestScansIncremental:
    def test_incremental_scan_not_git_repo(self, override_client, mock_db):
        with patch("fusion_security.engine.vcs.git.GitHelper", side_effect=ValueError("not a git repo")):
            resp = override_client.post(
                "/api/v1/scans/incremental",
                json={
                    "path": "/tmp/not_a_repo",
                    "base": "HEAD~1",
                    "head": "HEAD",
                },
            )
            assert resp.status_code == 400

    @patch("fusion_security.api.routes.scans._run_scan")
    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_incremental_scan_no_changed_files(self, mock_scan_to_orm, mock_run, override_client, mock_db):
        def _scan_to_orm_side_effect(scan_model):
            return _make_scan_orm(scan_type=scan_model.scan_type)

        mock_scan_to_orm.side_effect = _scan_to_orm_side_effect
        mock_diff = MagicMock()
        mock_diff.base_commit = "abc"
        mock_diff.head_commit = "def"
        mock_diff.changed_files = []
        mock_git = MagicMock()
        mock_git.get_changed_files.return_value = mock_diff
        mock_git.get_current_branch.return_value = "main"
        with patch("fusion_security.engine.vcs.git.GitHelper", return_value=mock_git):
            resp = override_client.post(
                "/api/v1/scans/incremental",
                json={
                    "path": "/tmp/repo",
                    "base": "HEAD~1",
                    "head": "HEAD",
                },
            )
            assert resp.status_code == 200

    @patch("fusion_security.api.routes.scans._run_scan")
    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_incremental_scan_with_changed_files(self, mock_scan_to_orm, mock_run, override_client, mock_db):
        mock_diff = MagicMock()
        mock_diff.base_commit = "abc"
        mock_diff.head_commit = "def"
        mock_diff.changed_files = ["file1.py", "file2.py"]
        mock_git = MagicMock()
        mock_git.get_changed_files.return_value = mock_diff
        mock_git.get_current_branch.return_value = "main"
        mock_orm = _make_scan_orm()
        mock_scan_to_orm.return_value = mock_orm
        with patch("fusion_security.engine.vcs.git.GitHelper", return_value=mock_git):
            resp = override_client.post(
                "/api/v1/scans/incremental",
                json={
                    "path": "/tmp/repo",
                    "base": "HEAD~1",
                    "head": "HEAD",
                },
            )
            assert resp.status_code == 200


class TestScansQueue:
    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_enqueue_scan(self, mock_scan_to_orm, override_client, mock_db):
        mock_orm = _make_scan_orm(status="queued")
        mock_scan_to_orm.return_value = mock_orm
        resp = override_client.post(
            "/api/v1/scans/queue",
            json={
                "project_id": "proj1",
                "path": "/tmp/test",
                "scan_type": "full",
                "priority": 2,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert "task_id" in data
        assert data["status"] == "queued"

    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_enqueue_scan_high_priority(self, mock_scan_to_orm, override_client, mock_db):
        mock_orm = _make_scan_orm(status="queued")
        mock_scan_to_orm.return_value = mock_orm
        resp = override_client.post(
            "/api/v1/scans/queue",
            json={
                "project_id": "proj1",
                "path": "/tmp/test",
                "priority": 0,
            },
        )
        assert resp.status_code == 200

    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_enqueue_scan_invalid_priority(self, mock_scan_to_orm, override_client, mock_db):
        mock_orm = _make_scan_orm(status="queued")
        mock_scan_to_orm.return_value = mock_orm
        resp = override_client.post(
            "/api/v1/scans/queue",
            json={
                "project_id": "proj1",
                "path": "/tmp/test",
                "priority": 99,
            },
        )
        assert resp.status_code == 200

    def test_queue_status(self, client):
        resp = client.get("/api/v1/scans/queue/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "queue_size" in data
        assert "pool_active" in data
        assert "by_status" in data

    def test_queue_list_tasks(self, client):
        resp = client.get("/api/v1/scans/queue/tasks")
        assert resp.status_code == 200
        assert "tasks" in resp.json()

    def test_queue_list_tasks_with_status_filter(self, client):
        resp = client.get("/api/v1/scans/queue/tasks", params={"status": "pending"})
        assert resp.status_code == 200

    def test_cancel_queue_task_not_found(self, client):
        resp = client.post("/api/v1/scans/queue/nonexistent_task/cancel")
        assert resp.status_code == 404

    @patch("fusion_security.api.routes.scans.scan_to_orm")
    def test_cancel_queue_task_found(self, mock_scan_to_orm, override_client, mock_db):
        mock_orm = _make_scan_orm(status="queued")
        mock_scan_to_orm.return_value = mock_orm
        enq = override_client.post(
            "/api/v1/scans/queue",
            json={
                "project_id": "proj1",
                "path": "/tmp/test",
            },
        )
        task_id = enq.json()["task_id"]
        resp = override_client.post(f"/api/v1/scans/queue/{task_id}/cancel")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    def test_pool_start_stop(self, client):
        resp = client.post("/api/v1/scans/queue/pool/start")
        assert resp.status_code == 200
        assert resp.json()["status"] == "started"
        resp2 = client.post("/api/v1/scans/queue/pool/stop")
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "stopped"


class TestScansCheckpointsAndResume:
    def test_list_checkpoints(self, client):
        resp = client.get("/api/v1/scans/checkpoints")
        assert resp.status_code == 200
        assert "checkpoints" in resp.json()

    @patch("fusion_security.api.routes.scans._run_pipeline_resume")
    def test_resume_scan_checkpoint_not_found(self, mock_run, override_client, mock_db):
        with patch("fusion_security.engine.resume.CheckpointManager") as MockCP:
            MockCP.return_value.load.return_value = None
            resp = override_client.post(
                "/api/v1/scans/resume",
                json={
                    "scan_id": "nonexistent",
                    "path": "/tmp/test",
                },
            )
            assert resp.status_code == 404

    @patch("fusion_security.api.routes.scans._run_pipeline_resume")
    def test_resume_scan_db_scan_not_found(self, mock_run, override_client, mock_db):
        with patch("fusion_security.engine.resume.CheckpointManager") as MockCP:
            mock_cp = MagicMock()
            mock_cp.completed_stage = "rule_scan"
            MockCP.return_value.load.return_value = mock_cp
            mock_db.query.return_value.filter.return_value.first.return_value = None
            resp = override_client.post(
                "/api/v1/scans/resume",
                json={
                    "scan_id": "scan001",
                    "path": "/tmp/test",
                },
            )
            assert resp.status_code == 404

    @patch("fusion_security.api.routes.scans._run_pipeline_resume")
    def test_resume_scan_success(self, mock_run, override_client, mock_db):
        with patch("fusion_security.engine.resume.CheckpointManager") as MockCP:
            mock_cp = MagicMock()
            mock_cp.completed_stage = "rule_scan"
            MockCP.return_value.load.return_value = mock_cp
            mock_scan_orm = MagicMock()
            mock_scan_orm.status = "pending"
            mock_db.query.return_value.filter.return_value.first.return_value = mock_scan_orm
            resp = override_client.post(
                "/api/v1/scans/resume",
                json={
                    "scan_id": "scan001",
                    "path": "/tmp/test",
                    "changed_files": ["file1.py"],
                },
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "resuming"
            assert resp.json()["resume_from"] == "rule_scan"


# ===== Reports routes =====


class TestReportsGenerate:
    def test_generate_report_md_format(self, override_client, mock_db):
        mock_scan = _make_scan_orm(total_vulnerabilities=3, critical=1)
        mock_scan.findings = []
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan
        mock_db.query.return_value.all.return_value = []
        resp = override_client.post(
            "/api/v1/reports/generate",
            json={
                "scan_id": "scan001",
                "format": "md",
            },
        )
        assert resp.status_code == 200

    def test_generate_report_json_format(self, override_client, mock_db):
        mock_scan = _make_scan_orm()
        mock_scan.findings = []
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan
        mock_db.query.return_value.all.return_value = []
        resp = override_client.post(
            "/api/v1/reports/generate",
            json={
                "scan_id": "scan001",
                "format": "json",
            },
        )
        assert resp.status_code == 200

    def test_generate_report_html_format(self, override_client, mock_db):
        mock_scan = _make_scan_orm()
        mock_scan.findings = []
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan
        mock_db.query.return_value.all.return_value = []
        resp = override_client.post(
            "/api/v1/reports/generate",
            json={
                "scan_id": "scan001",
                "format": "html",
            },
        )
        assert resp.status_code == 200

    def test_generate_report_scan_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.post(
            "/api/v1/reports/generate",
            json={
                "scan_id": "nonexistent",
                "format": "md",
            },
        )
        assert resp.status_code == 404


# ===== Projects routes =====


class TestProjectsCRUD:
    @patch("fusion_security.api.routes.projects.project_to_orm")
    def test_create_project(self, mock_project_to_orm, override_client, mock_db):
        mock_orm = _make_project_orm()
        mock_project_to_orm.return_value = mock_orm
        resp = override_client.post(
            "/api/v1/projects",
            json={
                "name": "test-project",
                "repo_url": "https://github.com/test",
                "tech_stack": "python",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "test-project"

    def test_list_projects_with_status_filter(self, override_client, mock_db):
        mock_orm = _make_project_orm()
        mock_db.query.return_value.filter.return_value.offset.return_value.limit.return_value.all.return_value = [
            mock_orm
        ]
        resp = override_client.get("/api/v1/projects", params={"status": "active"})
        assert resp.status_code == 200

    def test_list_projects_with_pagination(self, override_client, mock_db):
        mock_db.query.return_value.offset.return_value.limit.return_value.all.return_value = []
        resp = override_client.get("/api/v1/projects", params={"limit": 10, "offset": 5})
        assert resp.status_code == 200

    def test_get_project_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.get("/api/v1/projects/nonexistent")
        assert resp.status_code == 404

    def test_get_project_found(self, override_client, mock_db):
        mock_orm = _make_project_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.get("/api/v1/projects/proj001")
        assert resp.status_code == 200
        assert resp.json()["id"] == "proj001"

    def test_delete_project_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.delete("/api/v1/projects/nonexistent")
        assert resp.status_code == 404

    def test_delete_project_found(self, override_client, mock_db):
        mock_orm = _make_project_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.delete("/api/v1/projects/proj001")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"


# ===== Patches routes =====


class TestPatchesCRUD:
    def test_list_patches_with_filters(self, override_client, mock_db):
        mock_orm = _make_patch_orm()
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_orm]
        resp = override_client.get(
            "/api/v1/patches",
            params={
                "vuln_id": "v001",
                "scan_id": "scan001",
                "status": "pending",
            },
        )
        assert resp.status_code == 200

    def test_get_patch_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.get("/api/v1/patches/nonexistent")
        assert resp.status_code == 404

    def test_get_patch_found(self, override_client, mock_db):
        mock_orm = _make_patch_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.get("/api/v1/patches/patch001")
        assert resp.status_code == 200
        assert resp.json()["id"] == "patch001"

    def test_update_patch_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.patch(
            "/api/v1/patches/nonexistent",
            json={
                "status": "reviewed",
            },
        )
        assert resp.status_code == 404

    def test_update_patch_found(self, override_client, mock_db):
        mock_orm = _make_patch_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.patch(
            "/api/v1/patches/patch001",
            json={
                "status": "reviewed",
                "verified": True,
            },
        )
        assert resp.status_code == 200

    def test_apply_patch_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.post("/api/v1/patches/nonexistent/apply")
        assert resp.status_code == 404

    def test_apply_patch_found(self, override_client, mock_db):
        mock_orm = _make_patch_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.post("/api/v1/patches/patch001/apply")
        assert resp.status_code == 200

    def test_generate_patch_vuln_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.post("/api/v1/patches/generate/nonexistent")
        assert resp.status_code == 404

    @patch("fusion_security.api.routes.patches.patch_to_orm")
    def test_generate_patch_vuln_found(self, mock_patch_to_orm, override_client, mock_db):
        mock_vuln_orm = _make_vuln_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_vuln_orm
        with patch("fusion_security.engine.fix.fix_generator.FixGenerator") as MockFG:
            mock_patch_model = MagicMock()
            mock_patch_model.id = "p1"
            mock_patch_model.strategy = "template"
            mock_patch_model.vuln_id = "v001"
            mock_patch_model.scan_id = ""
            mock_patch_model.diff_content = ""
            mock_patch_model.original_code = ""
            mock_patch_model.patched_code = ""
            mock_patch_model.description = ""
            mock_patch_model.status = "pending"
            mock_patch_model.verified = False
            MockFG.return_value.generate.return_value = [mock_patch_model]
            mock_patch_orm_obj = _make_patch_orm()
            mock_patch_to_orm.return_value = mock_patch_orm_obj
            resp = override_client.post("/api/v1/patches/generate/v001")
            assert resp.status_code == 200
            assert "patches" in resp.json()

    def test_generate_patch_vuln_found_empty(self, override_client, mock_db):
        mock_vuln_orm = _make_vuln_orm(id="v002")
        mock_db.query.return_value.filter.return_value.first.return_value = mock_vuln_orm
        with patch("fusion_security.engine.fix.fix_generator.FixGenerator") as MockFG:
            MockFG.return_value.generate.return_value = []
            resp = override_client.post("/api/v1/patches/generate/v002")
            assert resp.status_code == 200
            assert resp.json()["patches"] == []


# ===== Vulnerabilities routes =====


class TestVulnerabilitiesCRUD:
    def test_list_vulnerabilities_with_filters(self, override_client, mock_db):
        mock_orm = _make_vuln_orm()
        mock_db.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [
            mock_orm
        ]
        resp = override_client.get(
            "/api/v1/vulnerabilities",
            params={
                "severity": "high",
                "status": "open",
                "rule_id": "SQL001",
                "file_path": "test.py",
                "limit": 50,
                "offset": 0,
            },
        )
        assert resp.status_code == 200

    def test_get_vulnerability_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.get("/api/v1/vulnerabilities/nonexistent")
        assert resp.status_code == 404

    def test_get_vulnerability_found(self, override_client, mock_db):
        mock_orm = _make_vuln_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.get("/api/v1/vulnerabilities/v001")
        assert resp.status_code == 200
        assert resp.json()["id"] == "v001"

    def test_update_vulnerability_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.patch("/api/v1/vulnerabilities/nonexistent", json={"status": "resolved"})
        assert resp.status_code == 404

    def test_update_vulnerability_found(self, override_client, mock_db):
        mock_orm = _make_vuln_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.patch("/api/v1/vulnerabilities/v001", json={"status": "resolved"})
        assert resp.status_code == 200

    def test_vulnerability_stats(self, override_client, mock_db):
        mock_db.query.return_value.scalar.return_value = 10
        mock_db.query.return_value.group_by.return_value.all.return_value = [
            ("high", 5),
            ("medium", 3),
            ("low", 2),
        ]
        resp = override_client.get("/api/v1/vulnerabilities/stats/summary")
        assert resp.status_code == 200

    def test_mark_false_positive_not_found(self, override_client, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = override_client.post("/api/v1/vulnerabilities/nonexistent/false-positive", params={"reason": "test"})
        assert resp.status_code == 404

    def test_mark_false_positive_found(self, override_client, mock_db):
        mock_orm = _make_vuln_orm()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_orm
        resp = override_client.post("/api/v1/vulnerabilities/v001/false-positive", params={"reason": "test"})
        assert resp.status_code == 200

    def test_recent_findings_with_hours(self, override_client, mock_db):
        mock_orm = _make_vuln_orm()
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [
            mock_orm
        ]
        resp = override_client.get("/api/v1/vulnerabilities/findings/recent", params={"hours": 48, "limit": 10})
        assert resp.status_code == 200
        assert "count" in resp.json()

    def test_findings_by_rule(self, override_client, mock_db):
        mock_db.query.return_value.group_by.return_value.all.return_value = [
            ("SQL001", 5),
            ("XSS001", 3),
        ]
        resp = override_client.get("/api/v1/vulnerabilities/findings/by-rule")
        assert resp.status_code == 200
        assert "rules" in resp.json()


# ===== Integrations routes =====


class TestIntegrationsGate:
    def test_evaluate_gate_standard(self, client):
        resp = client.post(
            "/api/v1/integrations/gate",
            json=[
                {"id": "v1", "title": "SQL Injection", "severity": "critical"},
            ],
        )
        assert resp.status_code == 200
        assert "passed" in resp.json()

    def test_evaluate_gate_strict(self, client):
        resp = client.post(
            "/api/v1/integrations/gate",
            json=[
                {"id": "v1", "title": "SQL Injection", "severity": "high"},
            ],
            params={"policy": "strict"},
        )
        assert resp.status_code == 200

    def test_evaluate_gate_permissive(self, client):
        resp = client.post(
            "/api/v1/integrations/gate",
            json=[
                {"id": "v1", "title": "Info", "severity": "low"},
            ],
            params={"policy": "permissive"},
        )
        assert resp.status_code == 200

    def test_evaluate_gate_empty_vulns(self, client):
        resp = client.post("/api/v1/integrations/gate", json=[])
        assert resp.status_code == 200

    def test_evaluate_gate_with_all_fields(self, client):
        resp = client.post(
            "/api/v1/integrations/gate",
            json=[
                {
                    "id": "v1",
                    "title": "SQL Injection",
                    "description": "sql inject",
                    "severity": "high",
                    "confidence": 90,
                    "file_path": "a.py",
                    "line_number": 10,
                    "code_snippet": "code",
                    "rule_id": "SQL001",
                },
            ],
        )
        assert resp.status_code == 200


class TestIntegrationsCVSS:
    def test_calculate_cvss_default(self, client):
        resp = client.post("/api/v1/integrations/cvss")
        assert resp.status_code == 200
        data = resp.json()
        assert "vector" in data
        assert "base_score" in data
        assert "severity" in data

    def test_calculate_cvss_custom_params(self, client):
        resp = client.post(
            "/api/v1/integrations/cvss",
            params={
                "av": "A",
                "ac": "H",
                "pr": "L",
                "ui": "R",
                "s": "C",
                "c": "H",
                "i": "H",
                "a": "H",
            },
        )
        assert resp.status_code == 200


class TestIntegrationsCompliance:
    def test_map_compliance_with_vulns(self, client):
        resp = client.post(
            "/api/v1/integrations/compliance",
            json=[
                {"id": "v1", "rule_id": "SQL001"},
            ],
        )
        assert resp.status_code == 200

    def test_map_compliance_empty(self, client):
        resp = client.post("/api/v1/integrations/compliance", json=[])
        assert resp.status_code == 200

    def test_map_compliance_multiple_rules(self, client):
        resp = client.post(
            "/api/v1/integrations/compliance",
            json=[
                {"id": "v1", "rule_id": "SQL001"},
                {"id": "v2", "rule_id": "CMD001"},
                {"id": "v3", "rule_id": "XSS001"},
            ],
        )
        assert resp.status_code == 200


class TestIntegrationsFeedback:
    def test_add_feedback(self, client):
        resp = client.post(
            "/api/v1/integrations/feedback",
            params={
                "vuln_id": "v1",
                "rule_id": "SQL001",
                "file_path": "test.py",
                "line_number": 10,
                "is_false_positive": True,
                "reason": "not applicable",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_feedback_stats(self, client):
        client.post(
            "/api/v1/integrations/feedback",
            params={
                "vuln_id": "v2",
                "rule_id": "XSS001",
                "file_path": "test.py",
                "line_number": 5,
                "is_false_positive": False,
            },
        )
        resp = client.get("/api/v1/integrations/feedback/stats")
        assert resp.status_code == 200


class TestIntegrationsCustomRules:
    def test_create_custom_rule(self, client):
        resp = client.post(
            "/api/v1/integrations/rules",
            params={
                "id": "custom100",
                "name": "My Rule",
                "pattern": "eval\\(",
                "severity": "high",
                "language": "python",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["rule_id"] == "custom100"

    def test_list_custom_rules(self, client):
        client.post(
            "/api/v1/integrations/rules",
            params={
                "id": "custom200",
                "name": "Rule 2",
                "pattern": "exec\\(",
            },
        )
        resp = client.get("/api/v1/integrations/rules")
        assert resp.status_code == 200
        assert "rules" in resp.json()

    def test_list_custom_rules_enabled_only(self, client):
        resp = client.get("/api/v1/integrations/rules", params={"enabled_only": True})
        assert resp.status_code == 200

    def test_delete_custom_rule_found(self, client):
        client.post(
            "/api/v1/integrations/rules",
            params={
                "id": "custom300",
                "name": "Rule to Delete",
                "pattern": "test",
            },
        )
        resp = client.delete("/api/v1/integrations/rules/custom300")
        assert resp.status_code == 200

    def test_delete_custom_rule_not_found(self, client):
        resp = client.delete("/api/v1/integrations/rules/nonexistent_rule_xyz")
        assert resp.status_code == 404


class TestIntegrationsDashboard:
    def test_dashboard_stats(self, client):
        resp = client.get("/api/v1/integrations/dashboard")
        assert resp.status_code == 200


class TestIntegrationsNotifications:
    def test_add_feishu_notifier(self, client):
        resp = client.post(
            "/api/v1/integrations/notify/feishu",
            json={
                "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/test",
                "secret": "",
                "mention_all": False,
                "events": ["scan.completed"],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["type"] == "feishu"

    def test_add_dingtalk_notifier(self, client):
        resp = client.post(
            "/api/v1/integrations/notify/dingtalk",
            json={
                "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=test",
                "secret": "",
                "mention_all": False,
                "at_mobiles": [],
                "events": ["scan.completed"],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["type"] == "dingtalk"

    def test_send_notification_no_channels(self, client):
        with patch("fusion_security.api.routes.integrations._notification_dispatcher", None):
            resp = client.post(
                "/api/v1/integrations/notify/send",
                json={
                    "event": "scan.completed",
                    "scan_id": "scan001",
                },
            )
            assert resp.status_code == 400

    def test_send_notification_with_feishu(self, client):
        client.post(
            "/api/v1/integrations/notify/feishu",
            json={
                "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/test",
            },
        )
        with patch("fusion_security.engine.ci.notifier.FeishuNotifier.send", return_value=True):
            resp = client.post(
                "/api/v1/integrations/notify/send",
                json={
                    "event": "scan.completed",
                    "scan_id": "scan001",
                    "total": 5,
                    "critical": 1,
                    "high": 1,
                    "medium": 2,
                    "low": 1,
                    "gate_passed": True,
                },
            )
            assert resp.status_code == 200
            assert "results" in resp.json()

    def test_send_notification_with_dingtalk(self, client):
        client.post(
            "/api/v1/integrations/notify/dingtalk",
            json={
                "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=test",
            },
        )
        with patch("fusion_security.engine.ci.notifier.DingTalkNotifier.send", return_value=True):
            resp = client.post(
                "/api/v1/integrations/notify/send",
                json={
                    "event": "scan.completed",
                    "scan_id": "scan001",
                },
            )
            assert resp.status_code == 200


# ===== App routes =====


class TestAppLifespanAndKeys:
    def test_create_api_key(self, client):
        resp = client.post("/api/v1/keys", params={"name": "test-key", "roles": "admin"})
        assert resp.status_code == 200
        data = resp.json()
        assert "api_key" in data
        assert data["name"] == "test-key"
        assert "admin" in data["roles"]

    def test_create_api_key_default_roles(self, client):
        resp = client.post("/api/v1/keys", params={"name": "viewer-key2"})
        assert resp.status_code == 200
        data = resp.json()
        assert "viewer" in data["roles"]

    def test_create_api_key_multiple_roles(self, client):
        resp = client.post("/api/v1/keys", params={"name": "multi-key", "roles": "admin,operator"})
        assert resp.status_code == 200
        data = resp.json()
        assert "admin" in data["roles"]
        assert "operator" in data["roles"]

    def test_list_api_keys(self, client):
        client.post("/api/v1/keys", params={"name": "list-test-key", "roles": "viewer"})
        resp = client.get("/api/v1/keys")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) >= 1


# ===== Auth module =====


class TestAuthManager:
    def test_validate_key_valid(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("test", ["admin"])
        result = mgr.validate_key(raw)
        assert result is not None
        assert result.name == "test"

    def test_validate_key_empty(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        result = mgr.validate_key("")
        assert result is None

    def test_validate_key_invalid(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        result = mgr.validate_key("fs_invalid_key")
        assert result is None

    def test_validate_key_expired(self):
        import hashlib
        import time

        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("expired", ["viewer"], expires_in=1)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        mgr.api_keys[key_hash].expires_at = time.time() - 100
        result = mgr.validate_key(raw)
        assert result is None

    def test_has_permission_admin(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("admin-key", ["admin"])
        key = mgr.validate_key(raw)
        assert mgr.has_permission(key, "scan:run") is True
        assert mgr.has_permission(key, "api_key:manage") is True

    def test_has_permission_viewer(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("viewer-key", ["viewer"])
        key = mgr.validate_key(raw)
        assert mgr.has_permission(key, "scan:read") is True
        assert mgr.has_permission(key, "scan:run") is False

    def test_has_permission_operator(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("op-key", ["operator"])
        key = mgr.validate_key(raw)
        assert mgr.has_permission(key, "scan:run") is True
        assert mgr.has_permission(key, "vuln:read") is True

    def test_has_permission_unknown_role(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("unknown-role", ["nonexistent"])
        key = mgr.validate_key(raw)
        assert mgr.has_permission(key, "scan:read") is False

    def test_revoke_key(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("to-revoke", ["viewer"])
        assert mgr.revoke_key("to-revoke") is True
        assert mgr.validate_key(raw) is None

    def test_revoke_key_not_found(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        assert mgr.revoke_key("nonexistent") is False

    def test_list_keys(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        mgr.create_api_key("list-test", ["admin"])
        keys = mgr.list_keys()
        assert len(keys) >= 1
        assert any(k["name"] == "list-test" for k in keys)

    def test_api_key_is_expired(self):
        import time

        from fusion_security.api.auth import APIKey

        key = APIKey(key_hash="x", name="test", expires_at=0)
        assert key.is_expired() is False
        key2 = APIKey(key_hash="x", name="test", expires_at=time.time() - 1)
        assert key2.is_expired() is True

    def test_create_api_key_with_expiry(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        raw = mgr.create_api_key("temp", ["viewer"], expires_in=3600)
        key = mgr.validate_key(raw)
        assert key is not None
        assert key.name == "temp"
        assert key.expires_at > 0

    def test_revoke_key_multiple_same_name(self):
        from fusion_security.api.auth import AuthManager

        mgr = AuthManager()
        mgr.create_api_key("dup", ["viewer"])
        mgr.create_api_key("dup", ["admin"])
        assert mgr.revoke_key("dup") is True
        keys = [k for k in mgr.list_keys() if k["name"] == "dup"]
        assert len(keys) == 0


class TestAuthDependencies:
    def test_require_permission_insufficient(self):
        import asyncio

        from fusion_security.api.auth import AuthManager, require_permission

        mgr = AuthManager()
        raw = mgr.create_api_key("viewer-only", ["viewer"])
        key = mgr.validate_key(raw)
        checker = asyncio.get_event_loop().run_until_complete(require_permission("scan:run"))
        with pytest.raises(Exception) as exc_info:
            asyncio.get_event_loop().run_until_complete(checker(key))
        assert exc_info.value.status_code == 403

    def test_require_permission_sufficient(self):
        import asyncio

        from fusion_security.api.auth import AuthManager, require_permission

        mgr = AuthManager()
        raw = mgr.create_api_key("admin-user", ["admin"])
        key = mgr.validate_key(raw)
        checker = asyncio.get_event_loop().run_until_complete(require_permission("scan:run"))
        result = asyncio.get_event_loop().run_until_complete(checker(key))
        assert result.name == "admin-user"

    def test_get_current_key_missing_header_returns_401(self):
        import asyncio

        from fusion_security.api.auth import get_current_key

        with pytest.raises(Exception) as exc_info:
            asyncio.get_event_loop().run_until_complete(get_current_key(None, api_key=None))
        assert exc_info.value.status_code == 401

    def test_get_current_key_invalid_returns_401(self):
        import asyncio

        from fusion_security.api.auth import get_current_key

        with pytest.raises(Exception) as exc_info:
            asyncio.get_event_loop().run_until_complete(get_current_key(None, api_key="fs_bad_key"))
        assert exc_info.value.status_code == 401
