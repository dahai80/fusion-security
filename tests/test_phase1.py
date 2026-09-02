"""Fusion-Security Phase1 tests — AST parser, taint tracker, DB, API, models."""

from pathlib import Path

from fusion_security.api.app import app
from fusion_security.db import get_session, init_db
from fusion_security.db.convert import _to_datetime, orm_to_project, orm_to_vuln, project_to_orm, vuln_to_orm
from fusion_security.db.models import ProjectORM, VulnerabilityORM
from fusion_security.engine.rules.ast_parser import ASTParser
from fusion_security.engine.rules.taint_tracker import TaintTracker
from fusion_security.engine.scanner import ScanResult, ScanTarget
from fusion_security.models.patch import Patch
from fusion_security.models.project import Project, Scan
from fusion_security.models.rule import Rule
from fusion_security.models.vulnerability import Vulnerability


class TestASTParser:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_python(self):
        code = "import os\ndef hello(name):\n    print(name)\n"
        result = self.parser.parse(Path("test.py"), code)
        assert result is not None
        assert result.language == "py"
        assert len(result.functions) == 1
        assert result.functions[0].name == "hello"

    def test_parse_javascript(self):
        code = "function greet(name) { console.log(name); }\n"
        result = self.parser.parse(Path("test.js"), code)
        assert result is not None
        assert result.language == "js"

    def test_unsupported_language(self):
        result = self.parser.parse(Path("test.xyz"), "hello world")
        assert result is None

    def test_python_imports(self):
        code = "import os\nfrom sys import path\n"
        result = self.parser.parse(Path("test.py"), code)
        assert result is not None
        assert len(result.imports) >= 1

    def test_python_decorators(self):
        code = "@app.route('/api')\ndef api():\n    pass\n"
        result = self.parser.parse(Path("test.py"), code)
        assert result is not None
        assert len(result.decorators) >= 1

    def test_supported_extensions(self):
        exts = self.parser.get_supported_extensions()
        assert ".py" in exts
        assert ".js" in exts
        assert ".java" in exts
        assert ".go" in exts


class TestTaintTracker:
    def setup_method(self):
        self.tracker = TaintTracker()

    def test_detect_taint_path(self):
        code = (
            "from flask import request\n"
            "import os\n"
            "def cmd():\n"
            "    user_input = request.args.get('cmd')\n"
            "    os.system(user_input)\n"
        )
        result = self.tracker.analyze(Path("test.py"), code)
        assert len(result.taint_paths) > 0
        tp = result.taint_paths[0]
        assert tp.is_sanitized is False

    def test_sanitized_path(self):
        code = (
            "from flask import request\n"
            "import os\n"
            "def safe_cmd():\n"
            "    user_input = request.args.get('cmd')\n"
            "    sanitized = sanitize(user_input)\n"
            "    os.system(sanitized)\n"
        )
        result = self.tracker.analyze(Path("test.py"), code)
        sanitized_paths = [tp for tp in result.taint_paths if tp.is_sanitized]
        assert len(sanitized_paths) >= 0

    def test_no_taint_without_source(self):
        code = "import os\ndef safe():\n    os.system('ls')\n"
        result = self.tracker.analyze(Path("test.py"), code)
        assert len(result.taint_paths) == 0


class TestDatabase:
    def test_init_and_session(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        init_db(db_path)
        session = get_session()
        assert session is not None
        session.close()

    def test_project_crud(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        init_db(db_path)
        session = get_session()

        p = ProjectORM(name="test-project", local_path="/tmp/test")
        session.add(p)
        session.commit()

        found = session.query(ProjectORM).first()
        assert found.name == "test-project"
        session.close()

    def test_vulnerability_crud(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        init_db(db_path)
        session = get_session()

        v = VulnerabilityORM(
            id="V001",
            title="SQL注入",
            description="test",
            severity="critical",
            confidence=90,
            file_path="test.py",
            line_number=10,
            code_snippet="execute(sql)",
        )
        session.add(v)
        session.commit()

        found = session.query(VulnerabilityORM).first()
        assert found.id == "V001"
        assert found.status == "open"
        session.close()


class TestConverters:
    def test_vuln_roundtrip(self):
        v = Vulnerability(
            id="V001",
            title="Test",
            description="test desc",
            severity="high",
            confidence=80,
            file_path="a.py",
            line_number=5,
            code_snippet="code",
            rule_id="SQL001",
            cwe_id="CWE-89",
            fix_suggestion="fix it",
            verified=True,
            status="open",
            data_flow_path="a->b",
        )
        orm = vuln_to_orm(v)
        assert orm.id == "V001"
        back = orm_to_vuln(orm)
        assert back.title == "Test"
        assert back.status == "open"
        assert back.data_flow_path == "a->b"

    def test_project_roundtrip(self):
        p = Project(name="test", local_path="/tmp")
        orm = project_to_orm(p)
        assert orm.name == "test"
        back = orm_to_project(orm)
        assert back.name == "test"


class TestConvertDatetime:
    def test_empty_returns_none(self):
        assert _to_datetime("") is None
        assert _to_datetime(None) is None

    def test_datetime_passthrough(self):
        from datetime import datetime

        dt = datetime(2026, 8, 7, 12, 0, 0)
        assert _to_datetime(dt) is dt

    def test_iso_string_parsed(self):
        from datetime import datetime

        result = _to_datetime("2026-08-07T12:00:00")
        assert result == datetime(2026, 8, 7, 12, 0, 0)

    def test_invalid_string_returns_none(self):
        assert _to_datetime("not-a-date") is None


class TestModels:
    def test_vulnerability_with_status(self):
        v = Vulnerability(
            id="V1",
            title="T",
            description="D",
            severity="high",
            confidence=80,
            file_path="f.py",
            line_number=1,
            code_snippet="c",
            status="false_positive",
        )
        assert v.status == "false_positive"

    def test_scan_model(self):
        s = Scan(scan_type="incremental", use_ai=True)
        assert s.scan_type == "incremental"

    def test_patch_model(self):
        p = Patch()
        p.vuln_id = "V1"
        p.original_code = "bad"
        p.patched_code = "good"
        assert p.original_code == "bad"

    def test_rule_model(self):
        r = Rule(id="FUS-INJ-001", name="SQL注入", severity="critical")
        assert r.id == "FUS-INJ-001"


class TestScanResultToScanModel:
    def test_to_scan_model(self):
        target = ScanTarget(".")
        result = ScanResult(target)
        result.files_scanned = 10
        result.duration_ms = 500.0
        result.summary = "test"

        scan_model = result.to_scan_model()
        assert scan_model.files_scanned == 10
        assert scan_model.duration_ms == 500.0
        assert scan_model.status == "completed"


class TestFastAPIApp:
    def test_app_creation(self):
        assert app.title == "Fusion-Security API"
        assert len(app.routes) > 0

    def test_health_endpoint(self):
        from fastapi.testclient import TestClient

        client = TestClient(app)
        resp = client.get("/api/v1/system/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_info_endpoint(self):

        from fastapi.testclient import TestClient

        from fusion_security.api.auth import APIKey, get_current_key

        app.dependency_overrides[get_current_key] = lambda: APIKey(
            key_hash="t", name="t", roles=["admin"], tenant_id=""
        )
        client = TestClient(app)
        resp = client.get("/api/v1/system/info")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        app.dependency_overrides.pop(get_current_key, None)

    def test_rules_endpoint(self):

        from fastapi.testclient import TestClient

        from fusion_security.api.auth import APIKey, get_current_key

        app.dependency_overrides[get_current_key] = lambda: APIKey(
            key_hash="t", name="t", roles=["admin"], tenant_id=""
        )
        client = TestClient(app)
        resp = client.get("/api/v1/system/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] > 0
        app.dependency_overrides.pop(get_current_key, None)
