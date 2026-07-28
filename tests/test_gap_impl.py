from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from fusion_security.engine.ci.jira import SEVERITY_JIRA_PRIORITY, JiraClient, JiraConfig, JiraIssue
from fusion_security.engine.rules.engine import AI_SEMANTIC_RULES, RuleEngine
from fusion_security.engine.sca.scanner import Dependency, SCAScanner
from fusion_security.engine.scanner import ScanTarget
from fusion_security.models.vulnerability import Vulnerability


class TestHI01UUIDVulnID:
    def test_ast_vuln_id_is_uuid_format(self):
        engine = RuleEngine()
        code = "eval(user_input)"
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        try:
            findings = engine.scan_file_ast(path, code)
            assert len(findings) > 0
            for v in findings:
                assert len(v.id) == 16, f"ID should be 16 chars, got: {v.id}"
        finally:
            os.unlink(f.name)

    def test_ast_auth_vuln_id_is_uuid(self):
        engine = RuleEngine()
        code = "@app.route('/admin')\ndef admin():\n    pass"
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        try:
            findings = engine.scan_file_ast(path, code)
            for v in findings:
                if "鉴权" in v.title:
                    assert len(v.id) == 16
        finally:
            os.unlink(f.name)


class TestLO01ScanTargetConstructor:
    def test_incremental_files_via_constructor(self):
        target = ScanTarget("/tmp", incremental_files=["/tmp/a.py", "/tmp/b.py"])
        assert target._incremental_files == ["/tmp/a.py", "/tmp/b.py"]

    def test_incremental_files_default_empty(self):
        target = ScanTarget("/tmp")
        assert target._incremental_files == []

    def test_incremental_files_none_default(self):
        target = ScanTarget("/tmp", incremental_files=None)
        assert target._incremental_files == []


class TestNewRules:
    def test_crypto002_hardcoded_encryption_key(self):
        engine = RuleEngine()
        code = 'encryption_key = "mysecretkey123"'
        findings = engine.scan_file(Path("test.py"), code)
        crypto = [v for v in findings if v.rule_id == "CRYPTO002"]
        assert len(crypto) >= 1
        assert crypto[0].cwe_id == "CWE-321"

    def test_crypto002_aes_key(self):
        engine = RuleEngine()
        code = 'aes_key = "1234567890abcdef"'
        findings = engine.scan_file(Path("test.py"), code)
        crypto = [v for v in findings if v.rule_id == "CRYPTO002"]
        assert len(crypto) >= 1

    def test_dirtravers001_directory_listing(self):
        engine = RuleEngine()
        code = "autoindex = True"
        findings = engine.scan_file(Path("test.py"), code)
        dt = [v for v in findings if v.rule_id == "DIRTRAVERS001"]
        assert len(dt) >= 1
        assert dt[0].cwe_id == "CWE-548"

    def test_insecuretrans001_http_with_password(self):
        engine = RuleEngine()
        code = 'requests.get("http://example.com?password=secret")'
        findings = engine.scan_file(Path("test.py"), code)
        it = [v for v in findings if v.rule_id == "INSECURETRANS001"]
        assert len(it) >= 1
        assert it[0].cwe_id == "CWE-319"

    def test_rule_count_includes_new_rules(self):
        engine = RuleEngine()
        count = engine.get_rule_count()
        assert count >= 37


class TestAISemanticRules:
    def test_semantic_rules_exist(self):
        assert len(AI_SEMANTIC_RULES) == 8

    def test_semantic_rules_have_prdid(self):
        prdids = [r.prdid for r in AI_SEMANTIC_RULES]
        assert "FUS-ACL-001" in prdids
        assert "FUS-ACL-002" in prdids
        assert "FUS-AUTH-006" in prdids
        assert "FUS-CONF-002" in prdids
        assert "FUS-LOGIC-001" in prdids
        assert "FUS-LOGIC-002" in prdids
        assert "FUS-LOGIC-003" in prdids
        assert "FUS-LOGIC-004" in prdids

    def test_semantic_rule_fields(self):
        for r in AI_SEMANTIC_RULES:
            assert r.id
            assert r.name
            assert r.description
            assert r.severity in ("critical", "high", "medium", "low")
            assert r.cwe_id
            assert r.category
            assert r.prdid
            assert r.prompt_hint
            assert r.fix_template

    def test_acl001_horizontal_privilege(self):
        rule = next(r for r in AI_SEMANTIC_RULES if r.prdid == "FUS-ACL-001")
        assert "水平越权" in rule.name
        assert rule.cwe_id == "CWE-639"

    def test_logic001_payment_tampering(self):
        rule = next(r for r in AI_SEMANTIC_RULES if r.prdid == "FUS-LOGIC-001")
        assert "支付" in rule.name or "金额" in rule.prompt_hint
        assert rule.severity == "critical"


class TestSCAEnhancements:
    def test_sca002_deprecated_component(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("pycrypto==2.6.1\n")
            scanner = SCAScanner(use_osv=False)
            deps = scanner.collect_dependencies(tmpdir)
            vulns = scanner.check_deprecated(deps)
            assert any(v.rule_id == "FUS-SCA-002" for v in vulns)

    def test_sca002_no_deprecated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("flask==2.3.0\n")
            scanner = SCAScanner(use_osv=False)
            deps = scanner.collect_dependencies(tmpdir)
            vulns = scanner.check_deprecated(deps)
            assert not any(v.rule_id == "FUS-SCA-002" for v in vulns)

    def test_sca003_license_gpl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lic = Path(tmpdir) / "LICENSE"
            lic.write_text("This software is licensed under GPL-3.0")
            scanner = SCAScanner(use_osv=False)
            vulns = scanner.check_license(tmpdir)
            assert any(v.rule_id == "FUS-SCA-003" for v in vulns)

    def test_sca003_no_license_risk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lic = Path(tmpdir) / "LICENSE"
            lic.write_text("MIT License")
            scanner = SCAScanner(use_osv=False)
            vulns = scanner.check_license(tmpdir)
            assert not any(v.rule_id == "FUS-SCA-003" for v in vulns)

    def test_sca004_stale_version(self):
        scanner = SCAScanner(use_osv=False)
        deps = [Dependency(name="oldlib", version="1.0.0", ecosystem="pypi", source_file="req.txt")]
        vulns = scanner.check_stale_versions(deps)
        stale = [v for v in vulns if v.rule_id == "FUS-SCA-004"]
        assert len(stale) >= 1

    def test_sca004_recent_version_ok(self):
        scanner = SCAScanner(use_osv=False)
        deps = [Dependency(name="newlib", version="2024.1.0", ecosystem="pypi", source_file="req.txt")]
        vulns = scanner.check_stale_versions(deps)
        stale = [v for v in vulns if v.rule_id == "FUS-SCA-004"]
        assert len(stale) == 0

    def test_scan_includes_all_sca_checks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("pycrypto==2.6.1\n")
            scanner = SCAScanner(use_osv=False)
            vulns = scanner.scan(tmpdir)
            rule_ids = {v.rule_id for v in vulns}
            assert "FUS-SCA-002" in rule_ids


class TestJiraClient:
    def test_jira_config_defaults(self):
        config = JiraConfig(
            base_url="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_key="SEC",
        )
        assert config.issue_type == "Bug"
        assert config.labels == ["security"]
        assert config.custom_fields == {}

    def test_jira_create_issue_mock(self):
        config = JiraConfig(
            base_url="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_key="SEC",
        )
        jira = JiraClient(config)
        vuln = Vulnerability(
            id="test-vuln-1",
            title="SQL注入",
            description="检测到SQL注入",
            severity="critical",
            confidence=90,
            file_path="app.py",
            line_number=10,
            code_snippet="execute(sql)",
            rule_id="SQL001",
            cwe_id="CWE-89",
            fix_suggestion="使用参数化查询",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"key": "SEC-123"}
        mock_http = MagicMock()
        mock_http.post.return_value = mock_resp
        jira._client = mock_http
        issue = jira.create_issue(vuln)
        assert issue is not None
        assert issue.key == "SEC-123"
        assert issue.status == "Open"
        assert "SEC-123" in issue.url

    def test_jira_create_issue_failure(self):
        config = JiraConfig(
            base_url="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_key="SEC",
        )
        jira = JiraClient(config)
        vuln = Vulnerability(
            id="test-vuln-2",
            title="XSS",
            description="XSS漏洞",
            severity="high",
            confidence=85,
            file_path="view.html",
            line_number=5,
            code_snippet="innerHTML=",
            rule_id="XSS001",
            cwe_id="CWE-79",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_http = MagicMock()
        mock_http.post.return_value = mock_resp
        jira._client = mock_http
        issue = jira.create_issue(vuln)
        assert issue is None

    def test_jira_batch_create(self):
        config = JiraConfig(
            base_url="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_key="SEC",
        )
        client = JiraClient(config)
        vulns = [
            Vulnerability(
                id="v1",
                title="V1",
                description="d1",
                severity="high",
                confidence=80,
                file_path="a.py",
                line_number=1,
                code_snippet="code",
                rule_id="R001",
                cwe_id="CWE-1",
            ),
        ]
        with patch.object(
            client,
            "create_issue",
            return_value=JiraIssue(
                key="SEC-1", summary="V1", status="Open", url="https://jira.example.com/browse/SEC-1"
            ),
        ):
            issues = client.create_issues_batch(vulns)
            assert len(issues) == 1

    def test_jira_get_issue(self):
        config = JiraConfig(
            base_url="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_key="SEC",
        )
        jira = JiraClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "key": "SEC-42",
            "fields": {"summary": "Test", "status": {"name": "In Progress"}},
        }
        mock_http = MagicMock()
        mock_http.get.return_value = mock_resp
        jira._client = mock_http
        issue = jira.get_issue("SEC-42")
        assert issue is not None
        assert issue.status == "In Progress"

    def test_jira_build_description(self):
        config = JiraConfig(
            base_url="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_key="SEC",
        )
        client = JiraClient(config)
        vuln = Vulnerability(
            id="v1",
            title="Test Vuln",
            description="Description text",
            severity="high",
            confidence=80,
            file_path="app.py",
            line_number=10,
            code_snippet="code snippet here",
            rule_id="R001",
            cwe_id="CWE-89",
            fix_suggestion="Fix it",
        )
        desc = client._build_description(vuln)
        assert "Test Vuln" in desc
        assert "HIGH" in desc
        assert "CWE-89" in desc
        assert "Fix it" in desc
        assert "80%" in desc

    def test_severity_jira_priority_mapping(self):
        assert SEVERITY_JIRA_PRIORITY["critical"] == "Highest"
        assert SEVERITY_JIRA_PRIORITY["high"] == "High"
        assert SEVERITY_JIRA_PRIORITY["medium"] == "Medium"
        assert SEVERITY_JIRA_PRIORITY["low"] == "Low"

    def test_jira_close(self):
        config = JiraConfig(
            base_url="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_key="SEC",
        )
        client = JiraClient(config)
        mock_http = MagicMock()
        client._client = mock_http
        client.close()
        mock_http.close.assert_called_once()
        assert client._client is None


def _make_mock_db():
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.all.return_value = []
    db.add = MagicMock()
    db.commit = MagicMock()
    db.refresh = MagicMock()
    db.close = MagicMock()
    return db


def _make_project_orm(**overrides):
    defaults = {
        "id": "proj-update-1",
        "name": "OldName",
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


def _make_vuln_orm(**overrides):
    defaults = {
        "id": "vuln-status-1",
        "title": "Test",
        "description": "d",
        "severity": "high",
        "confidence": 80.0,
        "file_path": "a.py",
        "line_number": 1,
        "code_snippet": "c",
        "rule_id": "R1",
        "cwe_id": "CWE-1",
        "fix_suggestion": "",
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
        "id": "patch-verify-1",
        "vuln_id": "v1",
        "scan_id": "s1",
        "diff_content": "",
        "original_code": "",
        "patched_code": "",
        "description": "test",
        "status": "generated",
        "strategy": "template",
        "verified": False,
    }
    defaults.update(overrides)
    orm = MagicMock()
    for k, v in defaults.items():
        setattr(orm, k, v)
    return orm


class TestNewAPIEndpoints:
    @pytest.fixture(autouse=True)
    def setup(self):
        from fusion_security.api.app import create_app
        from fusion_security.db import get_session

        self.mock_db = _make_mock_db()
        self.app = create_app()
        self.app.dependency_overrides[get_session] = lambda: self.mock_db
        self.client = TestClient(self.app)

    def test_put_project_update(self):
        proj = _make_project_orm()
        self.mock_db.query.return_value.filter.return_value.first.return_value = proj
        resp = self.client.put("/api/v1/projects/proj-update-1", json={"name": "NewName"})
        assert resp.status_code == 200

    def test_put_project_not_found(self):
        self.mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = self.client.put("/api/v1/projects/nonexistent", json={"name": "X"})
        assert resp.status_code == 404

    def test_put_vuln_status(self):
        vuln = _make_vuln_orm()
        q = MagicMock()
        q.filter.return_value.first.return_value = vuln
        self.mock_db.query.return_value = q
        resp = self.client.put("/api/v1/vulnerabilities/vuln-status-1/status", json={"status": "fixed"})
        assert resp.status_code == 200

    def test_put_vuln_status_invalid(self):
        vuln = _make_vuln_orm()
        q = MagicMock()
        q.filter.return_value.first.return_value = vuln
        self.mock_db.query.return_value = q
        resp = self.client.put("/api/v1/vulnerabilities/vuln-status-2/status", json={"status": "invalid_status"})
        assert resp.status_code == 400

    def test_put_vuln_status_not_found(self):
        q = MagicMock()
        q.filter.return_value.first.return_value = None
        self.mock_db.query.return_value = q
        resp = self.client.put("/api/v1/vulnerabilities/nonexistent/status", json={"status": "fixed"})
        assert resp.status_code == 404

    def test_post_patch_verify(self):
        patch_orm = _make_patch_orm()
        self.mock_db.query.return_value.filter.return_value.first.return_value = patch_orm
        resp = self.client.post("/api/v1/patches/patch-verify-1/verify", json={"test_result": "passed"})
        assert resp.status_code == 200

    def test_post_patch_verify_failed(self):
        patch_orm = _make_patch_orm()
        self.mock_db.query.return_value.filter.return_value.first.return_value = patch_orm
        resp = self.client.post("/api/v1/patches/patch-verify-2/verify", json={"test_result": "failed"})
        assert resp.status_code == 200

    def test_post_patch_verify_not_found(self):
        self.mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = self.client.post("/api/v1/patches/nonexistent/verify", json={"test_result": "passed"})
        assert resp.status_code == 404

    def test_get_vulnerabilities_export(self):
        vuln = _make_vuln_orm()
        q = MagicMock()
        q.all.return_value = [vuln]
        q.filter.return_value.all.return_value = [vuln]
        self.mock_db.query = MagicMock(return_value=q)
        resp = self.client.get("/api/v1/vulnerabilities/export")
        assert resp.status_code == 200

    def test_get_vulnerabilities_export_csv(self):
        vuln = _make_vuln_orm()
        q = MagicMock()
        q.all.return_value = [vuln]
        q.filter.return_value.all.return_value = [vuln]
        self.mock_db.query = MagicMock(return_value=q)
        resp = self.client.get("/api/v1/vulnerabilities/export?format=csv")
        assert resp.status_code == 200

    def test_get_scan_sarif(self):
        scan_orm = MagicMock()
        scan_orm.id = "scan-sarif-1"
        scan_orm.status = "completed"
        scan_orm.project_id = "p1"
        scan_orm.total_vulnerabilities = 0
        scan_orm.critical = 0
        scan_orm.high = 0
        scan_orm.medium = 0
        scan_orm.low = 0
        scan_orm.duration_ms = 100.0
        self.mock_db.query.return_value.filter.return_value.first.return_value = scan_orm
        self.mock_db.query.return_value.filter.return_value.all.return_value = []
        resp = self.client.get("/api/v1/reports/scans/scan-sarif-1/sarif")
        assert resp.status_code == 200

    def test_get_scan_sarif_not_found(self):
        self.mock_db.query.return_value.filter.return_value.first.return_value = None
        resp = self.client.get("/api/v1/reports/scans/nonexistent/sarif")
        assert resp.status_code == 404

    @patch("httpx.get")
    def test_put_system_models(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"id": "qwen3.5-9b"}]}
        mock_get.return_value = mock_resp
        resp = self.client.put("/api/v1/system/models", json={"default_model": "qwen3.5-9b"})
        assert resp.status_code == 200

    def test_put_system_models_empty(self):
        resp = self.client.put("/api/v1/system/models", json={"default_model": ""})
        assert resp.status_code == 400


class TestJiraAPIEndpoints:
    @pytest.fixture(autouse=True)
    def setup(self):
        from fusion_security.api.app import create_app
        from fusion_security.db import get_session

        self.mock_db = _make_mock_db()
        self.app = create_app()
        self.app.dependency_overrides[get_session] = lambda: self.mock_db
        self.client = TestClient(self.app)

    def test_jira_config(self):
        resp = self.client.post(
            "/api/v1/integrations/jira/config",
            json={
                "base_url": "https://jira.example.com",
                "email": "test@example.com",
                "api_token": "token123",
                "project_key": "SEC",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["project_key"] == "SEC"

    def test_jira_sync_no_config(self):
        import fusion_security.api.routes.integrations as integ

        integ._jira_client = None
        resp = self.client.post("/api/v1/integrations/jira/sync", json={"vuln_ids": []})
        assert resp.status_code == 400

    def test_jira_get_issue_no_config(self):
        import fusion_security.api.routes.integrations as integ

        integ._jira_client = None
        resp = self.client.get("/api/v1/integrations/jira/issue/SEC-1")
        assert resp.status_code == 400

    def test_jira_get_issue_with_config(self):
        import fusion_security.api.routes.integrations as integ

        mock_client = MagicMock()
        mock_client.get_issue.return_value = JiraIssue(
            key="SEC-1", summary="Test", status="Open", url="https://jira.example.com/browse/SEC-1"
        )
        integ._jira_client = mock_client

        resp = self.client.get("/api/v1/integrations/jira/issue/SEC-1")
        assert resp.status_code == 200
        assert resp.json()["key"] == "SEC-1"

        integ._jira_client = None

    def test_jira_get_issue_not_found(self):
        import fusion_security.api.routes.integrations as integ

        mock_client = MagicMock()
        mock_client.get_issue.return_value = None
        integ._jira_client = mock_client

        resp = self.client.get("/api/v1/integrations/jira/issue/SEC-999")
        assert resp.status_code == 404

        integ._jira_client = None
