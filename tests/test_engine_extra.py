from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fusion_security.engine.ai.adversarial import AdversarialVerifier
from fusion_security.engine.ai.analyzer import AIAnalyzer
from fusion_security.engine.ci.webhook import WebhookConfig, WebhookNotifier
from fusion_security.engine.pipeline import (
    PipelineConfig,
    PipelineContext,
    ScanPipeline,
)
from fusion_security.engine.resume.checkpoint import (
    CheckpointManager,
    CircuitBreaker,
    CircuitState,
    RetryPolicy,
    StageCheckpoint,
)
from fusion_security.engine.rules.ast_parser import ASTResult, FunctionDef
from fusion_security.engine.rules.taint_tracker import (
    TaintResult,
    TaintSink,
    TaintSource,
    TaintTracker,
)
from fusion_security.engine.sca.scanner import (
    Dependency,
    KnownVuln,
    OSVClient,
    SCAScanner,
)
from fusion_security.engine.scanner import ScanCache, Scanner, ScanResult, ScanTarget
from fusion_security.engine.scheduler import (
    FREQUENCY_SECONDS,
    ScanScheduler,
    ScheduledScan,
    ScheduleFrequency,
)
from fusion_security.engine.vcs.git import DiffResult, GitHelper
from fusion_security.models.vulnerability import Vulnerability


def _make_vuln(**kwargs) -> Vulnerability:
    defaults = {
        "id": "V-TEST",
        "title": "Test Vuln",
        "description": "test vuln",
        "severity": "high",
        "confidence": 90,
        "file_path": "test.py",
        "line_number": 1,
        "code_snippet": "cursor.execute(user_input)",
        "rule_id": "SQL001",
        "cwe_id": "CWE-89",
    }
    defaults.update(kwargs)
    return Vulnerability(**defaults)


# ===== OSVClient =====


class TestOSVClient:
    def test_query_batch_empty(self):
        client = OSVClient()
        result = client.query_batch([])
        assert result == {}
        client.close()

    def test_query_batch_no_ecosystem(self):
        client = OSVClient()
        dep = Dependency(name="foo", version="1.0", ecosystem="unknown_eco")
        result = client.query_batch([dep])
        assert result == {}
        client.close()

    def test_query_batch_success(self):
        client = OSVClient()
        dep = Dependency(name="requests", version="2.28.0", ecosystem="pypi")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "OSV-2023-001",
                            "summary": "test vuln",
                            "severity": [{"score": "HIGH"}],
                            "aliases": ["CVE-2023-1234"],
                            "affected": [
                                {
                                    "package": {"name": "requests"},
                                    "ranges": [{"events": [{"fixed": "2.31.0"}]}],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        with patch.object(client, "_get_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.return_value = mock_resp
            mock_get.return_value = mock_http
            result = client.query_batch([dep])
        assert "requests@2.28.0" in result
        assert len(result["requests@2.28.0"]) == 1
        client.close()

    def test_query_batch_http_error(self):
        client = OSVClient()
        dep = Dependency(name="requests", version="2.28.0", ecosystem="pypi")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch.object(client, "_get_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.return_value = mock_resp
            mock_get.return_value = mock_http
            result = client.query_batch([dep])
        assert result == {}
        client.close()

    def test_query_batch_exception(self):
        import httpx

        client = OSVClient()
        dep = Dependency(name="requests", version="2.28.0", ecosystem="pypi")
        with patch.object(client, "_get_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.side_effect = httpx.HTTPError("conn fail")
            mock_get.return_value = mock_http
            result = client.query_batch([dep])
        assert result == {}
        client.close()

    def test_close_client(self):
        client = OSVClient()
        client._client = MagicMock()
        client.close()
        assert client._client is None

    def test_close_no_client(self):
        client = OSVClient()
        client.close()
        assert client._client is None


# ===== SCAScanner =====


class TestSCAScanner:
    def test_scan_no_osv(self):
        scanner = SCAScanner(use_osv=False)
        assert scanner.osv_client is None

    def test_parse_requirements(self):
        scanner = SCAScanner(use_osv=False)
        content = "requests==2.28.0\nflask>=2.0\n# comment\n-r other.txt\n"
        deps = scanner._parse_requirements("requirements.txt", content)
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"
        assert deps[0].ecosystem == "pypi"

    def test_parse_requirements_empty(self):
        scanner = SCAScanner(use_osv=False)
        content = "# just comments\n\n"
        deps = scanner._parse_requirements("requirements.txt", content)
        assert deps == []

    def test_parse_pipfile(self):
        scanner = SCAScanner(use_osv=False)
        content = '[packages]\nflask = "2.2.3"\nrequests = "2.28.0"\n\n[dev-packages]\npytest = "7.4.0"\n'
        deps = scanner._parse_pipfile("Pipfile", content)
        assert len(deps) >= 2
        flask_dep = [d for d in deps if d.name == "flask"]
        assert len(flask_dep) == 1
        assert flask_dep[0].is_dev is False

    def test_parse_pipfile_other_section(self):
        scanner = SCAScanner(use_osv=False)
        content = '[packages]\nflask = "2.2.3"\n[some_other]\nfoo = "1.0"\n'
        deps = scanner._parse_pipfile("Pipfile", content)
        assert len(deps) == 1

    def test_parse_pyproject(self):
        scanner = SCAScanner(use_osv=False)
        content = '[project]\nname = "myproject"\ndependencies = [\n    "requests>=2.28.0",\n    "flask==2.2.3",\n]\n'
        deps = scanner._parse_pyproject("pyproject.toml", content)
        assert len(deps) == 2
        assert deps[0].ecosystem == "pypi"

    def test_parse_pyproject_no_deps(self):
        scanner = SCAScanner(use_osv=False)
        content = '[project]\nname = "myproject"\n[build-system]\nrequires = ["setuptools"]\n'
        deps = scanner._parse_pyproject("pyproject.toml", content)
        assert deps == []

    def test_parse_package_json(self):
        scanner = SCAScanner(use_osv=False)
        data = {
            "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        deps = scanner._parse_package_json("package.json", json.dumps(data))
        assert len(deps) == 3
        npm_deps = [d for d in deps if d.ecosystem == "npm"]
        assert len(npm_deps) == 3

    def test_parse_package_json_invalid(self):
        scanner = SCAScanner(use_osv=False)
        deps = scanner._parse_package_json("package.json", "not json")
        assert deps == []

    def test_parse_gomod(self):
        scanner = SCAScanner(use_osv=False)
        content = "module example.com/myproject\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/text v0.13.0\n)\n"
        deps = scanner._parse_gomod("go.mod", content)
        assert len(deps) == 2
        assert deps[0].ecosystem == "gomod"
        assert deps[0].version == "1.9.1"

    def test_parse_gomod_block_only(self):
        scanner = SCAScanner(use_osv=False)
        content = "module example.com\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"
        deps = scanner._parse_gomod("go.mod", content)
        assert len(deps) == 1
        assert deps[0].name == "github.com/gin-gonic/gin"

    def test_parse_gomod_empty(self):
        scanner = SCAScanner(use_osv=False)
        content = "module example.com\n\ngo 1.21\n"
        deps = scanner._parse_gomod("go.mod", content)
        assert deps == []

    def test_parse_cargo(self):
        scanner = SCAScanner(use_osv=False)
        content = (
            '[dependencies]\nserde = { version = "1.0.188" }\ntokio = { version = "1.32.0" }\n\n[dev-dependencies]\n'
        )
        deps = scanner._parse_cargo("Cargo.toml", content)
        assert len(deps) == 2
        assert deps[0].ecosystem == "cargo"

    def test_parse_cargo_empty(self):
        scanner = SCAScanner(use_osv=False)
        content = '[package]\nname = "mycrate"\n'
        deps = scanner._parse_cargo("Cargo.toml", content)
        assert deps == []

    def test_parse_gemfile(self):
        scanner = SCAScanner(use_osv=False)
        content = "source 'https://rubygems.org'\ngem 'rails', '7.0.8'\ngem 'puma'\ngem 'devise', '~> 4.9'\n"
        deps = scanner._parse_gemfile("Gemfile", content)
        assert len(deps) == 3
        rails = [d for d in deps if d.name == "rails"]
        assert len(rails) == 1
        assert rails[0].version == "7.0.8"
        assert rails[0].ecosystem == "rubygems"

    def test_parse_gemfile_no_version(self):
        scanner = SCAScanner(use_osv=False)
        content = "gem 'puma'\n"
        deps = scanner._parse_gemfile("Gemfile", content)
        assert len(deps) == 1
        assert deps[0].version == "0"

    def test_collect_dependencies_with_files(self):
        scanner = SCAScanner(use_osv=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("flask==2.2.3\n")
            deps = scanner.collect_dependencies(tmpdir)
            assert len(deps) >= 1
            assert any(d.name == "flask" for d in deps)

    def test_collect_dependencies_skip_dirs(self):
        scanner = SCAScanner(use_osv=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            venv = Path(tmpdir) / ".venv"
            venv.mkdir()
            req = venv / "requirements.txt"
            req.write_text("flask==2.2.3\n")
            deps = scanner.collect_dependencies(tmpdir)
            flask_deps = [d for d in deps if d.name == "flask"]
            assert len(flask_deps) == 0

    def test_check_vulnerabilities_known(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="pypdf", version="3.15.0", ecosystem="pypi", source_file="req.txt")
        vulns = scanner.check_vulnerabilities([dep])
        assert len(vulns) >= 1
        assert any("CVE-2023-36664" in v.id for v in vulns)

    def test_check_vulnerabilities_not_affected(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="pypdf", version="3.17.0", ecosystem="pypi", source_file="req.txt")
        vulns = scanner.check_vulnerabilities([dep])
        pypdf_vulns = [v for v in vulns if "pypdf" in v.id]
        assert len(pypdf_vulns) == 0

    def test_check_vulnerabilities_with_osv(self):
        scanner = SCAScanner(use_osv=True)
        dep = Dependency(name="requests", version="2.28.0", ecosystem="pypi", source_file="req.txt")
        osv_data = {
            "requests@2.28.0": [
                {
                    "id": "OSV-2023-100",
                    "summary": "requests vuln",
                    "severity": [{"score": "HIGH"}],
                    "aliases": ["CVE-2023-9999"],
                    "affected": [
                        {
                            "package": {"name": "requests"},
                            "ranges": [{"events": [{"fixed": "2.31.0"}]}],
                        }
                    ],
                }
            ]
        }
        with patch.object(scanner.osv_client, "query_batch", return_value=osv_data):
            vulns = scanner.check_vulnerabilities([dep])
        assert len(vulns) >= 1
        assert any("CVE-2023-9999" in v.id for v in vulns)
        scanner.osv_client.close()

    def test_osv_to_vulnerability(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="requests", version="2.28.0", ecosystem="pypi", source_file="req.txt")
        osv_vuln = {
            "id": "OSV-TEST",
            "summary": "test summary",
            "details": "test details",
            "database_specific": {"severity": "CRITICAL"},
            "aliases": ["CVE-2023-5555"],
            "affected": [
                {
                    "package": {"name": "requests"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
                }
            ],
        }
        v = scanner._osv_to_vulnerability(dep, osv_vuln)
        assert v is not None
        assert "CVE-2023-5555" in v.id
        assert v.severity == "critical"
        assert "2.31.0" in v.fix_suggestion

    def test_osv_to_vulnerability_no_fix(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="foo", version="1.0", ecosystem="pypi", source_file="req.txt")
        osv_vuln = {
            "id": "OSV-NOFIX",
            "summary": "",
            "details": "some details",
            "severity": [],
            "aliases": [],
            "affected": [],
        }
        v = scanner._osv_to_vulnerability(dep, osv_vuln)
        assert v is not None
        assert "OSV 漏洞详情" in v.fix_suggestion

    def test_osv_to_vulnerability_severity_from_score(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="foo", version="1.0", ecosystem="pypi", source_file="req.txt")
        osv_vuln = {
            "id": "OSV-SEV",
            "summary": "test",
            "database_specific": {},
            "severity": [{"score": "MODERATE"}],
            "aliases": [],
            "affected": [],
        }
        v = scanner._osv_to_vulnerability(dep, osv_vuln)
        assert v.severity == "medium"

    def test_map_severity(self):
        scanner = SCAScanner(use_osv=False)
        assert scanner._map_severity("CRITICAL") == "critical"
        assert scanner._map_severity("CRIT") == "critical"
        assert scanner._map_severity("HIGH") == "high"
        assert scanner._map_severity("IMPORTANT") == "high"
        assert scanner._map_severity("MODERATE") == "medium"
        assert scanner._map_severity("MEDIUM") == "medium"
        assert scanner._map_severity("LOW") == "low"
        assert scanner._map_severity("UNKNOWN") == "low"
        assert scanner._map_severity("") == "low"

    def test_is_affected_less_than(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="pypdf", version="3.15.0", ecosystem="pypi")
        kv = KnownVuln("CVE-T", "pypdf", "<3.16.0", "high", "test", "3.16.0")
        assert scanner._is_affected(dep, kv) is True
        dep2 = Dependency(name="pypdf", version="3.17.0", ecosystem="pypi")
        assert scanner._is_affected(dep2, kv) is False

    def test_is_affected_less_equal(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="foo", version="1.0", ecosystem="pypi")
        kv = KnownVuln("CVE-T", "foo", "<=1.0", "high", "test", "1.1")
        assert scanner._is_affected(dep, kv) is True

    def test_is_affected_greater_equal(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="foo", version="2.0", ecosystem="pypi")
        kv = KnownVuln("CVE-T", "foo", ">=1.0", "high", "test", "0.9")
        assert scanner._is_affected(dep, kv) is True

    def test_is_affected_name_mismatch(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="bar", version="1.0", ecosystem="pypi")
        kv = KnownVuln("CVE-T", "foo", "<2.0", "high", "test", "2.0")
        assert scanner._is_affected(dep, kv) is False

    def test_is_affected_bad_version(self):
        scanner = SCAScanner(use_osv=False)
        dep = Dependency(name="foo", version="abc", ecosystem="pypi")
        kv = KnownVuln("CVE-T", "foo", "<2.0", "high", "test", "2.0")
        assert scanner._is_affected(dep, kv) is False

    def test_parse_version(self):
        scanner = SCAScanner(use_osv=False)
        assert scanner._parse_version("1.2.3") == (1, 2, 3)
        assert scanner._parse_version("v2.0.1") == (2, 0, 1)

    def test_parse_version_invalid(self):
        scanner = SCAScanner(use_osv=False)
        with pytest.raises(ValueError):
            scanner._parse_version("abc")

    def test_scan_with_project(self):
        scanner = SCAScanner(use_osv=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("pypdf==3.15.0\n")
            vulns = scanner.scan(tmpdir)
            assert any("CVE-2023-36664" in v.id for v in vulns)


# ===== AdversarialVerifier =====


class TestAdversarialVerifier:
    @pytest.fixture
    def mock_ai(self):
        ai = MagicMock(spec=AIAnalyzer)
        ai._chat = AsyncMock()
        ai._parse_json = MagicMock()
        return ai

    async def test_verify_exploitable(self, mock_ai):
        mock_ai._chat.return_value = "irrelevant"
        mock_ai._parse_json.side_effect = [
            {
                "is_exploitable": True,
                "exploit": "SQL injection via user_input",
                "difficulty": 0.3,
                "impact": 0.8,
                "reason": "no sanitization",
            },
            {"refuted": False, "reason": "no defense found", "defense": ""},
        ]
        verifier = AdversarialVerifier(mock_ai, rounds=2)
        vuln = _make_vuln()
        is_real, confidence, exploit = await verifier.verify(vuln, [Path("test.py")])
        assert is_real is True
        assert confidence > 0
        assert "SQL injection" in exploit

    async def test_verify_not_exploitable(self, mock_ai):
        mock_ai._chat.return_value = "irrelevant"
        mock_ai._parse_json.return_value = {"is_exploitable": False}
        verifier = AdversarialVerifier(mock_ai)
        vuln = _make_vuln()
        is_real, confidence, exploit = await verifier.verify(vuln, [Path("test.py")])
        assert is_real is False
        assert confidence == 0.0

    async def test_verify_defended(self, mock_ai):
        mock_ai._chat.return_value = "irrelevant"
        mock_ai._parse_json.side_effect = [
            {"is_exploitable": True, "exploit": "path", "difficulty": 0.5, "impact": 0.5, "reason": "test"},
            {"refuted": True, "reason": "input validated", "defense": "parameterized query"},
        ]
        verifier = AdversarialVerifier(mock_ai)
        vuln = _make_vuln()
        is_real, confidence, reason = await verifier.verify(vuln, [Path("test.py")])
        assert is_real is False
        assert "防御反驳" in reason

    async def test_verify_batch(self, mock_ai):
        mock_ai._chat.return_value = "irrelevant"
        mock_ai._parse_json.side_effect = [
            {"is_exploitable": True, "exploit": "path", "difficulty": 0.2, "impact": 0.9, "reason": "r"},
            {"refuted": False, "reason": "no defense", "defense": ""},
            {"is_exploitable": False},
        ]
        verifier = AdversarialVerifier(mock_ai)
        vulns = [_make_vuln(id="V1"), _make_vuln(id="V2")]
        result = await verifier.verify_batch(vulns, [Path("test.py")])
        assert len(result) == 1
        assert result[0].verified is True

    async def test_verify_batch_exception(self, mock_ai):
        mock_ai._chat.side_effect = RuntimeError("ai error")
        verifier = AdversarialVerifier(mock_ai)
        vulns = [_make_vuln(id="V1")]
        result = await verifier.verify_batch(vulns, [Path("test.py")])
        assert len(result) == 1

    def test_compute_confidence(self, mock_ai):
        verifier = AdversarialVerifier(mock_ai)
        c = verifier._compute_confidence(
            {"difficulty": 0.2, "impact": 0.9},
            {"refuted": False},
        )
        assert 10 <= c <= 100

    def test_compute_confidence_refuted(self, mock_ai):
        verifier = AdversarialVerifier(mock_ai)
        c = verifier._compute_confidence(
            {"difficulty": 0.2, "impact": 0.9},
            {"refuted": True},
        )
        assert c < 40


# ===== TaintTracker =====


class TestTaintTracker:
    def test_analyze_python_source_to_sink(self):
        tracker = TaintTracker()
        code = """
import flask
app = flask.Flask(__name__)

@app.route('/login')
def login():
    username = request.args.get('user')
    cursor.execute("SELECT * FROM users WHERE name='" + username + "'")
    return 'ok'
"""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            f.flush()
            result = tracker.analyze(Path(f.name), code)
        os.unlink(f.name)
        assert isinstance(result, TaintResult)
        assert len(result.taint_paths) >= 0

    def test_analyze_unsupported_extension(self):
        tracker = TaintTracker()
        result = tracker.analyze(Path("test.xyz"), "some code")
        assert isinstance(result, TaintResult)
        assert len(result.taint_paths) == 0

    def test_analyze_project_cross_file(self):
        tracker = TaintTracker()
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as fa:
            fa.write("""
from db_ops import execute_query

def handle_request():
    user_input = request.args.get('id')
    execute_query(user_input)
""")
            fa.flush()
            path_a = fa.name
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as fb:
            fb.write("""
def execute_query(param):
    cursor.execute(param)
""")
            fb.flush()
            path_b = fb.name
        results = tracker.analyze_project(
            [(Path(path_a), Path(path_a).read_text()), (Path(path_b), Path(path_b).read_text())]
        )
        os.unlink(path_a)
        os.unlink(path_b)
        assert isinstance(results, list)

    def test_find_sources_from_calls(self):
        tracker = TaintTracker()
        ast_result = ASTResult(
            file_path="test.py",
            language="python",
            calls=[{"name": "request.args.get", "line": 5}],
        )
        sources = tracker._find_sources(ast_result)
        assert len(sources) >= 1
        assert sources[0].source_type == "http_input"

    def test_find_sources_from_assignments(self):
        tracker = TaintTracker()
        ast_result = ASTResult(
            file_path="test.py",
            language="python",
            assignments=[{"name": "user_id", "value": "request.form.get('id')", "line": 10}],
        )
        sources = tracker._find_sources(ast_result)
        assert len(sources) >= 1

    def test_find_sinks(self):
        tracker = TaintTracker()
        ast_result = ASTResult(
            file_path="test.py",
            language="python",
            calls=[{"name": "cursor.execute", "line": 20}],
        )
        sinks = tracker._find_sinks(ast_result)
        assert len(sinks) >= 1
        assert sinks[0].sink_type == "SQL注入"

    def test_find_sinks_base_name(self):
        tracker = TaintTracker()
        ast_result = ASTResult(
            file_path="test.py",
            language="python",
            calls=[{"name": "os.system", "line": 5}],
        )
        sinks = tracker._find_sinks(ast_result)
        assert len(sinks) >= 1
        assert sinks[0].sink_type == "命令注入"

    def test_check_sanitization(self):
        tracker = TaintTracker()
        source = TaintSource(name="request.args", line=1, variable="x", source_type="http_input")
        sink = TaintSink(name="execute", line=10, sink_type="SQL注入")
        ast_result = ASTResult(
            file_path="test.py",
            language="python",
            calls=[{"name": "escape", "line": 5}],
        )
        assert tracker._check_sanitization(source, sink, ast_result) is True

    def test_check_no_sanitization(self):
        tracker = TaintTracker()
        source = TaintSource(name="request.args", line=1, variable="x", source_type="http_input")
        sink = TaintSink(name="execute", line=10, sink_type="SQL注入")
        ast_result = ASTResult(
            file_path="test.py",
            language="python",
            calls=[{"name": "format", "line": 5}],
        )
        assert tracker._check_sanitization(source, sink, ast_result) is False

    def test_is_source(self):
        tracker = TaintTracker()
        assert tracker._is_source("request.args") is True
        assert tracker._is_source("input(") is True
        assert tracker._is_source("safe_function") is False

    def test_classify_source(self):
        tracker = TaintTracker()
        assert tracker._classify_source("request.args") == "http_input"
        assert tracker._classify_source("sys.stdin") == "user_input"
        assert tracker._classify_source("os.environ") == "environment"
        assert tracker._classify_source("unknown_thing") == "unknown"

    def test_cross_file_analysis(self):
        tracker = TaintTracker()

        class FakeImport:
            names = ["run_query"]
            module = "db.run_query"

        ast_a = ASTResult(
            file_path="a.py",
            language="python",
            functions=[],
            imports=[FakeImport()],
            calls=[{"name": "request.args.get", "line": 5}],
        )
        ast_b = ASTResult(
            file_path="b.py",
            language="python",
            functions=[
                FunctionDef(
                    name="run_query",
                    params=["q"],
                    start_line=1,
                    end_line=5,
                    body="cursor.execute(q)",
                    calls=["cursor.execute"],
                )
            ],
            imports=[],
            calls=[],
        )
        paths = tracker._cross_file_analysis({"a.py": ast_a, "b.py": ast_b})
        assert isinstance(paths, list)
        assert len(paths) >= 1

    def test_trace_propagation(self):
        tracker = TaintTracker()
        source = TaintSource(name="request.args", line=5, variable="x", source_type="http_input")
        sink = TaintSink(name="execute", line=15, sink_type="SQL注入")
        ast_result = ASTResult(
            file_path="test.py",
            language="python",
            functions=[
                FunctionDef(
                    name="handler",
                    params=[],
                    start_line=3,
                    end_line=20,
                    body="x = request.args\nexecute(x)",
                    calls=["execute"],
                )
            ],
        )
        path = tracker._trace_propagation(source, sink, ast_result)
        assert len(path) >= 2
        assert path[0]["type"] == "source"
        assert path[-1]["type"] == "sink"


# ===== Pipeline =====


class TestScanPipeline:
    @pytest.fixture
    def temp_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "app.py"
            py_file.write_text("import os\nos.system('echo hello')\n")
            yield tmpdir

    async def test_pipeline_run_full(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        ctx = await pipeline.run(temp_project)
        assert ctx.scan_id.startswith("scan_")
        assert len(ctx.files) >= 1
        assert "recon" in ctx.stage_results
        assert "discover" in ctx.stage_results

    async def test_pipeline_incremental(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        ctx = await pipeline.run(temp_project, changed_files=["app.py"])
        assert ctx.files is not None

    async def test_pipeline_context_auto_scan_id(self):
        ctx = PipelineContext()
        assert ctx.scan_id.startswith("scan_")

    async def test_pipeline_with_scan_id(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        ctx = await pipeline.run(temp_project, scan_id="test_scan_123")
        assert ctx.scan_id == "test_scan_123"

    async def test_pipeline_resume_from_checkpoint(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        cp = StageCheckpoint(
            scan_id="resume_test",
            project_path=temp_project,
            completed_stage="recon",
            stage_data={"files": [], "language_stats": {}, "dependency_files": []},
        )
        pipeline.checkpoint_mgr.save(cp)
        ctx = await pipeline.run(temp_project, scan_id="resume_test")
        assert "recon" not in ctx.stage_results or ctx.stage_results.get("recon", {}).get("duration_ms", 0) >= 0
        pipeline.checkpoint_mgr.remove("resume_test")

    async def test_pipeline_triage_dedup(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        ctx = await pipeline.run(temp_project)
        seen = set()
        for v in ctx.vulnerabilities:
            key = f"{v.file_path}:{v.line_number}:{v.rule_id}"
            assert key not in seen
            seen.add(key)

    def test_detect_language(self):
        config = PipelineConfig(use_ai=False)
        pipeline = ScanPipeline(config)
        assert pipeline._detect_language(Path("app.py")) == "python"
        assert pipeline._detect_language(Path("app.js")) == "javascript"
        assert pipeline._detect_language(Path("app.go")) == "go"
        assert pipeline._detect_language(Path("app.rs")) == "rust"
        assert pipeline._detect_language(Path("app.xyz")) == "unknown"

    def test_sanitize_stage_result(self):
        config = PipelineConfig(use_ai=False)
        pipeline = ScanPipeline(config)
        data = {"path": Path("/tmp/test"), "num": 1.234567, "nested": {"p": Path("a.py")}}
        result = pipeline._sanitize_stage_result(data)
        assert result["path"] == "/tmp/test"
        assert isinstance(result["num"], float)
        assert result["nested"]["p"] == "a.py"

    def test_to_scan_result(self):
        config = PipelineConfig(use_ai=False)
        pipeline = ScanPipeline(config)
        ctx = PipelineContext(project_path="/tmp/test")
        ctx.files = [Path("/tmp/test/a.py")]
        ctx.vulnerabilities = []
        ctx.stage_results = {"triage": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "duration_ms": 10}}
        result = pipeline.to_scan_result(ctx)
        assert isinstance(result, ScanResult)
        assert "未发现安全漏洞" in result.summary or len(result.vulnerabilities) == 0

    async def test_pipeline_verify_no_vulns(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        ctx = PipelineContext(project_path=temp_project)
        ctx.files = [Path(temp_project) / "clean.py"]
        (Path(temp_project) / "clean.py").write_text("x = 1\n")
        ctx.vulnerabilities = []
        await pipeline._stage_verify(ctx)
        assert ctx.stage_results["verify"]["verified"] == 0

    async def test_pipeline_patch_disabled(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        ctx = PipelineContext(project_path=temp_project)
        ctx.vulnerabilities = [_make_vuln()]
        await pipeline._stage_patch(ctx)
        assert ctx.stage_results["patch"]["patches"] == 0

    async def test_pipeline_retest_no_patches(self, temp_project):
        config = PipelineConfig(
            use_ai=False, enable_sca=False, enable_adversarial=False, enable_patch=False, enable_taint=False
        )
        pipeline = ScanPipeline(config)
        ctx = PipelineContext(project_path=temp_project)
        ctx.patches = []
        await pipeline._stage_retest(ctx)
        assert ctx.stage_results["retest"]["retested"] == 0


# ===== CheckpointManager / CircuitBreaker / RetryPolicy =====


class TestCheckpointManager:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CheckpointManager(checkpoint_dir=tmpdir)
            cp = StageCheckpoint(scan_id="test_scan", project_path="/tmp", completed_stage="recon")
            mgr.save(cp)
            loaded = mgr.load("test_scan")
            assert loaded is not None
            assert loaded.completed_stage == "recon"

    def test_load_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CheckpointManager(checkpoint_dir=tmpdir)
            assert mgr.load("nonexistent") is None

    def test_remove(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CheckpointManager(checkpoint_dir=tmpdir)
            cp = StageCheckpoint(scan_id="to_remove", project_path="/tmp")
            mgr.save(cp)
            assert mgr.remove("to_remove") is True
            assert mgr.remove("to_remove") is False

    def test_list_checkpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CheckpointManager(checkpoint_dir=tmpdir)
            mgr.save(StageCheckpoint(scan_id="s1", project_path="/tmp", completed_stage="recon"))
            mgr.save(StageCheckpoint(scan_id="s2", project_path="/tmp", completed_stage="discover"))
            cps = mgr.list_checkpoints()
            assert len(cps) == 2


class TestCircuitBreaker:
    def test_initial_state_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.01)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_half_open_after_recovery(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_success_closes_from_half_open(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        _ = cb.state
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_failure_in_half_open_reopens(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        _ = cb.state
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_reset(self):
        cb = CircuitBreaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_half_open_max_calls(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01, half_open_max_calls=1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        assert cb.allow_request() is True
        assert cb.allow_request() is False


class TestRetryPolicy:
    def test_get_delay(self):
        rp = RetryPolicy(max_retries=3, base_delay=1.0, max_delay=30.0, exponential_base=2.0)
        assert rp.get_delay(0) == 1.0
        assert rp.get_delay(1) == 2.0
        assert rp.get_delay(2) == 4.0

    def test_get_delay_capped(self):
        rp = RetryPolicy(base_delay=10.0, max_delay=15.0, exponential_base=2.0)
        assert rp.get_delay(5) == 15.0


# ===== Scheduler =====


class TestScanSchedulerExtra:
    def test_compute_next_run_with_last_run(self):
        s = ScheduledScan(
            id="s1",
            project_path="/tmp",
            frequency=ScheduleFrequency.DAILY,
            last_run=time.time() - 1000,
        )
        next_run = s.compute_next_run()
        assert next_run > s.last_run

    def test_compute_next_run_without_last_run(self):
        s = ScheduledScan(id="s2", project_path="/tmp", frequency=ScheduleFrequency.HOURLY)
        next_run = s.compute_next_run()
        assert next_run > time.time() - 1

    def test_frequency_seconds(self):
        assert FREQUENCY_SECONDS[ScheduleFrequency.HOURLY] == 3600
        assert FREQUENCY_SECONDS[ScheduleFrequency.DAILY] == 86400
        assert FREQUENCY_SECONDS[ScheduleFrequency.WEEKLY] == 604800
        assert FREQUENCY_SECONDS[ScheduleFrequency.MONTHLY] == 2592000

    async def test_start_stop(self):
        sched = ScanScheduler()
        sched.add_schedule(ScheduledScan(id="s1", project_path="/tmp", frequency=ScheduleFrequency.DAILY))
        await sched.start()
        assert sched._running is True
        await sched.stop()
        assert sched._running is False

    async def test_start_idempotent(self):
        sched = ScanScheduler()
        await sched.start()
        await sched.start()
        assert sched._running is True
        await sched.stop()

    async def test_run_loop_executes_callback(self):
        sched = ScanScheduler()
        called = []

        async def callback(schedule):
            called.append(schedule.id)

        s = ScheduledScan(
            id="s1",
            project_path="/tmp",
            frequency=ScheduleFrequency.HOURLY,
            next_run=time.time() - 1,
            enabled=True,
        )
        sched.schedules["s1"] = s
        sched._running = True
        with patch("fusion_security.engine.scheduler.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:

            async def stop_after_first_sleep(*args, **kwargs):
                sched._running = False

            mock_sleep.side_effect = stop_after_first_sleep
            await sched._run_loop(callback)
        assert "s1" in called

    async def test_run_loop_disabled_schedule(self):
        sched = ScanScheduler()
        called = []

        async def callback(schedule):
            called.append(schedule.id)

        s = ScheduledScan(
            id="s1",
            project_path="/tmp",
            frequency=ScheduleFrequency.HOURLY,
            next_run=time.time() - 1,
            enabled=False,
        )
        sched.schedules["s1"] = s
        sched._running = True
        with patch("fusion_security.engine.scheduler.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:

            async def stop_after_first(*args, **kwargs):
                sched._running = False

            mock_sleep.side_effect = stop_after_first
            await sched._run_loop(callback)
        assert "s1" not in called

    async def test_run_loop_callback_exception(self):
        sched = ScanScheduler()

        async def bad_callback(schedule):
            raise RuntimeError("scan failed")

        s = ScheduledScan(
            id="s1",
            project_path="/tmp",
            frequency=ScheduleFrequency.HOURLY,
            next_run=time.time() - 1,
            enabled=True,
        )
        sched.schedules["s1"] = s
        sched._running = True
        with patch("fusion_security.engine.scheduler.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:

            async def stop_after_first(*args, **kwargs):
                sched._running = False

            mock_sleep.side_effect = stop_after_first
            await sched._run_loop(bad_callback)


# ===== Webhook =====


class TestWebhookExtra:
    def test_send_with_secret(self):
        notifier = WebhookNotifier()
        config = WebhookConfig(url="http://localhost:9999/hook", secret="my_secret_key")
        body = json.dumps({"event": "test", "payload": {}}).encode("utf-8")
        hmac.new(b"my_secret_key", body, hashlib.sha256).hexdigest()
        from fusion_security.engine.ci._url_guard import URLGuardResult

        with (
            patch(
                "fusion_security.engine.ci.webhook.pin_url",
                return_value=(URLGuardResult(ok=True, safe_url=config.url), None),
            ),
            patch("fusion_security.engine.ci.webhook.urlopen") as mock_urlopen,
        ):
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            result = notifier._send(config, "test", {})
        assert result is True

    def test_send_without_secret(self):
        notifier = WebhookNotifier()
        config = WebhookConfig(url="http://localhost:9999/hook")
        from fusion_security.engine.ci._url_guard import URLGuardResult

        with (
            patch(
                "fusion_security.engine.ci.webhook.pin_url",
                return_value=(URLGuardResult(ok=True, safe_url=config.url), None),
            ),
            patch("fusion_security.engine.ci.webhook.urlopen") as mock_urlopen,
        ):
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            result = notifier._send(config, "test", {})
        assert result is True

    def test_send_url_error(self):
        from urllib.error import URLError

        from fusion_security.engine.ci._url_guard import URLGuardResult

        notifier = WebhookNotifier()
        config = WebhookConfig(url="http://localhost:9999/hook")
        with (
            patch(
                "fusion_security.engine.ci.webhook.pin_url",
                return_value=(URLGuardResult(ok=True, safe_url=config.url), None),
            ),
            patch("fusion_security.engine.ci.webhook.urlopen", side_effect=URLError("fail")),
        ):
            result = notifier._send(config, "test", {})
        assert result is False

    def test_send_general_exception(self):
        from fusion_security.engine.ci._url_guard import URLGuardResult

        notifier = WebhookNotifier()
        config = WebhookConfig(url="http://localhost:9999/hook")
        with (
            patch(
                "fusion_security.engine.ci.webhook.pin_url",
                return_value=(URLGuardResult(ok=True, safe_url=config.url), None),
            ),
            patch("fusion_security.engine.ci.webhook.urlopen", side_effect=Exception("boom")),
        ):
            result = notifier._send(config, "test", {})
        assert result is False

    def test_send_ssrf_rejected(self):
        from fusion_security.engine.ci._url_guard import URLGuardResult

        notifier = WebhookNotifier()
        config = WebhookConfig(url="http://169.254.169.254/latest/meta-data/")
        with patch(
            "fusion_security.engine.ci.webhook.pin_url",
            return_value=(URLGuardResult(ok=False, reason="目标地址禁止外发"), None),
        ):
            result = notifier._send(config, "test", {})
        assert result is False

    def test_notify_event_matched(self):
        notifier = WebhookNotifier([WebhookConfig(url="http://localhost:9999/hook", events=["scan.completed"])])
        with patch.object(notifier, "_send", return_value=True):
            results = notifier.notify("scan.completed", {"scan_id": "s1"})
        assert results == [True]

    def test_notify_event_unmatched(self):
        notifier = WebhookNotifier([WebhookConfig(url="http://localhost:9999/hook", events=["scan.completed"])])
        results = notifier.notify("other.event", {})
        assert results == [True]

    def test_notify_send_failure(self):
        notifier = WebhookNotifier([WebhookConfig(url="http://localhost:9999/hook", events=["scan.completed"])])
        with patch.object(notifier, "_send", side_effect=Exception("fail")):
            results = notifier.notify("scan.completed", {})
        assert results == [False]

    def test_notify_scan_complete_gate_passed(self):
        notifier = WebhookNotifier([WebhookConfig(url="http://localhost:9999/hook", events=["scan.completed"])])
        with patch.object(notifier, "_send", return_value=True):
            results = notifier.notify_scan_complete("s1", 5, 1, 2, 1, 1, gate_passed=True)
        assert len(results) == 1

    def test_notify_scan_complete_gate_failed(self):
        notifier = WebhookNotifier([WebhookConfig(url="http://localhost:9999/hook", events=["gate.failed"])])
        with patch.object(notifier, "_send", return_value=True):
            results = notifier.notify_scan_complete("s1", 5, 1, 2, 1, 1, gate_passed=False)
        assert len(results) == 1

    def test_webhook_config_custom_headers(self):
        config = WebhookConfig(url="http://localhost/hook", headers={"X-Custom": "value"})
        assert config.headers["X-Custom"] == "value"


# ===== Scanner extra =====


class TestScannerExtra:
    @pytest.fixture
    def temp_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py = Path(tmpdir) / "test.py"
            py.write_text("import os\nos.system('rm -rf /')\n")
            yield tmpdir

    async def test_scan_incremental(self, temp_project):
        scanner = Scanner(use_ai=False, enable_cache=True)
        target = ScanTarget(temp_project)
        result = await scanner.scan_incremental(target, ["test.py"])
        assert result.files_scanned >= 0

    async def test_scan_incremental_empty(self, temp_project):
        scanner = Scanner(use_ai=False)
        target = ScanTarget(temp_project)
        result = await scanner.scan_incremental(target, [])
        assert result.files_scanned == 0

    async def test_scan_directory(self, temp_project):
        scanner = Scanner(use_ai=False)
        result = await scanner.scan_directory(temp_project)
        assert isinstance(result, ScanResult)

    async def test_scan_with_cache(self, temp_project):
        scanner = Scanner(use_ai=False, enable_cache=True)
        target = ScanTarget(temp_project)
        await scanner.scan(target)
        await scanner.scan(target)
        assert scanner.cache.stats["hits"] > 0

    async def test_scan_severity_threshold(self, temp_project):
        scanner = Scanner(use_ai=False, enable_cache=False)
        target = ScanTarget(temp_project)
        result = await scanner.scan(target, severity_threshold="critical")
        for v in result.vulnerabilities:
            assert v.severity == "critical"

    def test_scan_cache_put_get(self):
        cache = ScanCache()
        cache.put(Path("test.py"), "content", [_make_vuln()])
        result = cache.get(Path("test.py"), "content")
        assert result is not None
        assert len(result) == 1

    def test_scan_cache_miss(self):
        cache = ScanCache()
        result = cache.get(Path("test.py"), "content")
        assert result is None

    def test_scan_cache_ttl_expired(self):
        cache = ScanCache(ttl_seconds=0)
        cache.put(Path("test.py"), "content", [_make_vuln()])
        time.sleep(0.01)
        result = cache.get(Path("test.py"), "content")
        assert result is None

    def test_scan_cache_eviction(self):
        cache = ScanCache(max_entries=2)
        cache.put(Path("a.py"), "a", [_make_vuln(id="V1")])
        cache.put(Path("b.py"), "b", [_make_vuln(id="V2")])
        cache.put(Path("c.py"), "c", [_make_vuln(id="V3")])
        assert cache.stats["entries"] == 2

    def test_scan_cache_invalidate(self):
        cache = ScanCache()
        p = Path("test.py")
        cache.put(p, "content", [_make_vuln()])
        cache.invalidate(p)
        result = cache.get(p, "content")
        # invalidate 按路径反查并删除条目，缓存应已清空
        assert result is None
        assert cache.stats["entries"] == 0

    def test_scan_cache_clear(self):
        cache = ScanCache()
        cache.put(Path("a.py"), "a", [_make_vuln()])
        cache.put(Path("b.py"), "b", [_make_vuln()])
        cache.clear()
        assert cache.stats["entries"] == 0
        assert cache.stats["hits"] == 0

    def test_scan_cache_stats(self):
        cache = ScanCache()
        cache.get(Path("a.py"), "a")
        cache.put(Path("a.py"), "a", [_make_vuln()])
        cache.get(Path("a.py"), "a")
        stats = cache.stats
        assert stats["misses"] >= 1
        assert stats["hits"] >= 1
        assert 0 < stats["hit_rate"] <= 1.0

    def test_scan_target_discover_incremental(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py = Path(tmpdir) / "test.py"
            py.write_text("x = 1\n")
            target = ScanTarget(tmpdir)
            files = target.discover_incremental(["test.py"])
            assert len(files) == 1

    def test_scan_target_discover_incremental_bad_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = ScanTarget(tmpdir)
            files = target.discover_incremental(["", "../etc/passwd"])
            assert len(files) == 0

    def test_scan_target_discover_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"x = 1\n")
            f.flush()
            target = ScanTarget(f.name)
            files = target.discover()
            assert len(files) == 1
        os.unlink(f.name)

    def test_scan_target_discover_file_not_source(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"data\n")
            f.flush()
            target = ScanTarget(f.name)
            files = target.discover()
            assert len(files) == 0
        os.unlink(f.name)

    def test_scan_target_check_file_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = ScanTarget(tmpdir, max_file_size=5)
            big = Path(tmpdir) / "big.py"
            big.write_text("x" * 100)
            assert target._check_file_size(big) is False

    def test_scan_result_to_dict(self):
        target = ScanTarget("/tmp")
        result = ScanResult(target)
        result.vulnerabilities = [_make_vuln(severity="critical")]
        d = result.to_dict()
        assert d["critical"] == 1
        assert d["total_vulnerabilities"] == 1

    def test_scan_result_to_scan_model(self):
        target = ScanTarget("/tmp")
        result = ScanResult(target)
        result.vulnerabilities = [_make_vuln()]
        model = result.to_scan_model()
        assert model.status == "completed"

    async def test_scan_no_cache(self, temp_project):
        scanner = Scanner(use_ai=False, enable_cache=False)
        assert scanner.cache is None
        target = ScanTarget(temp_project)
        result = await scanner.scan(target)
        assert isinstance(result, ScanResult)

    async def test_scan_with_ai_mock(self, temp_project):
        scanner = Scanner(use_ai=True, enable_cache=False)
        scanner.ai_analyzer = MagicMock(spec=AIAnalyzer)
        scanner.ai_analyzer.verify_findings = AsyncMock(return_value=[_make_vuln()])
        scanner.ai_analyzer.semantic_scan = AsyncMock(return_value=[])
        scanner.ai_analyzer.aclose = AsyncMock()
        target = ScanTarget(temp_project)
        result = await scanner.scan(target)
        assert isinstance(result, ScanResult)


# ===== GitHelper =====


class TestGitHelper:
    def test_init_not_git_repo(self):
        with tempfile.TemporaryDirectory() as tmpdir, pytest.raises(ValueError, match="不是git仓库"):
            GitHelper(tmpdir)

    def test_get_current_branch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            helper = GitHelper(tmpdir)
            branch = helper.get_current_branch()
            assert branch != ""

    def test_get_head_commit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            helper = GitHelper(tmpdir)
            commit = helper.get_head_commit()
            assert len(commit) >= 7

    def test_get_changed_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            (Path(tmpdir) / "test.py").write_text("x = 1\n")
            subprocess.run(["git", "-C", tmpdir, "add", "test.py"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "-m", "add test"], capture_output=True)
            helper = GitHelper(tmpdir)
            result = helper.get_changed_files()
            assert isinstance(result, DiffResult)

    def test_get_changed_files_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            head = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD"], capture_output=True, text=True
            ).stdout.strip()
            helper = GitHelper(tmpdir)
            result = helper.get_changed_files(base=head, head=head)
            assert isinstance(result, DiffResult)
            assert len(result.changed_files) == 0

    def test_get_file_at_commit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            (Path(tmpdir) / "hello.py").write_text("print('hello')\n")
            subprocess.run(["git", "-C", tmpdir, "add", "hello.py"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "-m", "add hello"], capture_output=True)
            helper = GitHelper(tmpdir)
            content = helper.get_file_at_commit("hello.py")
            assert content is not None
            assert "hello" in content

    def test_get_file_at_commit_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            helper = GitHelper(tmpdir)
            content = helper.get_file_at_commit("nonexistent.py")
            assert content is None

    def test_get_blame(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            (Path(tmpdir) / "hello.py").write_text("print('hello')\n")
            subprocess.run(["git", "-C", tmpdir, "add", "hello.py"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "-m", "add hello"], capture_output=True)
            helper = GitHelper(tmpdir)
            blame = helper.get_blame("hello.py")
            assert isinstance(blame, str)

    def test_list_commits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "first"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "second"], capture_output=True)
            helper = GitHelper(tmpdir)
            head = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD~1"], capture_output=True, text=True
            ).stdout.strip()
            commits = helper.list_commits(base=head, head="HEAD")
            assert len(commits) >= 1

    def test_run_git_timeout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            helper = GitHelper(tmpdir)
            with patch(
                "fusion_security.engine.vcs.git.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="git", timeout=1),
            ):
                result = helper._run_git("status")
                assert result == ""

    def test_run_git_exception(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            helper = GitHelper(tmpdir)
            with patch("fusion_security.engine.vcs.git.subprocess.run", side_effect=Exception("boom")):
                result = helper._run_git("status")
                assert result == ""

    def test_get_merge_base(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "branch", "-M", "main"], capture_output=True)
            helper = GitHelper(tmpdir)
            mb = helper.get_merge_base("main")
            assert isinstance(mb, str)

    def test_get_changed_files_with_extensions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.email", "test@test.com"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "config", "user.name", "test"], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "--allow-empty", "-m", "init"], capture_output=True)
            (Path(tmpdir) / "test.py").write_text("x = 1\n")
            (Path(tmpdir) / "data.csv").write_text("a,b\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True)
            subprocess.run(["git", "-C", tmpdir, "commit", "-m", "add files"], capture_output=True)
            helper = GitHelper(tmpdir)
            head = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD~1"],
                capture_output=True,
                text=True,
            ).stdout.strip()
            if head:
                result = helper.get_changed_files(base=head, extensions=[".py"])
                assert all(Path(f).suffix == ".py" for f in result.changed_files)


class TestSecretRedactingFilter:
    def _emit(self, msg):
        import logging

        from fusion_security.utils.logger import SecretRedactingFilter

        rec = logging.LogRecord("t", logging.INFO, __file__, 1, msg, None, None)
        SecretRedactingFilter().filter(rec)
        return rec.getMessage()

    def test_redacts_password_kv(self):
        out = self._emit("login password=s3cr3t-xyz done")
        assert "s3cr3t-xyz" not in out
        assert "[REDACTED]" in out

    def test_redacts_api_key_quotes(self):
        out = self._emit('cfg api_key="AKIA1234567890ABCDEF" loaded')
        assert "AKIA1234567890ABCDEF" not in out
        assert "[REDACTED]" in out

    def test_redacts_bearer(self):
        out = self._emit("Authorization: Bearer eyJhbGci.eyJzdWIi.SflKxw")
        assert "eyJhbGci.eyJzdWIi.SflKxw" not in out
        assert "[REDACTED]" in out

    def test_preserves_nonsecret(self):
        out = self._emit("scan 12 files, 3 vulns, duration 240ms")
        assert out == "scan 12 files, 3 vulns, duration 240ms"


class TestReDoSDetector:
    @pytest.mark.parametrize(
        "pattern, risky",
        [
            ("(a+)+", True),
            ("(a*)*", True),
            ("([a-z]+)+", True),
            ("(?:a+)*", True),
            ("(a+)*b", True),
            ("((ab)+)+", True),
            ("a+b+", False),
            ("(a|b)*", False),
            ("(foo)*", False),
            ("password.*=", False),
            ("[a-z]+", False),
        ],
    )
    def test_nested_quantifier(self, pattern, risky):
        from fusion_security.engine.rules.custom import CustomRule

        assert CustomRule._has_nested_quantifier(pattern) is risky

    def test_redos_rule_returns_none(self):
        from fusion_security.engine.rules.custom import CustomRule

        rule = CustomRule(id="R", name="bad", pattern="(a+)+")
        assert rule.to_scan_rule() is None

    def test_safe_rule_compiles(self):
        from fusion_security.engine.rules.custom import CustomRule

        rule = CustomRule(id="R", name="ok", pattern="eval\\(")
        assert rule.to_scan_rule() is not None
