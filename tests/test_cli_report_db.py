from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from fusion_security.cli import cli
from fusion_security.db.session import get_session, init_async_db, init_db
from fusion_security.engine.scanner import ScanResult, ScanTarget
from fusion_security.models.vulnerability import Vulnerability
from fusion_security.report.report import ReportGenerator


class TestVulnerabilityModel:
    def test_to_dict(self):
        v = Vulnerability(
            id="V001",
            title="test",
            description="desc",
            severity="high",
            confidence=90,
            file_path="a.py",
            line_number=5,
            code_snippet="code here",
            rule_id="R001",
            cwe_id="CWE-79",
            fix_suggestion="fix it",
        )
        d = v.to_dict()
        assert d["id"] == "V001"
        assert d["severity"] == "high"
        assert d["code_snippet"] == "code here"
        assert d["verified"] is False
        assert d["status"] == "open"

    def test_to_dict_truncates_snippet(self):
        v = Vulnerability(
            id="V002",
            title="t",
            description="d",
            severity="low",
            confidence=50,
            file_path="b.py",
            line_number=1,
            code_snippet="x" * 500,
        )
        d = v.to_dict()
        assert len(d["code_snippet"]) <= 200

    def test_defaults(self):
        v = Vulnerability(
            id="V003",
            title="t",
            description="d",
            severity="medium",
            confidence=60,
            file_path="c.py",
            line_number=1,
            code_snippet="s",
        )
        assert v.rule_id == ""
        assert v.cwe_id == ""
        assert v.fix_suggestion == ""
        assert v.verified is False
        assert v.status == "open"
        assert v.data_flow_path == ""


class TestDBSession:
    def test_init_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            init_db(db_path=db_path)
            session = get_session()
            assert session is not None
            session.close()

    def test_init_db_creates_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "sub", "dir", "test.db")
            init_db(db_path=db_path)
            assert os.path.exists(os.path.join(tmpdir, "sub", "dir"))

    def test_get_session_auto_init(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "auto.db")
            with patch("fusion_security.db.session.DEFAULT_DB_PATH", db_path):
                from fusion_security.db import session as sess

                sess._SessionLocal = None
                sess._engine = None
                s = sess.get_session()
                assert s is not None
                s.close()

    def test_init_async_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "async_test.db")
            init_async_db(db_path=db_path)

    def test_get_async_session_auto_init(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "async_auto.db")
            with patch("fusion_security.db.session.DEFAULT_DB_PATH", db_path):
                from fusion_security.db import session as sess

                sess._AsyncSessionLocal = None
                sess._async_engine = None
                s = sess.get_async_session()
                assert s is not None


class TestMultiDBUrl:
    # A1: SQLite->分布式。多节点走共享库,单机仍 SQLite 默认。

    def test_resolve_url_explicit_path(self):
        from fusion_security.db.session import _resolve_url

        url = _resolve_url(db_path="/tmp/x.db", db_url=None)
        assert url == "sqlite:////tmp/x.db"

    def test_resolve_url_explicit_url_wins(self):
        from fusion_security.db.session import _resolve_url

        url = _resolve_url(db_path="/tmp/x.db", db_url="postgresql://u:p@h:5432/db")
        assert url == "postgresql://u:p@h:5432/db"

    def test_resolve_url_env_override(self, monkeypatch):
        from fusion_security.db.session import DB_PATH_ENV, DB_URL_ENV, _resolve_url

        monkeypatch.setenv(DB_URL_ENV, "postgresql://u:p@h:5432/db")
        monkeypatch.setenv(DB_PATH_ENV, "/tmp/should_be_ignored.db")
        url = _resolve_url(db_path=None, db_url=None)
        assert url == "postgresql://u:p@h:5432/db"

    def test_resolve_url_env_path_fallback(self, monkeypatch):
        from fusion_security.db.session import DB_PATH_ENV, DB_URL_ENV, _resolve_url

        monkeypatch.delenv(DB_URL_ENV, raising=False)
        monkeypatch.setenv(DB_PATH_ENV, "/tmp/env.db")
        url = _resolve_url(db_path=None, db_url=None)
        assert url == "sqlite:////tmp/env.db"

    def test_to_async_url_sqlite(self):
        from fusion_security.db.session import _to_async_url

        assert _to_async_url("sqlite:////tmp/a.db") == "sqlite+aiosqlite:////tmp/a.db"

    def test_to_async_url_postgres(self):
        from fusion_security.db.session import _to_async_url

        assert _to_async_url("postgresql://u:p@h:5432/db") == "postgresql+asyncpg://u:p@h:5432/db"

    def test_to_async_url_already_async(self):
        from fusion_security.db.session import _to_async_url

        assert _to_async_url("postgresql+asyncpg://u:p@h:5432/db") == "postgresql+asyncpg://u:p@h:5432/db"

    def test_init_db_postgres_no_sqlite_pragma(self, monkeypatch):
        # 非 SQLite 库不应挂 SQLite PRAGMA 事件监听,也不走 PRAGMA table_info 迁移。
        # 不真实连 PG:用 mock engine 验证不走 StaticPool/PRAGMA 分支。
        from fusion_security.db import session as sess

        captured = {}

        class FakeEngine:
            def __init__(self):
                self.event_listeners = []

            class metadata:
                @staticmethod
                def create_all(engine):
                    captured["create_all"] = True

        real_create = sess.create_engine

        def fake_create_engine(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return real_create("sqlite://", **{k: v for k, v in kwargs.items() if k == "echo"})

        monkeypatch.setattr(sess, "create_engine", fake_create_engine)
        monkeypatch.setattr(sess, "_migrate_schema", lambda e: captured.setdefault("migrate_sqlite", True))
        monkeypatch.setattr(sess, "_migrate_schema_portable", lambda e: captured.setdefault("migrate_portable", True))
        try:
            sess.init_db(db_url="postgresql://u:p@h:5432/db")
            assert captured["url"] == "postgresql://u:p@h:5432/db"
            assert "poolclass" not in captured["kwargs"]
            assert "connect_args" not in captured["kwargs"]
            assert captured.get("migrate_portable") is True
            assert "migrate_sqlite" not in captured
        finally:
            monkeypatch.setattr(sess, "create_engine", real_create)
            sess._engine = None
            sess._SessionLocal = None


class TestReportGenerator:
    def _make_result(self, vulns=None):
        target = ScanTarget("/tmp/test_project")
        result = ScanResult(target)
        result.files_scanned = 5
        result.duration_ms = 100
        result.summary = "发现 0 个漏洞"
        if vulns:
            result.vulnerabilities = vulns
        return result

    def test_generate_markdown_no_vulns(self):
        rg = ReportGenerator()
        result = self._make_result()
        md = rg.generate_markdown(result)
        assert "代码安全审计报告" in md
        assert "扫描摘要" in md

    def test_generate_markdown_with_vulns(self):
        rg = ReportGenerator()
        v = Vulnerability(
            id="V001",
            title="SQL注入",
            description="desc",
            severity="high",
            confidence=85,
            file_path="app.py",
            line_number=10,
            code_snippet="cursor.execute(sql)",
            rule_id="SQL001",
            cwe_id="CWE-89",
            fix_suggestion="参数化查询",
        )
        result = self._make_result([v])
        md = rg.generate_markdown(result)
        assert "SQL注入" in md
        assert "🟠" in md
        assert "参数化查询" in md

    def test_generate_json(self):
        rg = ReportGenerator()
        result = self._make_result()
        j = rg.generate_json(result)
        data = json.loads(j)
        assert "summary" in data

    def test_generate_html_no_vulns(self):
        rg = ReportGenerator()
        result = self._make_result()
        html = rg.generate_html(result)
        assert "<!DOCTYPE html>" in html
        assert "代码安全审计报告" in html

    def test_generate_html_with_vulns(self):
        rg = ReportGenerator()
        v = Vulnerability(
            id="V001",
            title="XSS",
            description="xss desc",
            severity="critical",
            confidence=90,
            file_path="view.py",
            line_number=5,
            code_snippet="innerHTML = user_input",
            rule_id="XSS001",
            cwe_id="CWE-79",
            fix_suggestion="转义输出",
        )
        result = self._make_result([v])
        html = rg.generate_html(result)
        assert "XSS" in html
        assert "critical" in html
        assert "转义输出" in html

    def test_generate_html_vuln_without_fix(self):
        rg = ReportGenerator()
        v = Vulnerability(
            id="V002",
            title="test",
            description="d",
            severity="low",
            confidence=50,
            file_path="a.py",
            line_number=1,
            code_snippet="code",
        )
        result = self._make_result([v])
        html = rg.generate_html(result)
        assert "test" in html

    def test_save_report_all_formats(self):
        rg = ReportGenerator()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            saved = rg.save_report(result, tmpdir, ["md", "json", "html"])
            assert "markdown" in saved
            assert "json" in saved
            assert "html" in saved
            for path in saved.values():
                assert os.path.exists(path)

    def test_save_report_default_formats(self):
        rg = ReportGenerator()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            saved = rg.save_report(result, tmpdir)
            assert "markdown" in saved
            assert "json" in saved

    def test_save_report_creates_dir(self):
        rg = ReportGenerator()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "nested", "dir")
            saved = rg.save_report(result, out, ["md"])
            assert os.path.exists(saved["markdown"])


class TestCLI:
    def test_rules_command(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "检测规则" in result.output

    def test_scan_no_ai(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai"])
            assert result.exit_code == 0
            assert "Fusion-Security" in result.output

    def test_scan_with_severity(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--severity", "high"])
            assert result.exit_code == 0

    def test_scan_with_output(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            out_dir = os.path.join(tmpdir, "reports")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--output", out_dir])
            assert result.exit_code == 0

    def test_scan_json_format(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--format", "json"])
            assert result.exit_code == 0

    def test_check_command(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["check", tmpdir])
            assert result.exit_code == 0
            json_line = [line for line in result.output.splitlines() if line.startswith("{")]
            assert len(json_line) >= 1
            data = json.loads(json_line[0])
            assert "vulnerabilities" in data

    def test_sarif_command(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            out = os.path.join(tmpdir, "results.sarif")
            result = runner.invoke(cli, ["sarif", tmpdir, "--output", out])
            assert result.exit_code == 0

    def test_scan_pipeline_mode(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--pipeline"])
            assert result.exit_code == 0

    def test_scan_sca_mode(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--sca"])
            assert result.exit_code == 0

    def test_scan_incremental_fallback(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--incremental"])
            assert result.exit_code == 0

    def test_scan_html_format(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--format", "html"])
            assert result.exit_code == 0

    def test_scan_all_format(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            out_dir = os.path.join(tmpdir, "reports")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--format", "all", "--output", out_dir])
            assert result.exit_code == 0

    def test_verbose_flag(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["-v", "scan", tmpdir, "--no-ai"])
            assert result.exit_code == 0

    def test_scan_with_vulns_found(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "vuln.py"
            test_file.write_text("import os\nos.system(user_input)\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai"])
            assert result.exit_code == 0

    def test_gate_command_pass(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "safe.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["gate", tmpdir, "--policy", "permissive"])
            assert result.exit_code == 0

    def test_gate_command_fail(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "bad.py"
            test_file.write_text("password = 'hardcoded_secret_123'\n")
            result = runner.invoke(cli, ["gate", tmpdir, "--policy", "strict"])
            assert result.exit_code == 1

    def test_scan_with_model_option(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", tmpdir, "--no-ai", "--model", "test-model"])
            assert result.exit_code == 0
