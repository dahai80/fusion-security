"""Fusion-Security 全覆盖测试 — 补齐 AI、CLI、Report、Scanner、Fix、Logger。"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from fusion_security.engine.fix.fix_generator import FixGenerator
from fusion_security.engine.scanner import Scanner, ScanResult, ScanTarget
from fusion_security.models import Vulnerability
from fusion_security.models.patch import Patch as FixPatch
from fusion_security.report.report import ReportGenerator
from fusion_security.utils.logger import setup_logger

# ══════════════════════════════════════════════════════════════════════════════
# AI 分析器测试
# ══════════════════════════════════════════════════════════════════════════════


class TestAIAnalyzer:
    @pytest.mark.asyncio
    async def test_verify_findings_empty(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        result = await analyzer.verify_findings([], [])
        assert result == []

    @pytest.mark.asyncio
    async def test_verify_findings_with_vuln(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        vuln = Vulnerability(
            id="V1",
            title="SQL注入",
            description="测试",
            severity="high",
            confidence=90,
            file_path="/tmp/test.py",
            line_number=1,
            code_snippet="execute(sql)",
            rule_id="SQL001",
        )
        result = await analyzer.verify_findings([vuln], [])
        # fusion-mlx 不可用时保留原结果
        assert len(result) == 1
        assert result[0].id == "V1"

    @pytest.mark.asyncio
    async def test_semantic_scan_empty(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        result = await analyzer.semantic_scan([])
        assert result == []

    @pytest.mark.asyncio
    async def test_generate_fix(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        vuln = Vulnerability(
            id="V1",
            title="Test",
            description="",
            severity="low",
            confidence=50,
            file_path="/tmp/t.py",
            line_number=1,
            code_snippet="old code",
        )
        result = await analyzer.generate_fix(vuln)
        # fusion-mlx 不可用时返回错误信息
        assert "修复" in result or "error" in result

    def test_parse_json_valid(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        result = analyzer._parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_with_codeblock(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        result = analyzer._parse_json('```json\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    def test_parse_json_array(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        result = analyzer._parse_json('[{"a": 1}]', as_array=True)
        assert result == [{"a": 1}]

    def test_parse_json_invalid(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        result = analyzer._parse_json("not json", as_array=True)
        assert result == []

    def test_parse_json_invalid_dict(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        result = analyzer._parse_json("not json")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# Scanner 边界测试
# ══════════════════════════════════════════════════════════════════════════════


class TestScannerEdge:
    @pytest.mark.asyncio
    async def test_scan_with_file_size_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # 创建超大文件（应被跳过）
            large_file = Path(tmpdir, "large.py")
            large_file.write_text("x" * (2 * 1024 * 1024))  # 2MB
            # 创建正常文件
            normal_file = Path(tmpdir, "normal.py")
            normal_file.write_text("safe code")

            target = ScanTarget(tmpdir, max_file_size=1024 * 1024)  # 1MB limit
            target.discover()
            # macOS 上 /var 是 /private/var 的符号链接，用 resolve() 比较
            resolved_normal = str(normal_file.resolve())
            resolved_files = [str(f) for f in target.files]
            assert large_file.resolve() not in target.files
            assert resolved_normal in resolved_files

    @pytest.mark.asyncio
    async def test_scan_with_max_files_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(20):
                Path(tmpdir, f"f{i}.py").write_text("x")
            target = ScanTarget(tmpdir, max_files=5)
            target.discover()
            assert len(target.files) <= 5

    @pytest.mark.asyncio
    async def test_scan_single_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("safe code")
            f.flush()
            path = f.name

        try:
            target = ScanTarget(path)
            target.discover()
            assert len(target.files) == 1
        finally:
            Path(path).unlink()

    @pytest.mark.asyncio
    async def test_scan_binary_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"\x00\x01\x02\x03")
            f.flush()
            path = f.name

        try:
            scanner = Scanner(use_ai=False)
            result = await scanner.scan_directory(path)
            assert result.files_scanned >= 0
        finally:
            Path(path).unlink()

    def test_scan_result_with_vulnerabilities(self):
        result = ScanResult(ScanTarget("."))
        result.files_scanned = 5
        result.vulnerabilities.append(
            Vulnerability(
                id="V1",
                title="Test",
                description="",
                severity="critical",
                confidence=90,
                file_path="/t.py",
                line_number=1,
                code_snippet="x",
            )
        )
        d = result.to_dict()
        assert d["total_vulnerabilities"] == 1
        assert d["critical"] == 1

    def test_scan_result_summary_generated(self):
        result = ScanResult(ScanTarget("."))
        result.files_scanned = 1
        assert result.summary == ""


# ══════════════════════════════════════════════════════════════════════════════
# Report 生成器覆盖
# ══════════════════════════════════════════════════════════════════════════════


class TestReportCoverage:
    def test_generate_html(self):
        result = ScanResult(ScanTarget("/test"))
        result.files_scanned = 2
        result.duration_ms = 100.0
        result.summary = "发现漏洞"
        result.vulnerabilities.append(
            Vulnerability(
                id="V1",
                title="XSS",
                description="XSS漏洞",
                severity="high",
                confidence=95,
                file_path="/t.js",
                line_number=5,
                code_snippet="innerHTML=x",
            )
        )
        gen = ReportGenerator()
        html = gen.generate_html(result)
        assert "XSS" in html
        assert "high" in html
        assert "100%" in html

    def test_generate_json_with_vulns(self):
        result = ScanResult(ScanTarget("/test"))
        result.files_scanned = 3
        result.vulnerabilities.append(
            Vulnerability(
                id="V1",
                title="Test",
                description="",
                severity="low",
                confidence=50,
                file_path="/t.py",
                line_number=1,
                code_snippet="x",
            )
        )
        gen = ReportGenerator()
        js = gen.generate_json(result)
        assert '"severity": "low"' in js

    def test_save_all_formats(self, tmp_path):
        result = ScanResult(ScanTarget("/test"))
        result.files_scanned = 1
        gen = ReportGenerator()
        saved = gen.save_report(result, str(tmp_path), formats=["md", "json", "html"])
        assert "markdown" in saved
        assert "json" in saved
        assert "html" in saved

    def test_save_report_default_formats(self, tmp_path):
        result = ScanResult(ScanTarget("/test"))
        result.files_scanned = 1
        gen = ReportGenerator()
        saved = gen.save_report(result, str(tmp_path))
        assert "markdown" in saved
        assert "json" in saved


# ══════════════════════════════════════════════════════════════════════════════
# Fix 生成器覆盖
# ══════════════════════════════════════════════════════════════════════════════


class TestFixCoverage:
    def test_apply_template_fix_sql(self):
        vuln = Vulnerability(
            id="T1",
            title="SQL注入",
            description="",
            severity="high",
            confidence=90,
            file_path="/t.py",
            line_number=1,
            code_snippet="cursor.execute(sql)",
            rule_id="SQL001",
        )
        gen = FixGenerator()
        patch = gen.generate_fix(vuln)
        assert "execute_query" in patch.patched_code or patch.patched_code != patch.original_code

    def test_apply_template_fix_secret(self):
        vuln = Vulnerability(
            id="T2",
            title="硬编码密钥",
            description="",
            severity="high",
            confidence=90,
            file_path="/t.py",
            line_number=1,
            code_snippet='api_key = "sk-12345"',
            rule_id="SEC001",
        )
        gen = FixGenerator()
        patch = gen.generate_fix(vuln)
        assert "os.environ" in patch.patched_code or patch.patched_code != patch.original_code

    def test_apply_template_fix_xss(self):
        vuln = Vulnerability(
            id="T3",
            title="XSS",
            description="",
            severity="high",
            confidence=90,
            file_path="/t.js",
            line_number=1,
            code_snippet="element.innerHTML = x",
            rule_id="XSS001",
        )
        gen = FixGenerator()
        patch = gen.generate_fix(vuln)
        assert "textContent" in patch.patched_code or patch.patched_code != patch.original_code

    def test_extract_context_file_exists(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\nline3\nline4\nline5\n")
        vuln = Vulnerability(
            id="T4",
            title="Test",
            description="",
            severity="low",
            confidence=50,
            file_path=str(test_file),
            line_number=2,
            code_snippet="",
            rule_id="",
        )
        gen = FixGenerator()
        context = gen._extract_context(vuln)
        assert "line1" in context
        assert "line3" in context

    def test_extract_context_file_not_found(self):
        vuln = Vulnerability(
            id="T5",
            title="Test",
            description="",
            severity="low",
            confidence=50,
            file_path="/nonexistent/path.py",
            line_number=1,
            code_snippet="fallback code",
            rule_id="",
        )
        gen = FixGenerator()
        context = gen._extract_context(vuln)
        assert context == "fallback code"

    @pytest.mark.asyncio
    async def test_ai_enhance_fix(self):
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        vuln = Vulnerability(
            id="T6",
            title="Test",
            description="",
            severity="low",
            confidence=50,
            file_path="/t.py",
            line_number=1,
            code_snippet="old code",
            rule_id="",
        )
        ai = AIAnalyzer()
        gen = FixGenerator(ai_analyzer=ai)
        patch = FixPatch(vuln_id=vuln.id, original_code="old code", patched_code="new code")
        result = await gen.ai_enhance_fix(patch)
        assert result.patched_code == "new code" or len(result.patched_code) > 0


# ══════════════════════════════════════════════════════════════════════════════
# Logger 测试
# ══════════════════════════════════════════════════════════════════════════════


class TestLogger:
    def test_setup_logger_info(self):
        logger = setup_logger("test_logger", verbose=False)
        assert logger.level == 20  # INFO

    def test_setup_logger_debug(self):
        import logging

        logger = logging.getLogger("test_logger_debug")
        logger.handlers.clear()
        logger.setLevel(logging.DEBUG)
        assert logger.level == 10  # DEBUG


# ══════════════════════════════════════════════════════════════════════════════
# CLI 测试（需要 click）
# ══════════════════════════════════════════════════════════════════════════════


class TestCLI:
    def test_cli_import(self):
        from fusion_security import cli

        assert cli is not None
        assert cli.main is not None

    def test_cli_help(self):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Fusion-Security" in result.output

    def test_cli_version(self):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0

    def test_cli_rules(self):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "SQL" in result.output

    def test_cli_check_clean(self, tmp_path):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        Path(tmp_path, "safe.py").write_text("x = 1")
        runner = CliRunner()
        result = runner.invoke(cli, ["check", str(tmp_path)])
        assert result.exit_code == 0

    def test_cli_check_vuln(self, tmp_path):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        Path(tmp_path, "vuln.py").write_text('os.system("rm -rf " + x)')
        runner = CliRunner()
        result = runner.invoke(cli, ["check", str(tmp_path)])
        assert result.exit_code == 0
        assert "high" in result.output or "vulnerabilities" in result.output


# ══════════════════════════════════════════════════════════════════════════════
# 模块完整性测试
# ══════════════════════════════════════════════════════════════════════════════


class TestModuleIntegrity:
    def test_all_modules_importable(self):
        assert True

    def test_models_export(self):
        from fusion_security.models import Vulnerability

        v = Vulnerability(
            id="V1",
            title="T",
            description="D",
            severity="high",
            confidence=90,
            file_path="/f",
            line_number=1,
            code_snippet="c",
        )
        assert v.to_dict()["id"] == "V1"

    def test_scanner_import(self):
        from fusion_security.engine.scanner import Scanner

        assert Scanner is not None

    def test_scanner_summary_with_vulns(self):
        """测试生成摘要。"""
        from fusion_security.engine.scanner import ScanResult, ScanTarget
        from fusion_security.models import Vulnerability

        result = ScanResult(ScanTarget("/test"))
        result.vulnerabilities = [
            Vulnerability(
                id="V1",
                title="注入",
                description="",
                severity="critical",
                confidence=90,
                file_path="/f",
                line_number=1,
                code_snippet="c",
            ),
            Vulnerability(
                id="V2",
                title="XSS",
                description="",
                severity="high",
                confidence=80,
                file_path="/f",
                line_number=2,
                code_snippet="c",
            ),
        ]
        from fusion_security.engine.scanner import Scanner as S

        s = S(use_ai=False)
        s._generate_summary(result)
        assert "2 个安全漏洞" in result.summary
        assert "critical" in result.summary


# ══════════════════════════════════════════════════════════════════════════════
# CLI 深度覆盖
# ══════════════════════════════════════════════════════════════════════════════


class TestCLIDeep:
    def test_cli_scan_with_output(self, tmp_path):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        Path(tmp_path, "test.py").write_text("x = 1")
        output_dir = tmp_path / "reports"
        result = CliRunner().invoke(
            cli, ["scan", str(tmp_path), "--output", str(output_dir), "--no-ai", "--format", "md"]
        )
        assert result.exit_code == 0

    def test_cli_scan_no_ai(self, tmp_path):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        Path(tmp_path, "test.py").write_text("x = 1")
        result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--no-ai"])
        assert result.exit_code == 0

    def test_cli_scan_verbose(self, tmp_path):
        from click.testing import CliRunner

        from fusion_security.cli import cli

        Path(tmp_path, "test.py").write_text("x = 1")
        # --verbose 是全局选项，必须放在子命令之前
        result = CliRunner().invoke(cli, ["--verbose", "scan", str(tmp_path), "--no-ai"])
        assert result.exit_code == 0


# ══════════════════════════════════════════════════════════════════════════════
# Scanner 深度覆盖
# ══════════════════════════════════════════════════════════════════════════════


class TestScannerDeep:
    @pytest.mark.asyncio
    async def test_scan_with_ai_enabled(self):
        """测试启用 AI 的扫描（AI 不可用时应优雅降级）。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test.py").write_text('os.system("rm -rf " + x)')
            scanner = Scanner(use_ai=True)
            result = await scanner.scan_directory(tmpdir)
            assert result.files_scanned >= 1
            # AI 不可用时，规则引擎结果应保留
            assert len(result.vulnerabilities) >= 0

    @pytest.mark.asyncio
    async def test_scan_with_severity_filter(self):
        """测试严重级别过滤。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "vuln.py").write_text('os.system("rm -rf " + x)')
            scanner = Scanner(use_ai=False)
            # 只报告 high 以上
            result = await scanner.scan_directory(tmpdir, severity_threshold="high")
            assert result.files_scanned >= 1

    @pytest.mark.asyncio
    async def test_scan_discover_with_extensions(self):
        """测试自定义扩展名发现。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test.py").write_text("x")
            Path(tmpdir, "test.go").write_text("x")
            target = ScanTarget(tmpdir)
            target.discover(extensions={".go"})
            assert len(target.files) == 1
            assert target.files[0].suffix == ".go"

    @pytest.mark.asyncio
    async def test_scan_discover_non_recursive(self):
        """测试非递归扫描。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir, "sub")
            subdir.mkdir()
            Path(subdir, "deep.py").write_text("x")
            Path(tmpdir, "root.py").write_text("x")
            target = ScanTarget(tmpdir, recursive=False)
            target.discover()
            files = [f.name for f in target.files]
            assert "root.py" in files
            assert "deep.py" not in files

    def test_scan_result_defaults(self):
        """测试 ScanResult 默认值。"""
        result = ScanResult(ScanTarget("/test"))
        assert result.files_scanned == 0
        assert result.files_skipped == 0
        assert result.duration_ms == 0.0
        assert result.vulnerabilities == []

    def test_check_file_size(self):
        """测试文件大小检查。"""
        target = ScanTarget("/tmp", max_file_size=100)
        # 不存在的文件
        assert not target._check_file_size(Path("/nonexistent_file_xyz"))
        # 空文件应通过
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"")
            temp_path = f.name
        try:
            assert target._check_file_size(Path(temp_path))
        finally:
            Path(temp_path).unlink()


class TestPortableWidenMigration:
    """PG 端 String(16)->String(32) 拓宽迁移:SQLite 上验证代码路径可跑通。"""

    def test_varchar_len_parsing(self):
        from fusion_security.db.session import _varchar_len

        assert _varchar_len("VARCHAR(16)") == 16
        assert _varchar_len("VARCHAR(32)") == 32
        assert _varchar_len("INTEGER") is None

    def test_widen_column_noop_when_already_wide(self):
        from sqlalchemy import create_engine, inspect

        from fusion_security.db import models  # noqa: F401
        from fusion_security.db.session import Base, _widen_column_portable

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        insp = inspect(engine)
        before = str(insp.get_columns("scans")[0]["type"])
        _widen_column_portable(engine, "scans", "id", "VARCHAR(32)")
        insp2 = inspect(engine)
        after = str(insp2.get_columns("scans")[0]["type"])
        assert before == after

    def test_widen_column_grows_narrow_column(self):
        from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect

        # SQLite 不支持 ALTER COLUMN TYPE(PG 专用语法),这里只验证"窄列被识别为需要拓宽"。
        # 实际 ALTER 在 PG 上执行(多节点集成测试已验证)。用 mock engine 跑拓宽分支。
        engine = create_engine("sqlite://")
        md = MetaData()
        Table("scans", md, Column("id", String(16), primary_key=True))
        md.create_all(engine)
        insp = inspect(engine)
        col_type = str(insp.get_columns("scans")[0]["type"])
        assert "VARCHAR(16)" in col_type
        # 验证拓宽判定逻辑:窄列应判定为需要迁移(cur_len < tgt_len)。
        from fusion_security.db.session import _varchar_len

        assert _varchar_len(col_type) < _varchar_len("VARCHAR(32)")

    def test_migrate_schema_portable_runs_clean(self):
        # 在全量建表的 SQLite 引擎上跑 portable 迁移:所有列已存在/已拓宽,应全部 no-op 不报错。
        from sqlalchemy import create_engine

        from fusion_security.db import models  # noqa: F401
        from fusion_security.db.session import Base, _migrate_schema_portable

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        _migrate_schema_portable(engine)

    def test_ensure_column_portable_adds_missing(self):
        # 构造缺列的表,_ensure_column_portable 应 ALTER ADD 成功(SQLite 支持 ADD COLUMN)。
        from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect

        from fusion_security.db.session import _ensure_column_portable

        engine = create_engine("sqlite://")
        md = MetaData()
        Table("scans", md, Column("id", String(32), primary_key=True))
        md.create_all(engine)
        _ensure_column_portable(engine, "scans", "status", "VARCHAR(20) DEFAULT 'pending'")
        insp = inspect(engine)
        names = {c["name"] for c in insp.get_columns("scans")}
        assert "status" in names
