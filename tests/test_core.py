"""Fusion-Security 核心测试。"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from fusion_security.engine.rules.engine import RuleEngine, ScanRule
from fusion_security.models import Vulnerability
from fusion_security.engine.scanner import Scanner, ScanTarget, ScanResult
from fusion_security.report.report import ReportGenerator
from fusion_security.engine.fix.fix_generator import FixGenerator
from fusion_security.models.patch import Patch as FixPatch


class TestRuleEngine:
    def setup_method(self):
        self.engine = RuleEngine()

    def test_rule_count(self):
        assert self.engine.get_rule_count() >= 10

    def test_scan_sql_injection(self):
        content = 'cursor.execute("SELECT * FROM users WHERE id = " + user_input)'
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            findings = self.engine.scan_file(path, content)
            sql_findings = [f for f in findings if f.rule_id == "SQL001"]
            assert len(sql_findings) >= 1
        finally:
            path.unlink()

    def test_scan_hardcoded_secret(self):
        content = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"'
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            findings = self.engine.scan_file(path, content)
            secret_findings = [f for f in findings if f.rule_id == "SEC002"]
            assert len(secret_findings) >= 1
        finally:
            path.unlink()

    def test_scan_clean_file(self):
        content = "def hello():\n    print('Hello, world!')\n"
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            findings = self.engine.scan_file(path, content)
            assert len(findings) == 0
        finally:
            path.unlink()

    def test_scan_xss(self):
        content = 'element.innerHTML = user_input'
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False, mode="w") as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            findings = self.engine.scan_file(path, content)
            xss_findings = [f for f in findings if "XSS" in f.rule_id]
            assert len(xss_findings) >= 1
        finally:
            path.unlink()

    def test_scan_command_injection(self):
        content = 'os.system("rm -rf " + user_input)'
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            findings = self.engine.scan_file(path, content)
            cmd_findings = [f for f in findings if "CMD" in f.rule_id]
            assert len(cmd_findings) >= 1
        finally:
            path.unlink()

    def test_add_custom_rule(self):
        rule = ScanRule(
            id="CUSTOM001", name="自定义规则", description="测试",
            severity="high", cwe_id="CWE-000", pattern=r"dangerous_func"
        )
        self.engine.add_rule(rule)
        assert self.engine.get_rule_count() >= 11

    def test_get_rules_by_category(self):
        rules = self.engine.get_rules(category="injection")
        assert len(rules) >= 0


class TestScanner:
    @pytest.mark.asyncio
    async def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # 创建测试文件
            Path(tmpdir, "safe.py").write_text("def hello():\n    print('ok')\n")
            Path(tmpdir, "vuln.py").write_text(
                'import os\nos.system("rm -rf " + user_input)\n'
            )

            scanner = Scanner(use_ai=False)
            result = await scanner.scan_directory(tmpdir)

            assert result.files_scanned >= 2
            assert len(result.vulnerabilities) >= 1

    @pytest.mark.asyncio
    async def test_scan_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = Scanner(use_ai=False)
            result = await scanner.scan_directory(tmpdir)
            assert result.files_scanned == 0
            assert len(result.vulnerabilities) == 0

    def test_scan_result_to_dict(self):
        result = ScanResult(ScanTarget("."))
        result.files_scanned = 10
        result.duration_ms = 100.0
        d = result.to_dict()
        assert d["files_scanned"] == 10
        assert d["duration_ms"] == 100.0


class TestReportGenerator:
    def test_generate_markdown(self):
        result = ScanResult(ScanTarget("/test"))
        result.files_scanned = 5
        result.duration_ms = 50.0
        result.summary = "✅ 未发现安全漏洞"

        gen = ReportGenerator()
        md = gen.generate_markdown(result)
        assert "安全审计报告" in md
        assert "未发现安全漏洞" in md

    def test_generate_json(self):
        result = ScanResult(ScanTarget("/test"))
        result.files_scanned = 3
        gen = ReportGenerator()
        js = gen.generate_json(result)
        assert '"files_scanned"' in js

    def test_save_report(self, tmp_path):
        result = ScanResult(ScanTarget("/test"))
        result.files_scanned = 1
        gen = ReportGenerator()
        saved = gen.save_report(result, str(tmp_path), formats=["md"])
        assert "markdown" in saved


class TestFixGenerator:
    def test_generate_fix(self):
        vuln = Vulnerability(
            id="TEST001", title="SQL注入", description="测试",
            severity="high", confidence=90,
            file_path="/tmp/test.py", line_number=1,
            code_snippet="cursor.execute(sql)",
            rule_id="SQL001",
        )
        gen = FixGenerator()
        patch = gen.generate_fix(vuln)
        assert isinstance(patch, FixPatch)
        assert patch.vuln_id == "TEST001"

    def test_fix_patch_to_diff(self):
        vuln = Vulnerability(
            id="T1", title="Test", description="", severity="low",
            confidence=50, file_path="/tmp/t.py", line_number=1,
            code_snippet="old code",
        )
        patch = FixPatch(vuln_id="T1", original_code="old code", patched_code="new code")
        diff = patch.to_diff()
        assert "old code" in diff
        assert "new code" in diff


class TestVulnerability:
    def test_to_dict(self):
        vuln = Vulnerability(
            id="V1", title="Test", description="Desc",
            severity="high", confidence=95,
            file_path="/tmp/test.py", line_number=10,
            code_snippet="code here",
        )
        d = vuln.to_dict()
        assert d["id"] == "V1"
        assert d["severity"] == "high"
        assert d["confidence"] == 95