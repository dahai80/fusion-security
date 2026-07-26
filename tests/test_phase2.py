"""Tests for Phase 2: Pipeline + SCA + CI integrations."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fusion_security.engine.pipeline import (
    PipelineConfig,
    PipelineContext,
    PipelineStage,
    ScanPipeline,
)
from fusion_security.engine.sca.scanner import (
    Dependency,
    KnownVuln,
    KNOWN_VULNS,
    SCAScanner,
)


class TestSCAScanner:
    def test_parse_requirements(self):
        scanner = SCAScanner()
        content = "flask==2.2.0\nurllib3>=2.0.5\n# comment\nrequests>=2.28.0\n"
        deps = scanner._parse_requirements("/tmp/req.txt", content)
        assert len(deps) == 3
        assert deps[0].name == "flask"
        assert deps[0].version == "2.2.0"
        assert deps[0].ecosystem == "pypi"

    def test_parse_package_json(self):
        scanner = SCAScanner()
        content = json.dumps({
            "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        })
        deps = scanner._parse_package_json("/tmp/pkg.json", content)
        assert len(deps) == 3
        npm_deps = [d for d in deps if d.ecosystem == "npm"]
        assert len(npm_deps) == 3
        dev_deps = [d for d in deps if d.is_dev]
        assert len(dev_deps) == 1
        assert dev_deps[0].name == "jest"

    def test_parse_gomod(self):
        scanner = SCAScanner()
        content = "module example\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/text v0.3.7\n)\n"
        deps = scanner._parse_gomod("/tmp/go.mod", content)
        assert len(deps) == 2
        assert deps[0].ecosystem == "gomod"
        assert deps[1].version == "0.3.7"

    def test_parse_cargo(self):
        scanner = SCAScanner()
        content = '[package]\nname = "test"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\ntokio = "1.32"\n'
        deps = scanner._parse_cargo("/tmp/Cargo.toml", content)
        assert len(deps) == 2
        assert deps[0].ecosystem == "cargo"

    def test_parse_gemfile(self):
        scanner = SCAScanner()
        content = "source 'https://rubygems.org'\ngem 'rails', '7.0.0'\ngem 'puma'\n"
        deps = scanner._parse_gemfile("/tmp/Gemfile", content)
        assert len(deps) == 2
        assert deps[0].ecosystem == "rubygems"
        assert deps[0].version == "7.0.0"

    def test_check_vulnerabilities(self):
        scanner = SCAScanner()
        deps = [
            Dependency(name="urllib3", version="2.0.5", ecosystem="pypi"),
            Dependency(name="flask", version="2.2.0", ecosystem="pypi"),
            Dependency(name="numpy", version="1.24.0", ecosystem="pypi"),
        ]
        vulns = scanner.check_vulnerabilities(deps)
        vuln_names = [v.title for v in vulns]
        assert any("urllib3" in n for n in vuln_names)
        assert any("flask" in n for n in vuln_names)
        assert not any("numpy" in n for n in vuln_names)

    def test_scan_with_temp_project(self):
        scanner = SCAScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("flask==2.2.0\n")
            vulns = scanner.scan(tmpdir)
            assert len(vulns) >= 1
            assert any("flask" in v.title for v in vulns)

    def test_version_comparison(self):
        scanner = SCAScanner()
        assert scanner._parse_version("2.0.5") == (2, 0, 5)
        assert scanner._parse_version("1.0") == (1, 0)

    def test_is_affected(self):
        scanner = SCAScanner()
        dep = Dependency(name="urllib3", version="2.0.5", ecosystem="pypi")
        kv = KnownVuln("CVE-TEST", "urllib3", "<2.0.7", "high", "test", "2.0.7")
        assert scanner._is_affected(dep, kv) is True
        dep2 = Dependency(name="urllib3", version="2.0.7", ecosystem="pypi")
        assert scanner._is_affected(dep2, kv) is False

    def test_skip_git_node_modules(self):
        scanner = SCAScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir) / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "package.json").write_text('{"dependencies": {"lodash": "4.17.0"}}')
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("flask==2.2.0\n")
            deps = scanner.collect_dependencies(tmpdir)
            assert not any("node_modules" in d.source_file for d in deps)


class TestPipeline:
    def test_pipeline_config_defaults(self):
        config = PipelineConfig()
        assert config.use_ai is True
        assert config.enable_sca is True
        assert config.enable_taint is True
        assert config.batch_size == 50

    def test_pipeline_context_auto_id(self):
        ctx = PipelineContext()
        assert ctx.scan_id.startswith("scan_")
        assert ctx.current_stage == PipelineStage.RECON

    def test_pipeline_no_ai(self):
        config = PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False)
        pipeline = ScanPipeline(config)
        assert pipeline.ai_analyzer is None
        assert pipeline.adversarial is None
        assert pipeline.sca_scanner is None

    @pytest.mark.asyncio
    async def test_pipeline_run_no_ai(self):
        config = PipelineConfig(
            use_ai=False, enable_adversarial=False,
            enable_sca=False, enable_taint=False, enable_patch=False,
        )
        pipeline = ScanPipeline(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            py = Path(tmpdir) / "test.py"
            py.write_text("query = 'SELECT * FROM users WHERE id=' + user_input")
            ctx = await pipeline.run(tmpdir)
            assert ctx.scan_id
            assert len(ctx.files) >= 1
            assert ctx.stage_results.get("recon")

    @pytest.mark.asyncio
    async def test_pipeline_to_scan_result(self):
        config = PipelineConfig(
            use_ai=False, enable_adversarial=False,
            enable_sca=False, enable_taint=False, enable_patch=False,
        )
        pipeline = ScanPipeline(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            py = Path(tmpdir) / "test.py"
            py.write_text("x = 1")
            ctx = await pipeline.run(tmpdir)
            result = pipeline.to_scan_result(ctx)
            assert result.files_scanned >= 1

    def test_detect_language(self):
        pipeline = ScanPipeline(PipelineConfig(use_ai=False, enable_adversarial=False, enable_sca=False))
        assert pipeline._detect_language(Path("foo.py")) == "python"
        assert pipeline._detect_language(Path("foo.js")) == "javascript"
        assert pipeline._detect_language(Path("foo.go")) == "go"
        assert pipeline._detect_language(Path("foo.rs")) == "rust"
        assert pipeline._detect_language(Path("foo.xyz")) == "unknown"

    @pytest.mark.asyncio
    async def test_pipeline_sca_integration(self):
        config = PipelineConfig(
            use_ai=False, enable_adversarial=False,
            enable_sca=True, enable_taint=False, enable_patch=False,
        )
        pipeline = ScanPipeline(config)
        assert pipeline.sca_scanner is not None
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("flask==2.2.0\n")
            py = Path(tmpdir) / "app.py"
            py.write_text("from flask import Flask")
            ctx = await pipeline.run(tmpdir)
            sca_vulns = [v for v in ctx.vulnerabilities if v.rule_id == "FUS-SCA-001"]
            assert len(sca_vulns) >= 1
