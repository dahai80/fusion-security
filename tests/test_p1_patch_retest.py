from __future__ import annotations

import pytest

from fusion_security.engine.fix.fix_generator import FixGenerator
from fusion_security.models.patch import Patch
from fusion_security.models.vulnerability import Vulnerability


def _make_vuln(rule_id="SQL001", code="cursor.execute(query)"):
    return Vulnerability(
        id="V-test",
        title="Test vuln",
        description="test",
        severity="high",
        confidence=80,
        file_path="test.py",
        line_number=1,
        code_snippet=code,
        rule_id=rule_id,
    )


class TestFixGeneratorAlternatives:
    def test_generate_alternatives_returns_multiple(self):
        gen = FixGenerator()
        vuln = _make_vuln()
        patches = gen.generate_alternatives(vuln)
        assert len(patches) >= 1
        for p in patches:
            assert isinstance(p, Patch)
            assert p.vuln_id == vuln.id
            assert p.patched_code

    def test_generate_alternatives_sql(self):
        gen = FixGenerator()
        vuln = _make_vuln("SQL001", "cursor.execute(query)")
        patches = gen.generate_alternatives(vuln)
        strategies = [p.strategy for p in patches]
        assert "template" in strategies

    def test_generate_alternatives_cmd(self):
        gen = FixGenerator()
        vuln = _make_vuln("CMD001", "os.system(cmd)")
        patches = gen.generate_alternatives(vuln)
        assert len(patches) >= 1
        assert any("subprocess" in p.patched_code for p in patches)

    def test_generate_alternatives_xss(self):
        gen = FixGenerator()
        vuln = _make_vuln("XSS001", "el.innerHTML = data")
        patches = gen.generate_alternatives(vuln)
        assert any("textContent" in p.patched_code for p in patches)

    def test_generate_alternatives_unknown_rule(self):
        gen = FixGenerator()
        vuln = _make_vuln("UNKNOWN999", "some code")
        patches = gen.generate_alternatives(vuln)
        assert len(patches) >= 1
        assert patches[0].strategy == "placeholder"

    def test_max_strategies_limit(self):
        gen = FixGenerator()
        vuln = _make_vuln("SQL001", "cursor.execute(query)")
        patches = gen.generate_alternatives(vuln, max_strategies=1)
        assert len(patches) <= 1

    def test_generate_fix_still_works(self):
        gen = FixGenerator()
        vuln = _make_vuln()
        patch = gen.generate_fix(vuln)
        assert isinstance(patch, Patch)
        assert patch.strategy == "template"


class TestPipelineRetest:
    @pytest.mark.asyncio
    async def test_retest_stage_no_patches(self):
        from fusion_security.engine.pipeline import PipelineContext, ScanPipeline

        pipeline = ScanPipeline()
        ctx = PipelineContext(project_path="/tmp/nonexistent")
        await pipeline._stage_retest(ctx)
        assert "retest" in ctx.stage_results
        assert ctx.stage_results["retest"]["retested"] == 0

    @pytest.mark.asyncio
    async def test_retest_stage_with_verified_patch(self):
        from fusion_security.engine.pipeline import PipelineContext, ScanPipeline

        pipeline = ScanPipeline()
        ctx = PipelineContext(project_path="/tmp/nonexistent")
        patch = Patch()
        patch.vuln_id = "V-test"
        patch.status = "applied"
        patch.patched_code = "safe_code_no_match()"
        ctx.patches.append(patch)
        vuln = _make_vuln()
        vuln.rule_id = "SQL001"
        ctx.vulnerabilities.append(vuln)
        await pipeline._stage_retest(ctx)
        result = ctx.stage_results["retest"]
        assert result["retested"] == 1
        assert result["passed"] >= 1

    @pytest.mark.asyncio
    async def test_retest_stage_patch_still_vulnerable(self):
        from fusion_security.engine.pipeline import PipelineContext, ScanPipeline

        pipeline = ScanPipeline()
        ctx = PipelineContext(project_path="/tmp/nonexistent")
        patch = Patch()
        patch.vuln_id = "V-test"
        patch.status = "applied"
        patch.patched_code = "cursor.execute(query)"
        ctx.patches.append(patch)
        vuln = _make_vuln("SQL001", "cursor.execute(query)")
        ctx.vulnerabilities.append(vuln)
        await pipeline._stage_retest(ctx)
        result = ctx.stage_results["retest"]
        assert result["retested"] == 1
        assert result["failed"] >= 1

    @pytest.mark.asyncio
    async def test_retest_skips_non_applied_patches(self):
        from fusion_security.engine.pipeline import PipelineContext, ScanPipeline

        pipeline = ScanPipeline()
        ctx = PipelineContext(project_path="/tmp/nonexistent")
        patch = Patch()
        patch.vuln_id = "V-test"
        patch.status = "draft"
        ctx.patches.append(patch)
        await pipeline._stage_retest(ctx)
        result = ctx.stage_results["retest"]
        assert result["retested"] == 0
