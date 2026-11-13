"""Tests for P3.2 compliance mapping profiles (EU AI Act + report section)."""

from __future__ import annotations

import pytest

from fusion_security.engine.scoring.compliance import (
    EU_AI_ACT_TIMELINE,
    FRAMEWORK_PROFILES,
    ComplianceMapper,
    build_compliance_section,
)
from fusion_security.models import Vulnerability


def _vuln(rule_id: str, severity: str = "high") -> Vulnerability:
    return Vulnerability(
        id=f"V-{rule_id}",
        title="t",
        description="d",
        severity=severity,
        confidence=80,
        file_path="a.py",
        line_number=1,
        code_snippet="x",
        rule_id=rule_id,
    )


class TestProfiles:
    def test_framework_profiles_complete(self):
        for fw in ("dengbao", "iso27001", "pci_dss", "eu_ai_act"):
            assert fw in FRAMEWORK_PROFILES
            assert FRAMEWORK_PROFILES[fw]["name"]

    def test_eu_timeline_has_gpai_and_final(self):
        dates = [item["date"] for item in EU_AI_ACT_TIMELINE]
        assert "2025-08-02" in dates  # GPAI obligations
        assert "2026-08-02" in dates  # most high-risk obligations
        assert "2027-08-02" in dates  # final transposition

    def test_map_vulnerabilities_includes_eu_ai_act(self):
        mapper = ComplianceMapper()
        result = mapper.map_vulnerabilities([_vuln("SQL001"), _vuln("SEC001")])
        assert result["eu_ai_act"], "eu_ai_act controls must be populated"
        assert any("Art. 15" in e["control"] for e in result["eu_ai_act"])
        assert result["dengbao"] and result["iso27001"] and result["pci_dss"]

    def test_profile_summary_unknown_framework_raises(self):
        with pytest.raises(ValueError, match="unknown compliance framework"):
            ComplianceMapper().profile_summary("gdpr", [])

    def test_profile_summary_eu_ai_act(self):
        mapper = ComplianceMapper()
        summary = mapper.profile_summary("eu_ai_act", [_vuln("SQL001"), _vuln("AUTH001")])
        assert summary["framework"] == "eu_ai_act"
        assert summary["name"] == "EU AI Act"
        assert summary["timeline"] == EU_AI_ACT_TIMELINE
        assert set(summary["mapped_rule_ids"]) == {"SQL001", "AUTH001"}
        assert summary["unmapped_rule_count"] == 0

    def test_profile_summary_counts_unmapped(self):
        summary = ComplianceMapper().profile_summary("eu_ai_act", [_vuln("SQL001"), _vuln("UNKNOWN-999")])
        assert summary["unmapped_rule_count"] == 1


class TestReportSection:
    def test_build_section_eu_ai_act(self):
        lines = build_compliance_section("eu_ai_act", [_vuln("SQL001")])
        text = "\n".join(lines)
        assert "EU AI Act" in text
        assert "2027-08-02" in text
        assert "Art. 15" in text

    def test_build_section_empty_findings(self):
        lines = build_compliance_section("eu_ai_act", [])
        assert any("无" in line for line in lines)

    def test_build_section_unknown_framework_empty(self):
        assert build_compliance_section("gdpr", []) == []

    def test_markdown_renders_section_from_flag(self):
        from fusion_security.engine.scanner import ScanResult, ScanTarget

        result = ScanResult(ScanTarget("/tmp/x"))
        result.vulnerabilities = [_vuln("SEC001")]
        from fusion_security.report.report import ReportGenerator

        md = ReportGenerator().generate_markdown(result, compliance_framework="eu_ai_act")
        assert "合规对照" in md
        assert "EU AI Act" in md

    def test_markdown_without_flag_no_section(self):
        from fusion_security.engine.scanner import ScanResult, ScanTarget

        result = ScanResult(ScanTarget("/tmp/x"))
        from fusion_security.report.report import ReportGenerator

        md = ReportGenerator().generate_markdown(result)
        assert "合规对照" not in md
