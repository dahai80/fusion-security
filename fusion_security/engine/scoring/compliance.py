"""Compliance mapping — 等保2.0, ISO 27001, PCI DSS, EU AI Act.

P3.2: the flat mapper grows into control-item profiles per framework.
Each framework profile carries an id, display name and (where applicable)
a regulatory timeline; findings map to control items per framework.
Reports render a compliance section from a single profile flag.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# EU AI Act regulatory timeline (Regulation (EU) 2024/1689). Dates are the
# application milestones relevant to a security-audit tool consumer.
EU_AI_ACT_TIMELINE: list[dict[str, str]] = [
    {"date": "2025-08-02", "label": "GPAI obligations apply (Chapter V)"},
    {"date": "2026-08-02", "label": "Most high-risk system obligations apply (Annex III)"},
    {"date": "2027-08-02", "label": "Art. 6(1) embedded-product obligations apply (final transposition)"},
]

FRAMEWORK_PROFILES: dict[str, dict] = {
    "dengbao": {"name": "等保2.0", "timeline": []},
    "iso27001": {"name": "ISO 27001", "timeline": []},
    "pci_dss": {"name": "PCI DSS", "timeline": []},
    "eu_ai_act": {"name": "EU AI Act", "timeline": EU_AI_ACT_TIMELINE},
}


@dataclass
class ComplianceMapping:
    rule_id: str
    dengbao_controls: list[str]
    iso27001_controls: list[str]
    pci_dss_controls: list[str]
    description: str = ""
    eu_ai_act_controls: list[str] = field(default_factory=list)


COMPLIANCE_MAP: dict[str, ComplianceMapping] = {
    "SQL001": ComplianceMapping(
        "SQL001", ["8.1.3"], ["A.14.2.1"], ["6.5.1"], "SQL注入", ["Art. 15 robustness & cybersecurity"]
    ),
    "CMD001": ComplianceMapping(
        "CMD001", ["8.1.3"], ["A.14.2.1"], ["6.5.1"], "命令注入", ["Art. 15 robustness & cybersecurity"]
    ),
    "XSS001": ComplianceMapping(
        "XSS001", ["8.1.3"], ["A.14.2.1"], ["6.5.7"], "跨站脚本", ["Art. 15 robustness & cybersecurity"]
    ),
    "SEC001": ComplianceMapping(
        "SEC001", ["8.1.4"], ["A.10.1.1"], ["6.5.3"], "硬编码密钥", ["Art. 15 cybersecurity", "Art. 10 data governance"]
    ),
    "AUTH001": ComplianceMapping("AUTH001", ["8.1.4"], ["A.9.2.1"], ["8.1"], "弱认证", ["Art. 15 cybersecurity"]),
    "CRYPTO001": ComplianceMapping("CRYPTO001", ["8.1.4"], ["A.10.1.1"], ["4.1"], "弱加密", ["Art. 15 cybersecurity"]),
    "FUS-SCA-001": ComplianceMapping(
        "FUS-SCA-001",
        ["8.1.3", "8.1.10"],
        ["A.14.2.1", "A.12.6.1"],
        ["6.5", "11.3"],
        "依赖漏洞",
        ["Art. 15 robustness & cybersecurity"],
    ),
    "TAINT-001": ComplianceMapping(
        "TAINT-001", ["8.1.3"], ["A.14.2.1"], ["6.5.1"], "污点追踪", ["Art. 15 robustness & cybersecurity"]
    ),
}

_FRAMEWORK_KEYS = {
    "dengbao": "dengbao_controls",
    "iso27001": "iso27001_controls",
    "pci_dss": "pci_dss_controls",
    "eu_ai_act": "eu_ai_act_controls",
}


class ComplianceMapper:
    def map_rule(self, rule_id: str) -> ComplianceMapping | None:
        mapping = COMPLIANCE_MAP.get(rule_id)
        if mapping:
            logger.debug(f"[Compliance] {rule_id} → 等保{mapping.dengbao_controls} ISO{mapping.iso27001_controls}")
        return mapping

    def _controls_for(self, mapping: ComplianceMapping, framework: str) -> list[str]:
        attr = _FRAMEWORK_KEYS.get(framework)
        return list(getattr(mapping, attr)) if attr else []

    def map_vulnerabilities(self, vulns: list) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {fw: [] for fw in FRAMEWORK_PROFILES}
        for v in vulns:
            rule_id = getattr(v, "rule_id", "")
            mapping = self.map_rule(rule_id)
            if not mapping:
                continue
            for fw, attr in _FRAMEWORK_KEYS.items():
                for ctrl in getattr(mapping, attr):
                    entry = {"rule_id": rule_id, "control": ctrl, "description": mapping.description}
                    if entry not in result[fw]:
                        result[fw].append(entry)
        return result

    def profile_summary(self, framework: str, vulns: list) -> dict:
        """Control-item summary for one framework profile (report flag)."""
        profile = FRAMEWORK_PROFILES.get(framework)
        if profile is None:
            raise ValueError(f"unknown compliance framework: {framework}")
        mappings = self.map_vulnerabilities(vulns)
        mapped_rules = {entry["rule_id"] for entry in mappings[framework]}
        unmapped = len({getattr(v, "rule_id", "") for v in vulns} - mapped_rules - {""})
        return {
            "framework": framework,
            "name": profile["name"],
            "timeline": profile["timeline"],
            "controls": mappings[framework],
            "mapped_rule_ids": sorted(mapped_rules),
            "unmapped_rule_count": unmapped,
        }


def build_compliance_section(framework: str, vulns: list) -> list[str]:
    """Markdown lines for the report compliance section (single flag render)."""
    mapper = ComplianceMapper()
    try:
        summary = mapper.profile_summary(framework, vulns)
    except ValueError as e:
        logger.warning(f"[Compliance] section skipped: {e}")
        return []
    lines = ["## 合规对照", ""]
    lines.append(f"**框架**: {summary['name']}")
    if summary["timeline"]:
        lines.append("")
        lines.append("**法规时间线**:")
        for item in summary["timeline"]:
            lines.append(f"- {item['date']}: {item['label']}")
    lines.append("")
    if summary["controls"]:
        lines.append(f"**命中控制项** ({len(summary['controls'])}):")
        for entry in summary["controls"]:
            lines.append(f"- {entry['control']} — {entry['description']} ({entry['rule_id']})")
    else:
        lines.append("**命中控制项**: 无（本次扫描未发现映射到该框架的漏洞）")
    if summary["unmapped_rule_count"]:
        lines.append(f"- *未映射规则数: {summary['unmapped_rule_count']}（规则→控制项映射持续扩充）*")
    lines.append("")
    return lines
