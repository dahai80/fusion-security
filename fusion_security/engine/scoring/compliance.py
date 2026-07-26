"""Compliance mapping — 等保2.0, ISO 27001, PCI DSS."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ComplianceMapping:
    rule_id: str
    dengbao_controls: List[str]
    iso27001_controls: List[str]
    pci_dss_controls: List[str]
    description: str = ""


COMPLIANCE_MAP: Dict[str, ComplianceMapping] = {
    "SQL001": ComplianceMapping("SQL001", ["8.1.3"], ["A.14.2.1"], ["6.5.1"], "SQL注入"),
    "CMD001": ComplianceMapping("CMD001", ["8.1.3"], ["A.14.2.1"], ["6.5.1"], "命令注入"),
    "XSS001": ComplianceMapping("XSS001", ["8.1.3"], ["A.14.2.1"], ["6.5.7"], "跨站脚本"),
    "SEC001": ComplianceMapping("SEC001", ["8.1.4"], ["A.10.1.1"], ["6.5.3"], "硬编码密钥"),
    "AUTH001": ComplianceMapping("AUTH001", ["8.1.4"], ["A.9.2.1"], ["8.1"], "弱认证"),
    "CRYPTO001": ComplianceMapping("CRYPTO001", ["8.1.4"], ["A.10.1.1"], ["4.1"], "弱加密"),
    "FUS-SCA-001": ComplianceMapping("FUS-SCA-001", ["8.1.3", "8.1.10"], ["A.14.2.1", "A.12.6.1"], ["6.5", "11.3"], "依赖漏洞"),
    "TAINT-001": ComplianceMapping("TAINT-001", ["8.1.3"], ["A.14.2.1"], ["6.5.1"], "污点追踪"),
}


class ComplianceMapper:
    def map_rule(self, rule_id: str) -> Optional[ComplianceMapping]:
        mapping = COMPLIANCE_MAP.get(rule_id)
        if mapping:
            logger.debug(f"[Compliance] {rule_id} → 等保{mapping.dengbao_controls} ISO{mapping.iso27001_controls}")
        return mapping

    def map_vulnerabilities(self, vulns: list) -> Dict[str, List[Dict]]:
        result: Dict[str, List[Dict]] = {"dengbao": [], "iso27001": [], "pci_dss": []}
        for v in vulns:
            rule_id = getattr(v, "rule_id", "")
            mapping = self.map_rule(rule_id)
            if not mapping:
                continue
            for ctrl in mapping.dengbao_controls:
                entry = {"rule_id": rule_id, "control": ctrl, "description": mapping.description}
                if entry not in result["dengbao"]:
                    result["dengbao"].append(entry)
            for ctrl in mapping.iso27001_controls:
                entry = {"rule_id": rule_id, "control": ctrl, "description": mapping.description}
                if entry not in result["iso27001"]:
                    result["iso27001"].append(entry)
            for ctrl in mapping.pci_dss_controls:
                entry = {"rule_id": rule_id, "control": ctrl, "description": mapping.description}
                if entry not in result["pci_dss"]:
                    result["pci_dss"].append(entry)
        return result
