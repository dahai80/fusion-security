"""SARIF (Static Analysis Results Interchange Format) export."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from ..models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def vulnerabilities_to_sarif(vulnerabilities: List[Vulnerability], tool_name: str = "fusion-security", tool_version: str = "0.5.0") -> Dict[str, Any]:
    rules_map: Dict[str, Dict[str, Any]] = {}
    results = []

    for v in vulnerabilities:
        if v.rule_id not in rules_map:
            rules_map[v.rule_id] = {
                "id": v.rule_id,
                "name": v.title[:60] if v.title else v.rule_id,
                "shortDescription": {"text": v.description[:120] if v.description else v.rule_id},
                "properties": {"severity": v.severity},
            }
            if v.cwe_id:
                rules_map[v.rule_id]["helpUri"] = f"https://cwe.mitre.org/data/definitions/{v.cwe_id.replace('CWE-', '')}.html"

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": v.file_path},
                "region": {"startLine": max(v.line_number, 1)},
            }
        }
        result_entry = {
            "ruleId": v.rule_id,
            "ruleIndex": list(rules_map.keys()).index(v.rule_id),
            "level": _severity_to_level(v.severity),
            "message": {"text": v.description or v.title},
            "locations": [location],
        }
        if v.data_flow_path:
            result_entry["codeFlows"] = [{
                "threadFlows": [{
                    "locations": [{"location": location}],
                }],
            }]
        results.append(result_entry)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/fusion-security",
                    "rules": list(rules_map.values()),
                }
            },
            "results": results,
        }],
    }
    logger.info(f"[SARIF] 生成 {len(results)} 个结果")
    return sarif


def save_sarif(vulnerabilities: List[Vulnerability], output_path: str, tool_name: str = "fusion-security", tool_version: str = "0.5.0") -> str:
    sarif = vulnerabilities_to_sarif(vulnerabilities, tool_name, tool_version)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)
    logger.info(f"[SARIF] 保存到 {output_path}")
    return output_path


def _severity_to_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "warning")


from pathlib import Path
