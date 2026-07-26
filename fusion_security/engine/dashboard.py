"""Dashboard statistics — scan metrics, trends, top rules."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DashboardStats:
    total_scans: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    top_rules: List[Dict[str, Any]] = field(default_factory=list)
    top_files: List[Dict[str, Any]] = field(default_factory=list)
    severity_trend: List[Dict[str, Any]] = field(default_factory=list)
    projects_count: int = 0
    avg_scan_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_scans": self.total_scans,
            "total_vulnerabilities": self.total_vulnerabilities,
            "severity_counts": {
                "critical": self.critical_count, "high": self.high_count,
                "medium": self.medium_count, "low": self.low_count,
            },
            "top_rules": self.top_rules[:10],
            "top_files": self.top_files[:10],
            "severity_trend": self.severity_trend[-7:],
            "projects_count": self.projects_count,
            "avg_scan_duration_ms": self.avg_scan_duration_ms,
        }


class DashboardAggregator:
    def __init__(self):
        self._scan_history: List[Dict[str, Any]] = []

    def record_scan(self, scan_result: Dict[str, Any]) -> None:
        self._scan_history.append(scan_result)
        logger.info(f"[Dashboard] 记录扫描: {scan_result.get('scan_id', 'unknown')}")

    def get_stats(self) -> DashboardStats:
        stats = DashboardStats()
        stats.total_scans = len(self._scan_history)

        rule_counter: Counter = Counter()
        file_counter: Counter = Counter()
        total_duration = 0.0

        for scan in self._scan_history:
            vulns = scan.get("vulnerabilities", [])
            stats.total_vulnerabilities += len(vulns)
            total_duration += scan.get("duration_ms", 0)

            for v in vulns:
                sev = v.get("severity", "low")
                if sev == "critical":
                    stats.critical_count += 1
                elif sev == "high":
                    stats.high_count += 1
                elif sev == "medium":
                    stats.medium_count += 1
                else:
                    stats.low_count += 1
                rule_counter[v.get("rule_id", "unknown")] += 1
                file_counter[v.get("file_path", "unknown")] += 1

        stats.avg_scan_duration_ms = total_duration / max(stats.total_scans, 1)
        stats.top_rules = [{"rule_id": r, "count": c} for r, c in rule_counter.most_common(10)]
        stats.top_files = [{"file_path": f, "count": c} for f, c in file_counter.most_common(10)]
        stats.projects_count = len(set(s.get("project_path", "") for s in self._scan_history))

        return stats

    def get_trend(self, days: int = 7) -> List[Dict[str, Any]]:
        return [
            {
                "date": s.get("completed_at", ""),
                "critical": sum(1 for v in s.get("vulnerabilities", []) if v.get("severity") == "critical"),
                "high": sum(1 for v in s.get("vulnerabilities", []) if v.get("severity") == "high"),
                "medium": sum(1 for v in s.get("vulnerabilities", []) if v.get("severity") == "medium"),
                "low": sum(1 for v in s.get("vulnerabilities", []) if v.get("severity") == "low"),
            }
            for s in self._scan_history[-days:]
        ]
