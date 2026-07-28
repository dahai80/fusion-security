"""Security gate — CI/CD quality gate for pass/fail decisions."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ...models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class GatePolicy(StrEnum):
    STRICT = "strict"
    STANDARD = "standard"
    PERMISSIVE = "permissive"


@dataclass
class GateResult:
    passed: bool = True
    policy: GatePolicy = GatePolicy.STANDARD
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    blocked_by: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "policy": self.policy.value,
            "total_vulnerabilities": self.total_vulns,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "blocked_by": self.blocked_by,
            "details": self.details,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


POLICY_THRESHOLDS = {
    GatePolicy.STRICT: {"critical": 0, "high": 0, "medium": 0, "low": 999},
    GatePolicy.STANDARD: {"critical": 0, "high": 0, "medium": 5, "low": 999},
    GatePolicy.PERMISSIVE: {"critical": 0, "high": 3, "medium": 10, "low": 999},
}


class SecurityGate:
    def __init__(self, policy: GatePolicy = GatePolicy.STANDARD, custom_thresholds: dict[str, int] | None = None):
        self.policy = policy
        self.thresholds = custom_thresholds or POLICY_THRESHOLDS[policy]
        logger.info(f"[Gate] 初始化 policy={policy.value} thresholds={self.thresholds}")

    def evaluate(self, vulnerabilities: list[Vulnerability]) -> GateResult:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            sev = v.severity if v.severity in counts else "low"
            counts[sev] += 1

        result = GateResult(
            policy=self.policy,
            total_vulns=len(vulnerabilities),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
        )

        for sev, count in counts.items():
            threshold = self.thresholds.get(sev, 999)
            if count > threshold:
                result.passed = False
                result.blocked_by.append(f"{sev}:{count}>{threshold}")

        if result.passed:
            logger.info(f"[Gate] ✅ 通过 total={len(vulnerabilities)}")
        else:
            logger.warning(f"[Gate] ❌ 阻断 blocked_by={result.blocked_by}")

        return result

    def evaluate_from_pipeline(self, stage_results: dict[str, dict[str, Any]]) -> GateResult:
        triage = stage_results.get("triage", {})
        vulns = []
        for sev in ("critical", "high", "medium", "low"):
            count = triage.get(sev, 0)
            for _ in range(count):
                from ...models.vulnerability import Vulnerability as V

                vulns.append(
                    V(
                        id="gate-v",
                        title=f"gate-{sev}",
                        description="",
                        severity=sev,
                        confidence=100,
                        file_path="",
                        line_number=0,
                        code_snippet="",
                        rule_id="GATE",
                    )
                )
        return self.evaluate(vulns)
