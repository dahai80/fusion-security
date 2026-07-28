"""CVSS 3.1 base score calculator."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CVSSResult:
    vector: str = ""
    base_score: float = 0.0
    severity: str = "none"
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"


METRIC_VALUES = {
    "attack_vector": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "attack_complexity": {"L": 0.77, "H": 0.44},
    "privileges_required_unchanged": {"N": 0.85, "L": 0.62, "H": 0.27},
    "privileges_required_changed": {"N": 0.85, "L": 0.68, "H": 0.50},
    "user_interaction": {"N": 0.85, "R": 0.62},
    "scope": {"U": 0, "C": 1},
    "confidentiality": {"N": 0, "L": 0.22, "H": 0.56},
    "integrity": {"N": 0, "L": 0.22, "H": 0.56},
    "availability": {"N": 0, "L": 0.22, "H": 0.56},
}


class CVSS31Scorer:
    def calculate(
        self,
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        s: str = "U",
        c: str = "N",
        i: str = "N",
        a: str = "N",
    ) -> CVSSResult:
        iss = self._impact_subscore(c, i, a)
        impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        exploitability = self._exploitability_subscore(av, ac, pr, ui, s)

        if impact <= 0:
            base_score = 0.0
        elif s == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        base_score = round(base_score * 10) / 10
        severity = self._severity_from_score(base_score)

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        return CVSSResult(
            vector=vector,
            base_score=base_score,
            severity=severity,
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a,
        )

    def from_severity(self, severity: str) -> CVSSResult:
        mapping = {
            "critical": ("N", "L", "N", "N", "U", "H", "H", "H"),
            "high": ("N", "L", "N", "N", "U", "H", "L", "N"),
            "medium": ("N", "L", "N", "R", "U", "L", "L", "N"),
            "low": ("L", "H", "L", "R", "U", "N", "L", "N"),
        }
        vals = mapping.get(severity, ("N", "L", "N", "N", "U", "N", "N", "N"))
        return self.calculate(*vals)

    def _impact_subscore(self, c: str, i: str, a: str) -> float:
        c_val = METRIC_VALUES["confidentiality"].get(c, 0)
        i_val = METRIC_VALUES["integrity"].get(i, 0)
        a_val = METRIC_VALUES["availability"].get(a, 0)
        return 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))

    def _exploitability_subscore(self, av: str, ac: str, pr: str, ui: str, s: str) -> float:
        av_val = METRIC_VALUES["attack_vector"].get(av, 0.85)
        ac_val = METRIC_VALUES["attack_complexity"].get(ac, 0.77)
        pr_key = "privileges_required_changed" if s == "C" else "privileges_required_unchanged"
        pr_val = METRIC_VALUES[pr_key].get(pr, 0.85)
        ui_val = METRIC_VALUES["user_interaction"].get(ui, 0.85)
        return 8.22 * av_val * ac_val * pr_val * ui_val

    def _severity_from_score(self, score: float) -> str:
        if score == 0:
            return "none"
        elif score < 4.0:
            return "low"
        elif score < 7.0:
            return "medium"
        elif score < 9.0:
            return "high"
        else:
            return "critical"
