from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CONFIDENCE_MIN = 0
CONFIDENCE_MAX = 100


@dataclass
class ConfidenceFactors:
    rule_match: float = 0.0
    ast_support: float = 0.0
    taint_reach: float = 0.0
    ai_verify: float = 0.0
    adversarial: float = 0.0
    context_score: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            "rule_match": self.rule_match,
            "ast_support": self.ast_support,
            "taint_reach": self.taint_reach,
            "ai_verify": self.ai_verify,
            "adversarial": self.adversarial,
            "context_score": self.context_score,
        }


WEIGHTS = ConfidenceFactors(
    rule_match=30.0,
    ast_support=15.0,
    taint_reach=20.0,
    ai_verify=15.0,
    adversarial=10.0,
    context_score=10.0,
)


def compute_confidence(factors: ConfidenceFactors) -> int:
    total = 0.0
    for attr in ["rule_match", "ast_support", "taint_reach",
                 "ai_verify", "adversarial", "context_score"]:
        f_val = getattr(factors, attr)
        w_val = getattr(WEIGHTS, attr)
        total += f_val * w_val / 100.0
    result = int(max(CONFIDENCE_MIN, min(CONFIDENCE_MAX, round(total))))
    logger.debug(f"置信度计算: factors={factors.to_dict()}, result={result}")
    return result


def from_rule_match(severity: str, pattern_specificity: str = "normal") -> ConfidenceFactors:
    base = {"critical": 70, "high": 60, "medium": 50, "low": 40}.get(severity, 50)
    boost = {"high": 15, "normal": 0, "low": -10}.get(pattern_specificity, 0)
    rule_score = max(0, min(100, base + boost))
    return ConfidenceFactors(rule_match=rule_score)


def from_ai_verify(ai_confidence: float) -> float:
    if ai_confidence <= 1.0:
        return ai_confidence * 100.0
    return max(0.0, min(100.0, ai_confidence))


def from_adversarial(is_real: bool, adv_confidence: float) -> float:
    if not is_real:
        return 0.0
    if adv_confidence <= 1.0:
        return adv_confidence * 100.0
    return max(0.0, min(100.0, adv_confidence))


def from_taint(reachable: bool, cross_file: bool = False) -> float:
    if not reachable:
        return 0.0
    return 90.0 if cross_file else 70.0


def from_ast(has_match: bool, node_type: str = "") -> float:
    if not has_match:
        return 0.0
    dangerous_types = {"call", "subscript", "attribute"}
    return 80.0 if node_type in dangerous_types else 60.0


def from_context(in_function: bool = False, in_import: bool = False,
                 has_user_input: bool = False) -> float:
    score = 30.0
    if in_function:
        score += 20.0
    if has_user_input:
        score += 30.0
    if in_import:
        score += 10.0
    return min(100.0, score)


def legacy_to_score(old_confidence: float) -> int:
    if old_confidence <= 1.0:
        return int(round(old_confidence * 100))
    return int(round(old_confidence))


def score_to_legacy(score: int) -> float:
    if score <= 0:
        return 0.0
    return round(score / 100.0, 2)
