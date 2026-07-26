import pytest
from fusion_security.engine.scoring.confidence import (
    ConfidenceFactors, compute_confidence, from_rule_match, from_ai_verify,
    from_adversarial, from_taint, from_ast, from_context,
    legacy_to_score, score_to_legacy, CONFIDENCE_MIN, CONFIDENCE_MAX,
)


class TestConfidenceFactors:
    def test_default_values(self):
        f = ConfidenceFactors()
        assert f.rule_match == 0.0
        assert f.ai_verify == 0.0

    def test_to_dict(self):
        f = ConfidenceFactors(rule_match=80, ast_support=60)
        d = f.to_dict()
        assert d["rule_match"] == 80
        assert d["ast_support"] == 60


class TestComputeConfidence:
    def test_all_zeros(self):
        f = ConfidenceFactors()
        assert compute_confidence(f) == 0

    def test_rule_only_critical(self):
        f = from_rule_match("critical")
        score = compute_confidence(f)
        assert 15 <= score <= 100

    def test_all_max(self):
        f = ConfidenceFactors(
            rule_match=100, ast_support=100, taint_reach=100,
            ai_verify=100, adversarial=100, context_score=100,
        )
        score = compute_confidence(f)
        assert score == 100

    def test_bounded_min_max(self):
        f = ConfidenceFactors(rule_match=-50, ast_support=200)
        score = compute_confidence(f)
        assert CONFIDENCE_MIN <= score <= CONFIDENCE_MAX


class TestFromRuleMatch:
    @pytest.mark.parametrize("severity,expected_min", [
        ("critical", 60), ("high", 50), ("medium", 40), ("low", 30),
    ])
    def test_severity_base(self, severity, expected_min):
        f = from_rule_match(severity)
        assert f.rule_match >= expected_min

    def test_high_specificity(self):
        f = from_rule_match("critical", "high")
        assert f.rule_match > from_rule_match("critical", "normal").rule_match

    def test_low_specificity(self):
        f = from_rule_match("medium", "low")
        assert f.rule_match < from_rule_match("medium", "normal").rule_match


class TestFromAiVerify:
    def test_legacy_0_to_1(self):
        assert from_ai_verify(0.85) == pytest.approx(85.0)

    def test_already_0_100(self):
        assert from_ai_verify(75.0) == 75.0

    def test_zero(self):
        assert from_ai_verify(0.0) == 0.0


class TestFromAdversarial:
    def test_not_real(self):
        assert from_adversarial(False, 0.9) == 0.0

    def test_real_legacy(self):
        assert from_adversarial(True, 0.8) == pytest.approx(80.0)

    def test_real_score(self):
        assert from_adversarial(True, 90.0) == 90.0


class TestFromTaint:
    def test_not_reachable(self):
        assert from_taint(False) == 0.0

    def test_intra_file(self):
        assert from_taint(True) == 70.0

    def test_cross_file(self):
        assert from_taint(True, cross_file=True) == 90.0


class TestFromAst:
    def test_no_match(self):
        assert from_ast(False) == 0.0

    def test_dangerous_call(self):
        assert from_ast(True, "call") == 80.0

    def test_safe_type(self):
        assert from_ast(True, "assignment") == 60.0


class TestFromContext:
    def test_minimal(self):
        assert from_context() == 30.0

    def test_with_user_input(self):
        score = from_context(in_function=True, has_user_input=True)
        assert score >= 80.0


class TestLegacyConversion:
    def test_legacy_to_score(self):
        assert legacy_to_score(0.85) == 85

    def test_legacy_to_score_already_100(self):
        assert legacy_to_score(85) == 85

    def test_score_to_legacy(self):
        assert score_to_legacy(85) == 0.85

    def test_roundtrip(self):
        assert legacy_to_score(score_to_legacy(75)) == 75

    def test_zero(self):
        assert legacy_to_score(0.0) == 0
        assert score_to_legacy(0) == 0.0


class TestVulnerabilityConfidence:
    def test_vulnerability_confidence_is_0_100(self):
        from fusion_security.models.vulnerability import Vulnerability
        v = Vulnerability(
            id="V1", title="Test", description="d",
            severity="high", confidence=85,
            file_path="test.py", line_number=1, code_snippet="x",
        )
        assert v.confidence == 85
        assert v.to_dict()["confidence"] == 85
