"""Tests for Phase 3-4: CI gate, SARIF, CVSS, compliance, feedback, auth, tenant, custom rules, dashboard."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fusion_security.api.auth import AuthManager
from fusion_security.engine.ci.gate import GatePolicy, GateResult, SecurityGate
from fusion_security.engine.ci.webhook import WebhookConfig, WebhookNotifier
from fusion_security.engine.dashboard import DashboardAggregator
from fusion_security.engine.feedback.loop import FeedbackEntry, FeedbackStore
from fusion_security.engine.fix.patch_verify import PatchVerifier
from fusion_security.engine.rules.custom import CustomRule, CustomRuleStore
from fusion_security.engine.scheduler import ScanScheduler, ScheduledScan, ScheduleFrequency
from fusion_security.engine.scoring.compliance import ComplianceMapper
from fusion_security.engine.scoring.cvss import CVSS31Scorer
from fusion_security.engine.tenant.audit import AuditLogger
from fusion_security.engine.tenant.manager import TenantManager
from fusion_security.models.patch import Patch
from fusion_security.models.vulnerability import Vulnerability
from fusion_security.report.sarif import _severity_to_level, vulnerabilities_to_sarif


def _make_vuln(severity: str = "high", rule_id: str = "SQL001") -> Vulnerability:
    return Vulnerability(
        id="V-TEST",
        title="Test Vuln",
        description="test",
        severity=severity,
        confidence=90,
        file_path="test.py",
        line_number=1,
        code_snippet="test",
        rule_id=rule_id,
    )


# --- CI Gate ---
class TestSecurityGate:
    def test_strict_policy_blocks_all(self):
        gate = SecurityGate(GatePolicy.STRICT)
        vulns = [_make_vuln("medium")]
        result = gate.evaluate(vulns)
        assert not result.passed
        assert "medium" in result.blocked_by[0]

    def test_standard_allows_medium_below_threshold(self):
        gate = SecurityGate(GatePolicy.STANDARD)
        vulns = [_make_vuln("medium")] * 3
        result = gate.evaluate(vulns)
        assert result.passed

    def test_standard_blocks_critical(self):
        gate = SecurityGate(GatePolicy.STANDARD)
        vulns = [_make_vuln("critical")]
        result = gate.evaluate(vulns)
        assert not result.passed

    def test_permissive_allows_some_high(self):
        gate = SecurityGate(GatePolicy.PERMISSIVE)
        vulns = [_make_vuln("high")] * 2
        result = gate.evaluate(vulns)
        assert result.passed

    def test_gate_result_to_dict(self):
        result = GateResult(passed=True, policy=GatePolicy.STANDARD, total_vulns=0)
        d = result.to_dict()
        assert d["passed"] is True
        assert d["policy"] == "standard"

    def test_gate_result_to_json(self):
        result = GateResult(passed=False, blocked_by=["critical:1>0"])
        j = result.to_json()
        data = json.loads(j)
        assert data["passed"] is False


# --- CVSS 3.1 ---
class TestCVSS31:
    def test_critical_score(self):
        scorer = CVSS31Scorer()
        result = scorer.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        assert result.base_score >= 9.0
        assert result.severity == "critical"

    def test_low_score(self):
        scorer = CVSS31Scorer()
        result = scorer.calculate(av="P", ac="H", pr="H", ui="R", s="U", c="N", i="L", a="N")
        assert result.base_score < 5.0

    def test_from_severity(self):
        scorer = CVSS31Scorer()
        result = scorer.from_severity("high")
        assert result.severity == "high"
        assert result.base_score >= 7.0

    def test_zero_impact(self):
        scorer = CVSS31Scorer()
        result = scorer.calculate(c="N", i="N", a="N")
        assert result.base_score == 0.0
        assert result.severity == "none"

    def test_vector_string(self):
        scorer = CVSS31Scorer()
        result = scorer.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        assert "CVSS:3.1" in result.vector
        assert "AV:N" in result.vector


# --- Compliance ---
class TestCompliance:
    def test_map_rule(self):
        mapper = ComplianceMapper()
        m = mapper.map_rule("SQL001")
        assert m is not None
        assert len(m.dengbao_controls) > 0
        assert len(m.iso27001_controls) > 0

    def test_map_unknown_rule(self):
        mapper = ComplianceMapper()
        assert mapper.map_rule("UNKNOWN999") is None

    def test_map_vulnerabilities(self):
        mapper = ComplianceMapper()
        vulns = [_make_vuln(rule_id="SQL001"), _make_vuln(rule_id="SEC001")]
        result = mapper.map_vulnerabilities(vulns)
        assert len(result["dengbao"]) > 0
        assert len(result["iso27001"]) > 0
        assert len(result["pci_dss"]) > 0


# --- Feedback ---
class TestFeedback:
    def test_add_fp_feedback(self):
        store = FeedbackStore()
        entry = FeedbackEntry(vuln_id="V1", rule_id="SQL001", file_path="a.py", line_number=1, is_false_positive=True)
        store.add_feedback(entry)
        assert store.is_false_positive("SQL001", "a.py", 1)

    def test_filter_vulnerabilities(self):
        store = FeedbackStore()
        store.add_feedback(FeedbackEntry(rule_id="SQL001", file_path="a.py", line_number=1, is_false_positive=True))
        vulns = [_make_vuln(rule_id="SQL001")]
        vulns[0].file_path = "a.py"
        vulns[0].line_number = 1
        filtered = store.filter_vulnerabilities(vulns)
        assert len(filtered) == 0

    def test_get_stats(self):
        store = FeedbackStore()
        store.add_feedback(FeedbackEntry(rule_id="SQL001", is_false_positive=True))
        store.add_feedback(FeedbackEntry(rule_id="CMD001", is_false_positive=False))
        stats = store.get_stats()
        assert stats["false_positives"] == 1
        assert stats["true_positives"] == 1

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "feedback.json")
            store = FeedbackStore(path)
            store.add_feedback(
                FeedbackEntry(vuln_id="V1", rule_id="SQL001", file_path="a.py", line_number=1, is_false_positive=True)
            )
            store2 = FeedbackStore(path)
            assert store2.is_false_positive("SQL001", "a.py", 1)


# --- Auth ---
class TestAuth:
    def test_create_api_key(self):
        mgr = AuthManager()
        raw = mgr.create_api_key("test", ["admin"])
        assert raw.startswith("fs_")
        key = mgr.validate_key(raw)
        assert key is not None
        assert key.name == "test"

    def test_invalid_key(self):
        mgr = AuthManager()
        assert mgr.validate_key("invalid") is None

    def test_has_permission(self):
        mgr = AuthManager()
        raw = mgr.create_api_key("admin_user", ["admin"])
        key = mgr.validate_key(raw)
        assert mgr.has_permission(key, "system:manage")
        assert mgr.has_permission(key, "scan:run")

    def test_viewer_no_admin(self):
        mgr = AuthManager()
        raw = mgr.create_api_key("viewer_user", ["viewer"])
        key = mgr.validate_key(raw)
        assert not mgr.has_permission(key, "system:manage")
        assert mgr.has_permission(key, "scan:read")

    def test_revoke_key(self):
        mgr = AuthManager()
        mgr.create_api_key("to_revoke", ["viewer"])
        assert mgr.revoke_key("to_revoke") is True
        assert mgr.revoke_key("nonexistent") is False

    def test_list_keys(self):
        mgr = AuthManager()
        mgr.create_api_key("key1", ["admin"])
        mgr.create_api_key("key2", ["viewer"])
        keys = mgr.list_keys()
        assert len(keys) == 2


# --- Tenant ---
class TestTenant:
    def test_create_tenant(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = TenantManager(base_dir=tmpdir)
            tid, raw_key = mgr.create_tenant("test_org")
            assert tid.startswith("tenant_")
            assert raw_key.startswith("fs_tenant_")

    def test_authenticate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = TenantManager(base_dir=tmpdir)
            tid, raw_key = mgr.create_tenant("test_org")
            t = mgr.authenticate(raw_key)
            assert t is not None
            assert t.name == "test_org"

    def test_deactivate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = TenantManager(base_dir=tmpdir)
            tid, _ = mgr.create_tenant("test_org")
            mgr.deactivate(tid)
            t = mgr.get_tenant(tid)
            assert t.is_active is False


# --- Audit ---
class TestAudit:
    def test_log_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            al = AuditLogger(log_dir=tmpdir, tenant_id="t1")
            entry = al.log("scan.run", actor="admin", resource_type="project", resource_id="p1")
            assert entry.action == "scan.run"
            assert len(al.entries) == 1

    def test_query(self):
        al = AuditLogger()
        al.log("scan.run", actor="admin")
        al.log("scan.run", actor="user")
        al.log("key.create", actor="admin")
        results = al.query(action="scan.run")
        assert len(results) == 2
        results = al.query(actor="admin")
        assert len(results) == 2


# --- Custom Rules ---
class TestCustomRules:
    def test_add_rule(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "rules.json")
            store = CustomRuleStore(store_path=path)
            rule = CustomRule(id="CUSTOM-001", name="Test Rule", pattern="eval\\(", severity="high", rule_type="regex")
            store.add_rule(rule)
            assert store.get_rule("CUSTOM-001") is not None

    def test_to_scan_rule(self):
        rule = CustomRule(id="C-001", name="Test", pattern="eval\\(", severity="high", rule_type="regex")
        sr = rule.to_scan_rule()
        assert sr is not None
        assert sr.id == "C-001"

    def test_invalid_pattern(self):
        rule = CustomRule(id="C-002", name="Bad", pattern="[invalid", severity="high")
        sr = rule.to_scan_rule()
        assert sr is None

    def test_gray_release(self):
        rule = CustomRule(id="C-003", name="Gray", pattern="test", gray_release=True, gray_percentage=50)
        applied = [rule.should_apply(f"tenant_{i}") for i in range(100)]
        true_count = sum(applied)
        assert 20 < true_count < 80

    def test_disabled_rule(self):
        rule = CustomRule(id="C-004", name="Disabled", pattern="test", enabled=False)
        assert not rule.should_apply()

    def test_update_rule(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "rules.json")
            store = CustomRuleStore(store_path=path)
            store.add_rule(CustomRule(id="C-001", name="Old", pattern="old"))
            store.update_rule("C-001", name="New", pattern="new")
            r = store.get_rule("C-001")
            assert r.name == "New"

    def test_delete_rule(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "rules.json")
            store = CustomRuleStore(store_path=path)
            store.add_rule(CustomRule(id="C-001", name="Del", pattern="x"))
            assert store.delete_rule("C-001") is True
            assert store.get_rule("C-001") is None

    def test_get_active_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "rules.json")
            store = CustomRuleStore(store_path=path)
            store.add_rule(CustomRule(id="C-001", name="R1", pattern="eval\\(", severity="high"))
            store.add_rule(CustomRule(id="C-002", name="R2", pattern="exec\\(", severity="medium"))
            store.add_rule(CustomRule(id="C-003", name="R3", pattern="[bad", enabled=False))
            rules = store.get_active_rules()
            assert len(rules) == 2


# --- Dashboard ---
class TestDashboard:
    def test_empty_stats(self):
        agg = DashboardAggregator()
        stats = agg.get_stats()
        assert stats.total_scans == 0
        assert stats.total_vulnerabilities == 0

    def test_record_scan(self):
        agg = DashboardAggregator()
        agg.record_scan(
            {
                "scan_id": "s1",
                "duration_ms": 100,
                "vulnerabilities": [
                    {"severity": "high", "rule_id": "SQL001", "file_path": "a.py"},
                    {"severity": "medium", "rule_id": "XSS001", "file_path": "b.py"},
                ],
            }
        )
        stats = agg.get_stats()
        assert stats.total_scans == 1
        assert stats.total_vulnerabilities == 2
        assert stats.high_count == 1
        assert stats.medium_count == 1

    def test_trend(self):
        agg = DashboardAggregator()
        agg.record_scan({"vulnerabilities": [{"severity": "high", "rule_id": "SQL001", "file_path": "a.py"}]})
        trend = agg.get_trend()
        assert len(trend) == 1


# --- Scheduler ---
class TestScheduler:
    def test_add_schedule(self):
        sched = ScanScheduler()
        s = ScheduledScan(id="s1", project_path="/tmp/test", frequency=ScheduleFrequency.DAILY)
        sched.add_schedule(s)
        assert len(sched.schedules) == 1

    def test_remove_schedule(self):
        sched = ScanScheduler()
        sched.add_schedule(ScheduledScan(id="s1", project_path="/tmp", frequency=ScheduleFrequency.DAILY))
        assert sched.remove_schedule("s1") is True
        assert sched.remove_schedule("nonexistent") is False

    def test_list_schedules(self):
        sched = ScanScheduler()
        sched.add_schedule(ScheduledScan(id="s1", project_path="/tmp", frequency=ScheduleFrequency.WEEKLY))
        result = sched.list_schedules()
        assert len(result) == 1
        assert result[0]["frequency"] == "weekly"


# --- Patch Verify ---
class TestPatchVerify:
    def test_apply_patch(self):
        pv = PatchVerifier()
        original = "line1\nline2\nline3\n"
        patch = "--- a/test.py\n+++ b/test.py\n@@ -1,3 +1,3 @@\n line1\n-line2\n+line2_fixed\n line3\n"
        result = pv._apply_patch_text(original, patch)
        assert result is not None
        assert "line2_fixed" in result

    def test_check_syntax_python(self):
        pv = PatchVerifier()
        assert pv._check_syntax("x = 1\n", "test.py") is True
        assert pv._check_syntax("def foo(\n", "test.py") is False

    def test_generate_git_diff(self):
        pv = PatchVerifier()
        diff = pv._generate_git_diff("old\n", "new\n", "test.py")
        assert "a/test.py" in diff
        assert "b/test.py" in diff

    def test_verify_patch(self):
        pv = PatchVerifier()
        p = Patch(id="P1", diff_content="fixed code", original_code="original code", patched_code="fixed code")
        result = pv.verify(p, "original code")
        assert result.patch_id == "P1"

    def test_verify_empty_patch(self):
        pv = PatchVerifier()
        p = Patch(id="P2", diff_content="")
        result = pv.verify(p, "original")
        assert not result.is_valid


# --- SARIF ---
class TestSARIF:
    def test_sarif_structure(self):
        vulns = [_make_vuln("high", "SQL001")]
        sarif = vulnerabilities_to_sarif(vulns)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1

    def test_severity_to_level(self):
        assert _severity_to_level("critical") == "error"
        assert _severity_to_level("high") == "error"
        assert _severity_to_level("medium") == "warning"
        assert _severity_to_level("low") == "note"

    def test_sarif_save(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from fusion_security.report.sarif import save_sarif

            vulns = [_make_vuln("high", "SQL001")]
            path = save_sarif(vulns, str(Path(tmpdir) / "test.sarif"))
            assert Path(path).exists()
            data = json.loads(Path(path).read_text())
            assert data["version"] == "2.1.0"


# --- Webhook ---
class TestWebhook:
    def test_add_config(self):
        notifier = WebhookNotifier()
        notifier.add_config(WebhookConfig(url="http://localhost:9999/hook"))
        assert len(notifier.configs) == 1

    def test_notify_skip_unmatched_event(self):
        notifier = WebhookNotifier([WebhookConfig(url="http://localhost:9999/hook", events=["scan.completed"])])
        results = notifier.notify("other.event", {})
        assert results == [True]

    def test_notify_scan_complete(self):
        notifier = WebhookNotifier()
        results = notifier.notify_scan_complete("s1", 5, 1, 2, 1, 1)
        assert len(results) == 0
