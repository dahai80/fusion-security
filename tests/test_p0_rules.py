from pathlib import Path

import pytest

from fusion_security.engine.rules.engine import RuleEngine, ScanRule
from fusion_security.models.rule import Rule


class TestScanRulePrdid:
    def test_scanrule_has_prdid_field(self):
        r = ScanRule("TEST001", "test", "desc", "medium", "CWE-0", r"test", prdid="FUS-INJ-001")
        assert r.prdid == "FUS-INJ-001"

    def test_scanrule_prdid_default_empty(self):
        r = ScanRule("TEST001", "test", "desc", "medium", "CWE-0", r"test")
        assert r.prdid == ""

    def test_scanrule_to_rule(self):
        sr = ScanRule(
            "SQL001",
            "SQL注入",
            "desc",
            "critical",
            "CWE-89",
            r"test",
            fix_template="fix",
            category="injection",
            prdid="FUS-INJ-001",
        )
        rule = sr.to_rule()
        assert isinstance(rule, Rule)
        assert rule.id == "SQL001"
        assert rule.prdid == "FUS-INJ-001"
        assert rule.fix_template == "fix"


class TestRuleModelPrdid:
    def test_rule_has_prdid_field(self):
        r = Rule(id="SQL001", prdid="FUS-INJ-001")
        assert r.prdid == "FUS-INJ-001"

    def test_rule_prdid_default_empty(self):
        r = Rule(id="SQL001")
        assert r.prdid == ""

    def test_rule_to_dict_includes_prdid(self):
        r = Rule(id="SQL001", prdid="FUS-INJ-001")
        d = r.to_dict()
        assert "prdid" in d
        assert d["prdid"] == "FUS-INJ-001"


class TestRuleCoverage:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.engine = RuleEngine()

    def test_total_rule_count(self):
        assert len(self.engine._rules) >= 30

    def test_all_rules_have_prdid(self):
        without_prdid = [r.id for r in self.engine._rules if not r.prdid]
        assert not without_prdid, f"规则缺少prdid: {without_prdid}"

    PRD_CATEGORIES = {
        "FUS-INJ": "注入类",
        "FUS-AUTH": "认证类",
        "FUS-ACL": "访问控制",
        "FUS-DATA": "数据保护",
        "FUS-CRYPTO": "加密类",
        "FUS-CONF": "配置安全",
        "FUS-DESER": "反序列化",
        "FUS-SSRF": "SSRF",
        "FUS-CSRF": "CSRF",
    }

    @pytest.mark.parametrize("prefix,category", list(PRD_CATEGORIES.items()))
    def test_prd_category_coverage(self, prefix, category):
        rules_in_cat = [r for r in self.engine._rules if r.prdid.startswith(prefix)]
        assert rules_in_cat, f"缺少{category}({prefix})规则"

    def test_injection_rules_covered(self):
        inj_prdids = {r.prdid for r in self.engine._rules if r.prdid.startswith("FUS-INJ")}
        expected = {
            "FUS-INJ-001",
            "FUS-INJ-002",
            "FUS-INJ-003",
            "FUS-INJ-004",
            "FUS-INJ-005",
            "FUS-INJ-006",
            "FUS-INJ-007",
        }
        missing = expected - inj_prdids
        assert not missing, f"缺少注入类规则: {missing}"

    def test_auth_rules_covered(self):
        auth_prdids = {r.prdid for r in self.engine._rules if r.prdid.startswith("FUS-AUTH")}
        expected = {"FUS-AUTH-001", "FUS-AUTH-002", "FUS-AUTH-003", "FUS-AUTH-004", "FUS-AUTH-005"}
        missing = expected - auth_prdids
        assert not missing, f"缺少认证类规则: {missing}"

    def test_acl_rules_covered(self):
        acl_prdids = {r.prdid for r in self.engine._rules if r.prdid.startswith("FUS-ACL")}
        expected = {"FUS-ACL-003", "FUS-ACL-004", "FUS-ACL-005"}
        missing = expected - acl_prdids
        assert not missing, f"缺少访问控制规则: {missing}"

    def test_data_rules_covered(self):
        data_prdids = {r.prdid for r in self.engine._rules if r.prdid.startswith("FUS-DATA")}
        expected = {"FUS-DATA-001", "FUS-DATA-002", "FUS-DATA-003"}
        missing = expected - data_prdids
        assert not missing, f"缺少数据保护规则: {missing}"

    def test_crypto_rules_covered(self):
        crypto_prdids = {r.prdid for r in self.engine._rules if r.prdid.startswith("FUS-CRYPTO")}
        expected = {"FUS-CRYPTO-001", "FUS-CRYPTO-003", "FUS-CRYPTO-004"}
        missing = expected - crypto_prdids
        assert not missing, f"缺少加密类规则: {missing}"

    def test_conf_rules_covered(self):
        conf_prdids = {r.prdid for r in self.engine._rules if r.prdid.startswith("FUS-CONF")}
        expected = {"FUS-CONF-001", "FUS-CONF-003", "FUS-CONF-004", "FUS-CONF-005"}
        missing = expected - conf_prdids
        assert not missing, f"缺少配置安全规则: {missing}"


class TestNewRuleDetection:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.engine = RuleEngine()

    def test_eval_detection(self):
        code = "eval(user_input)"
        results = self.engine.scan_file(Path("test.py"), code)
        eval_findings = [r for r in results if r.rule_id == "EVAL001"]
        assert eval_findings

    def test_ldap_detection(self):
        code = 'ldap.filter = "(uid=" + username + ")"'
        results = self.engine.scan_file(Path("test.py"), code)
        ldap_findings = [r for r in results if r.rule_id == "LDAP001"]
        assert ldap_findings

    def test_ssti_detection(self):
        code = "render_template_string(user_input)"
        results = self.engine.scan_file(Path("test.py"), code)
        ssti_findings = [r for r in results if r.rule_id == "SSTI001"]
        assert ssti_findings

    def test_weakpwd_detection(self):
        code = "min_length = 4"
        results = self.engine.scan_file(Path("test.py"), code)
        wp_findings = [r for r in results if r.rule_id == "WEAKPWD001"]
        assert wp_findings

    def test_jwt_detection(self):
        code = 'jwt.decode(token, algorithms=["none"])'
        results = self.engine.scan_file(Path("test.py"), code)
        jwt_findings = [r for r in results if r.rule_id == "JWT001"]
        assert jwt_findings

    def test_deser_detection(self):
        code = "pickle.loads(data)"
        results = self.engine.scan_file(Path("test.py"), code)
        deser_findings = [r for r in results if r.rule_id == "DESER001"]
        assert deser_findings

    def test_ssrf_detection(self):
        code = 'requests.get(request.args.get("url"))'
        results = self.engine.scan_file(Path("test.py"), code)
        ssrf_findings = [r for r in results if r.rule_id == "SSRF001"]
        assert ssrf_findings

    def test_csrf_detection(self):
        code = "@router.post('/transfer')"
        results = self.engine.scan_file(Path("test.py"), code)
        csrf_findings = [r for r in results if r.rule_id == "CSRF001"]
        assert csrf_findings

    def test_plaintext_detection(self):
        code = 'INSERT INTO users password VALUES "admin123"'
        results = self.engine.scan_file(Path("test.py"), code)
        pt_findings = [r for r in results if r.rule_id == "PLAINTEXT001"]
        assert pt_findings

    def test_cors_detection(self):
        code = "Access-Control-Allow-Origin: *"
        results = self.engine.scan_file(Path("test.py"), code)
        cors_findings = [r for r in results if r.rule_id == "CORS001"]
        assert cors_findings

    def test_insecrand_detection(self):
        code = "random.randint(0, 999999)"
        results = self.engine.scan_file(Path("test.py"), code)
        ir_findings = [r for r in results if r.rule_id == "INSECRAND001"]
        assert ir_findings

    def test_sslverify_detection(self):
        code = "requests.get(url, verify=False)"
        results = self.engine.scan_file(Path("test.py"), code)
        sv_findings = [r for r in results if r.rule_id == "SSLVERIFY001"]
        assert sv_findings

    def test_upload_detection(self):
        code = "os.path.join(upload_dir, file.filename)"
        results = self.engine.scan_file(Path("test.py"), code)
        up_findings = [r for r in results if r.rule_id == "UPLOAD001"]
        assert up_findings

    def test_header_detection(self):
        code = "Strict-Transport-Security"
        results = self.engine.scan_file(Path("test.py"), code)
        hdr_findings = [r for r in results if r.rule_id == "HEADER001"]
        assert hdr_findings

    def test_defpass_detection(self):
        code = 'default_password = "admin"'
        results = self.engine.scan_file(Path("test.py"), code)
        dp_findings = [r for r in results if r.rule_id == "DEFPASS001"]
        assert dp_findings


class TestDBConvertRule:
    def test_rule_to_orm_roundtrip(self):
        from fusion_security.db.convert import orm_to_rule, rule_to_orm
        from fusion_security.db.models import RuleORM

        r = Rule(
            id="SQL001",
            name="SQL注入",
            description="desc",
            severity="critical",
            cwe_id="CWE-89",
            pattern=r"test",
            prdid="FUS-INJ-001",
        )
        orm = rule_to_orm(r)
        assert isinstance(orm, RuleORM)
        assert orm.prdid == "FUS-INJ-001"
        back = orm_to_rule(orm)
        assert back.prdid == "FUS-INJ-001"
        assert back.id == r.id
