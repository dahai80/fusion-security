from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from ...models.vulnerability import Vulnerability
from .ast_parser import ASTParser

logger = logging.getLogger(__name__)

# LEGACY (guard-overlap) — rule matching engine. This module overlaps with fusion-guard's fg-rules (Rust),
# per issue #23 decision A, fusion-guard is the single source of truth for the overlapping capability; kept here until fusion-guard
# reaches parity and consumers migrate, then removed. See the repo-root DEPRECATED.md.


@dataclass
class ScanRule:
    id: str
    name: str
    description: str
    severity: str
    cwe_id: str
    pattern: str
    language: str = "all"
    fix_template: str = ""
    category: str = "injection"
    prdid: str = ""

    def to_rule(self):
        from ...models.rule import Rule

        return Rule(
            id=self.id,
            name=self.name,
            description=self.description,
            severity=self.severity,
            cwe_id=self.cwe_id,
            pattern=self.pattern,
            language=self.language,
            fix_template=self.fix_template,
            category=self.category,
            prdid=self.prdid,
        )


class RuleEngine:
    # Feature 1: supports injecting tenant custom rules (custom_rules), compiled merged with built-in rules.
    def __init__(self, custom_rules: list[ScanRule] | None = None):
        self._rules: list[ScanRule] = []
        self._compiled: list[tuple] = []
        self._ast_parser = ASTParser()
        self._init_rules()
        if custom_rules:
            for rule in custom_rules:
                self.add_rule(rule)
            logger.info(f"[RuleEngine] injected {len(custom_rules)} custom rules, {len(self._rules)} total")

    def _init_rules(self) -> None:
        rules = [
            ScanRule(
                "SQL001",
                "SQL injection",
                "SQL string concatenation without parameterized queries detected",
                "critical",
                "CWE-89",
                r"(?i)(execute\s*\(|exec\s*\(|query\s*\(|raw_query\s*\()",
                fix_template="Use parameterized queries instead of string concatenation",
                prdid="FUS-INJ-001",
            ),
            ScanRule(
                "SQL002",
                "SQL injection",
                "Direct concatenation of user input into SQL queries detected",
                "critical",
                "CWE-89",
                r"(?i)(SELECT\s+.*\s+FROM\s+.*\s*\+\s*|WHERE\s+.*\s*=\s*\'?\s*\+\s*\w+)",
                fix_template="Use parameterized queries or an ORM instead of concatenation",
                prdid="FUS-INJ-001",
            ),
            ScanRule(
                "XSS001",
                "Cross-site scripting (XSS)",
                "Unescaped user input output directly to HTML detected",
                "high",
                "CWE-79",
                r"(?i)(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)",
                fix_template="Use textContent instead of innerHTML, or a safe escaping function",
                prdid="FUS-INJ-003",
            ),
            ScanRule(
                "XSS002",
                "Cross-site scripting (XSS)",
                "Unfiltered user input rendering detected",
                "high",
                "CWE-79",
                r"(?i)(\.html\s*\(|\.append\(.*\w+\s*\)|v-html\s*=)",
                fix_template="Use a safe template engine with auto-escaping enabled",
                prdid="FUS-INJ-003",
            ),
            ScanRule(
                "CMD001",
                "Command injection",
                "System commands built from user input detected",
                "critical",
                "CWE-78",
                r"(?i)(os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(.*\s*\+\s*|Runtime\.getRuntime\(\)\.exec\s*\()",
                fix_template="Pass arguments as a list to subprocess.run instead of a string",
                prdid="FUS-INJ-002",
            ),
            ScanRule(
                "CMD002",
                "Command injection",
                "shell=True parameter detected",
                "high",
                "CWE-78",
                r"(?i)shell\s*=\s*True",
                fix_template="Avoid shell=True; pass arguments as a list",
                prdid="FUS-INJ-002",
            ),
            ScanRule(
                "PATH001",
                "Path traversal",
                "Unfiltered user input used in file paths detected",
                "high",
                "CWE-22",
                r"(?i)(open\s*\(.*\s*\+\s*|Path\(.*\s*\+\s*|os\.path\.join\(.*\w+\s*\))",
                fix_template="Normalize and validate user-input paths, restrict to allowed directories",
                prdid="FUS-ACL-003",
            ),
            # DEPRECATED (P1.2): superseded by engine/secrets (entropy +
            # provider validators + allowlist). Kept for backward compat;
            # findings now overlap with SEC-HIGH_ENTROPY_STRING / SEC-*.
            ScanRule(
                "SEC001",
                "Hardcoded secret",
                "Hardcoded API keys or passwords in code detected",
                "high",
                "CWE-798",
                r"(?i)(api_key\s*=\s*['\"][A-Za-z0-9_\-]{20,}|password\s*=\s*['\"][^'\"]{6,}|secret\s*=\s*['\"][^'\"]{10,})",
                fix_template="Store sensitive information in environment variables or a secret manager",
                prdid="FUS-AUTH-001",
            ),
            # DEPRECATED (P1.2): superseded by engine/secrets provider
            # validators (verified confidence class). Kept for backward compat.
            ScanRule(
                "SEC002",
                "Hardcoded token",
                "Hardcoded access tokens or keys detected",
                "critical",
                "CWE-798",
                r"(?i)(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36,}|AKIA[0-9A-Z]{16})",
                fix_template="Load tokens from environment variables or a secret manager",
                prdid="FUS-AUTH-001",
            ),
            ScanRule(
                "CRYPTO001",
                "Weak cryptographic algorithm",
                "Insecure cryptographic algorithm in use detected",
                "medium",
                "CWE-327",
                r"(?i)(MD5|SHA1|DES_|ECB\s*(?!.*GCM)|RSA/ECB)",
                fix_template="Use secure algorithms such as AES-GCM or SHA-256",
                prdid="FUS-CRYPTO-001",
            ),
            ScanRule(
                "AUTH001",
                "Missing authentication",
                "API endpoint without an authentication check detected",
                "high",
                "CWE-862",
                r"(?i)(@app\.route|@router\.(get|post|put|delete))\s*\n(?!.*@.*auth|.*@.*login|.*@.*token)",
                fix_template="Add an authentication decorator or middleware to the API endpoint",
                prdid="FUS-ACL-005",
            ),
            ScanRule(
                "XXE001",
                "XML external entity injection",
                "Insecure XML parser configuration detected",
                "high",
                "CWE-611",
                r"(?i)(XMLParser|SAXParser|DocumentBuilder).*?(resolveEntity|externalEntity|DTD)",
                fix_template="Disable external entity resolution: setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
                prdid="FUS-INJ-004",
            ),
            ScanRule(
                "REDIR001",
                "Open redirect",
                "Unvalidated user input used for redirects detected",
                "medium",
                "CWE-601",
                r"(?i)(redirect\s*\(.*\s*\+\s*|redirect_to\s*\(.*params|Location:\s*.*\s*\+\s*)",
                fix_template="Validate redirect URLs against an allowlist",
                prdid="FUS-CONF-005",
            ),
            ScanRule(
                "LOG001",
                "Log injection",
                "Unfiltered user input written to logs detected",
                "medium",
                "CWE-117",
                r"(?i)(logger\.(info|warn|error|debug)\s*\(.*\s*\+\s*\w+|logging\.(info|warn|error)\s*\(.*\s*\+\s*\w+)",
                fix_template="Filter newlines from user input before writing to logs",
                prdid="FUS-DATA-002",
            ),
            # ===== New rules: expression injection / LDAP / SSTI =====
            ScanRule(
                "EVAL001",
                "Expression injection",
                "eval/exec on user-controlled input detected",
                "critical",
                "CWE-94",
                r"(?i)(eval\s*\(|exec\s*\(|new\s+Function\s*\(|SpEL|OGNL|ExpressionParser)",
                fix_template="Do not use eval/exec on user input; use a safe parsing approach",
                category="injection",
                prdid="FUS-INJ-005",
            ),
            ScanRule(
                "LDAP001",
                "LDAP injection",
                "LDAP queries concatenated with user input detected",
                "medium",
                "CWE-90",
                r"(?i)(ldap.*search|ldap.*query|ldap.*filter\s*.*\+|search_s\s*\(|search_ext\s*\()",
                fix_template="Use parameterized LDAP queries and escape LDAP special characters in user input",
                category="injection",
                prdid="FUS-INJ-006",
            ),
            ScanRule(
                "SSTI001",
                "Template injection",
                "Server-side template engine receiving user-controlled content detected",
                "critical",
                "CWE-94",
                r"(?i)(render_template_string\s*\(|Jinja2.*render|Template\s*\(.*\+|\.render\s*\(.*request|Mako.*template)",
                fix_template="Use fixed template strings; never treat user input as template content",
                category="injection",
                prdid="FUS-INJ-007",
            ),
            # ===== New rules: authentication =====
            ScanRule(
                "WEAKPWD001",
                "Weak password policy",
                "Missing password complexity validation detected",
                "medium",
                "CWE-521",
                r"(?i)(password.*=.*request|min_length\s*=\s*[0-5]|password.*len\s*<\s*[6-8]|check_password\s*\(.*\)\s*:)",
                fix_template="Enforce password complexity: at least 8 characters with upper/lowercase letters, digits and special characters",
                category="auth",
                prdid="FUS-AUTH-002",
            ),
            ScanRule(
                "JWT001",
                "JWT configuration flaw",
                "JWT signature verification disabled or weak key detected",
                "high",
                "CWE-327",
                r"(?i)(verify\s*=\s*False|algorithms\s*=\s*\[.*none|jwt.*secret\s*=\s*['\"][^'\"]{0,5}|jwt.*decode.*verify\s*=\s*False)",
                fix_template="Enable JWT signature verification, use a strong key (at least 256 bits) and restrict allowed algorithms",
                category="auth",
                prdid="FUS-AUTH-003",
            ),
            ScanRule(
                "SESSFIX001",
                "Session fixation",
                "Session ID not regenerated after login detected",
                "medium",
                "CWE-384",
                r"(?i)(login.*session|session.*login|authenticate.*session)(?!.*regenerate|.*rotate|.*new_session)",
                fix_template="Call session.regenerate() after successful login to rotate the session ID",
                category="auth",
                prdid="FUS-AUTH-004",
            ),
            ScanRule(
                "CAPTCHA001",
                "Missing CAPTCHA",
                "Login/registration endpoints without CAPTCHA protection detected",
                "medium",
                "CWE-307",
                r"(?i)(@(app\.route|router)\.(post|get)\s*['\"/]*(login|register|signup|send_sms|send_code)(?!.*captcha|.*verify_code))",
                fix_template="Add CAPTCHA validation to login/registration/SMS-sending endpoints",
                category="auth",
                prdid="FUS-AUTH-005",
            ),
            # ===== New rules: access control =====
            ScanRule(
                "UPLOAD001",
                "Insecure file upload",
                "File upload without file type validation detected",
                "high",
                "CWE-434",
                r"(?i)(save.*file|write.*file|upload.*file|FileUpload|multipart.*file)(?!.*validate|.*check|.*whitelist|.*allowed)",
                fix_template="Validate uploaded files against an extension allowlist and MIME type; forbid executable uploads",
                category="acl",
                prdid="FUS-ACL-004",
            ),
            ScanRule(
                "BYPASS001",
                "API authorization bypass",
                "Bypass path in authentication middleware detected",
                "high",
                "CWE-862",
                r"(?i)(@app\.before_request|@middleware)(?!.*@login_required|.*@auth_required|.*@permission)|@(app\.route|router)\.(get|post|put|delete|patch)\s*['\"]/(admin|manage|config|internal|debug)",
                fix_template="Add a unified authentication middleware to all admin endpoints to prevent path bypass",
                category="acl",
                prdid="FUS-ACL-005",
            ),
            # ===== New rules: sensitive data =====
            ScanRule(
                "PLAINTEXT001",
                "Plaintext storage of sensitive data",
                "Passwords and other sensitive information stored in plaintext detected",
                "high",
                "CWE-312",
                r"(?i)(INSERT\s+INTO.*password\s+VALUES\s*['\"]|save.*password|store.*password|\.password\s*=\s*['\"])(?!.*hash|.*encrypt|.*bcrypt|.*argon)",
                fix_template="Hash passwords with bcrypt/argon2 before storage; never store plaintext passwords",
                category="data",
                prdid="FUS-DATA-001",
            ),
            ScanRule(
                "LOGLEAK001",
                "Sensitive data leaked to logs",
                "Log output containing passwords/tokens or other sensitive data detected",
                "medium",
                "CWE-532",
                r"(?i)(logger|logging|console\.log|print).*?(password|secret|token|api_key|access_key|private_key|credit_card)",
                fix_template="Mask sensitive fields before logging; never log passwords/tokens",
                category="data",
                prdid="FUS-DATA-002",
            ),
            ScanRule(
                "RESLEAK001",
                "API returns sensitive information",
                "API responses exposing excessive sensitive fields detected",
                "medium",
                "CWE-200",
                r"(?i)(return.*password|response.*secret|json.*private_key|\.to_dict\(\)|\.to_json\(\))(?!.*exclude|.*filter|.*sanitize)",
                fix_template="Filter sensitive fields from API responses using a serialization allowlist",
                category="data",
                prdid="FUS-DATA-003",
            ),
            # ===== New rules: cryptography =====
            ScanRule(
                "INSECRAND001",
                "Insecure randomness",
                "Pseudo-random numbers used for security-sensitive data detected",
                "medium",
                "CWE-338",
                r"(?i)(random\.(random|randint|choice|shuffle)|Math\.random\(\))(?!.*#.*not.security)",
                fix_template="Use the secrets module or os.urandom() for security-sensitive randomness such as tokens/keys",
                category="crypto",
                prdid="FUS-CRYPTO-003",
            ),
            ScanRule(
                "SSLVERIFY001",
                "SSL certificate verification disabled",
                "HTTPS requests with server certificate verification disabled detected",
                "high",
                "CWE-295",
                r"(?i)(verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*=\s*False|InsecureRequestWarning|check_hostname\s*=\s*False|ssl\._create_unverified_context)",
                fix_template="Enable SSL certificate verification; do not set verify=False",
                category="crypto",
                prdid="FUS-CRYPTO-004",
            ),
            # ===== New rules: security configuration =====
            ScanRule(
                "DEFPASS001",
                "Default credentials",
                "Default username/password configuration in use detected",
                "high",
                "CWE-798",
                r"(?i)(admin\s*[:=]\s*['\"]admin['\"]|root\s*[:=]\s*['\"]root['\"]|password\s*[:=]\s*['\"](admin|123456|password|root|test)['\"]|default_password)",
                fix_template="Change all default credentials, use strong passwords and rotate them regularly",
                category="config",
                prdid="FUS-CONF-001",
            ),
            ScanRule(
                "CORS001",
                "Overly permissive CORS",
                "Cross-origin configuration allowing any origin detected",
                "medium",
                "CWE-942",
                r"(?i)(Access-Control-Allow-Origin\s*:\s*\*|CORS.*origin.*\*|allow_origins\s*=\s*\[.*\*|cors.*\*.\*origin)",
                fix_template="Restrict CORS allowed origins to a known domain allowlist",
                category="config",
                prdid="FUS-CONF-003",
            ),
            ScanRule(
                "HEADER001",
                "Missing security response headers",
                "Missing security HTTP response header configuration detected",
                "low",
                "CWE-693",
                r"(?i)(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security)(?!(.*present|.*set|.*true|.*deny))",
                fix_template="Configure security headers: X-Frame-Options=DENY, X-Content-Type-Options=nosniff, CSP, HSTS",
                category="config",
                prdid="FUS-CONF-004",
            ),
            # ===== New rules: deserialization / SSRF / CSRF =====
            ScanRule(
                "DESER001",
                "Insecure deserialization",
                "Deserialization of user-controlled data detected",
                "critical",
                "CWE-502",
                r"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\(.*Loader|unserialize\s*\(|ObjectInputStream|readObject\s*\(|marshal\.loads?\s*\()",
                fix_template="Never deserialize untrusted data; use safe formats such as JSON instead",
                category="injection",
                prdid="FUS-DESER-001",
            ),
            ScanRule(
                "SSRF001",
                "SSRF (server-side request forgery)",
                "Server-side requests to user-controlled URLs detected",
                "high",
                "CWE-918",
                r"(?i)(requests\.(get|post)\s*\(.*request|urllib\.request\.urlopen\s*\(.*request|fetch\s*\(.*url.*request|http\.Client.*request)",
                fix_template="Validate user-supplied URLs against an allowlist; forbid requests to intranet addresses",
                category="injection",
                prdid="FUS-SSRF-001",
            ),
            ScanRule(
                "CSRF001",
                "CSRF (cross-site request forgery)",
                "State-changing endpoint without CSRF token validation detected",
                "medium",
                "CWE-352",
                r"(?i)@router\.(post|put|delete|patch)\s*\(['\"]/(user|account|password|transfer|delete|admin)",
                fix_template="Add CSRF token validation to state-changing endpoints",
                category="acl",
                prdid="FUS-CSRF-001",
            ),
            # ===== New rules: CRYPTO-002 / CONF-005 / DATA-004 =====
            ScanRule(
                "CRYPTO002",
                "Hardcoded encryption key",
                "Hardcoded encryption keys or AES keys in code detected",
                "high",
                "CWE-321",
                r"(?i)(encryption_key\s*=\s*['\"][^'\"]{8,}|aes_key\s*=\s*['\"][^'\"]{8,}|secret_key\s*=\s*['\"][^'\"]{10,}|private_key_pem\s*=\s*['\"][^'\"]{20,})",
                fix_template="Store encryption keys in a KMS or environment variables",
                category="crypto",
                prdid="FUS-CRYPTO-002",
            ),
            ScanRule(
                "DIRTRAVERS001",
                "Open directory listing",
                "Static file or directory listing without path restriction detected",
                "medium",
                "CWE-548",
                r"(?i)(serve_directory\s*\(|StaticFile\s*\(.*directory\s*=|send_from_directory\s*\(.*\.\.\/|DirectoryApp\s*\(|autoindex\s*=\s*True|listdir\s*\()",
                fix_template="Disable directory listing and restrict static file serving paths",
                category="config",
                prdid="FUS-CONF-005",
            ),
            ScanRule(
                "INSECURETRANS001",
                "Insecure data transfer",
                "Sensitive data sent over HTTP or with TLS verification disabled detected",
                "high",
                "CWE-319",
                r"(?i)(http://.*(?:password|token|secret|api_key|credit_card|ssn)|requests\.(get|post)\s*\(\s*['\"]http://|urlopen\s*\(\s*['\"]http://.*(?:password|token|secret))",
                fix_template="Transfer sensitive data over HTTPS with TLS certificate verification enabled",
                category="data",
                prdid="FUS-DATA-004",
            ),
        ]

        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule: ScanRule) -> None:
        try:
            compiled = re.compile(rule.pattern)
            self._rules.append(rule)
            self._compiled.append((rule, compiled))
        except re.error as e:
            logger.error(f"rule compilation failed {rule.id}: {e}")

    def scan_file_ast(self, file_path: Path, content: str) -> list[Vulnerability]:
        findings = []
        ast_result = self._ast_parser.parse(file_path, content)
        if not ast_result:
            return findings

        DANGEROUS_CALLS = {
            "execute",
            "exec",
            "query",
            "raw_query",
            "os.system",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.run",
            "eval",
            "innerHTML",
            "outerHTML",
            "document.write",
        }

        for call in ast_result.calls:
            name = call.get("name", "")
            base = name.split(".")[-1] if "." in name else name
            if base in DANGEROUS_CALLS or name in DANGEROUS_CALLS:
                rule_id = "AST_DANGEROUS_CALL"
                sev = "high"
                if base in ("execute", "exec", "query", "raw_query"):
                    rule_id = "AST_SQL001"
                    sev = "critical"
                elif base in ("system", "Popen", "run", "call") and "subprocess" in name:
                    rule_id = "AST_CMD001"
                    sev = "critical"
                elif base in ("eval",):
                    rule_id = "AST_EVAL001"
                    sev = "critical"

                lines = content.split("\n")
                line_no = call.get("line", 0)
                ctx_start = max(0, line_no - 3)
                ctx_end = min(len(lines), line_no + 2)
                snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(ctx_start, ctx_end))

                findings.append(
                    Vulnerability(
                        id=uuid.uuid4().hex[:16],
                        title=f"AST detection: dangerous call {name}",
                        description=f"Dangerous function call {name} detected, potential security risk",
                        severity=sev,
                        confidence=70,
                        file_path=str(file_path),
                        line_number=line_no,
                        code_snippet=snippet,
                        rule_id=rule_id,
                        cwe_id="CWE-000",
                        fix_suggestion="Check whether the call passes arguments safely",
                    )
                )

        for dec in ast_result.decorators:
            dec_name = dec.get("name", "")
            if "route" in dec_name or "app.get" in dec_name or "app.post" in dec_name:
                has_auth = False
                for other in ast_result.decorators:
                    other_name = other.get("name", "")
                    if any(k in other_name.lower() for k in ["auth", "login", "token", "require"]):
                        has_auth = True
                        break
                if not has_auth:
                    line_no = dec.get("line", 0)
                    lines = content.split("\n")
                    ctx_start = max(0, line_no - 1)
                    ctx_end = min(len(lines), line_no + 3)
                    snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(ctx_start, ctx_end))

                    findings.append(
                        Vulnerability(
                            id=uuid.uuid4().hex[:16],
                            title="AST detection: route without authentication",
                            description=f"Route decorator {dec_name} is not paired with an authentication decorator",
                            severity="high",
                            confidence=60,
                            file_path=str(file_path),
                            line_number=line_no,
                            code_snippet=snippet,
                            rule_id="AST_AUTH001",
                            cwe_id="CWE-862",
                            fix_suggestion="Add authentication middleware or a decorator to the route",
                        )
                    )

        return findings

    def scan_file(self, file_path: Path, content: str) -> list[Vulnerability]:
        findings = []
        lines = content.split("\n")

        for rule, pattern in self._compiled:
            for match in pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                context_start = max(0, line_no - 3)
                context_end = min(len(lines), line_no + 2)
                code_snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(context_start, context_end))

                vuln = Vulnerability(
                    id=f"{rule.id}_{file_path.stem}_{line_no}",
                    title=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=85,
                    file_path=str(file_path),
                    line_number=line_no,
                    code_snippet=code_snippet,
                    rule_id=rule.id,
                    cwe_id=rule.cwe_id,
                    fix_suggestion=rule.fix_template,
                )
                findings.append(vuln)

        return findings

    def scan_file_full(self, file_path: Path, content: str) -> list[Vulnerability]:
        findings = self.scan_file(file_path, content)
        findings.extend(self.scan_file_ast(file_path, content))
        return findings

    def get_rules(self, category: str = "") -> list[ScanRule]:
        if not category:
            return self._rules
        return [r for r in self._rules if r.category == category]

    def get_rule_count(self) -> int:
        return len(self._rules)


@dataclass
class AISemanticRule:
    id: str
    name: str
    description: str
    severity: str
    cwe_id: str
    category: str
    prdid: str
    prompt_hint: str
    fix_template: str = ""


AI_SEMANTIC_RULES: list[AISemanticRule] = [
    AISemanticRule(
        "AI_ACL001",
        "Horizontal privilege escalation",
        "A user can access resources belonging to other users at the same level",
        "high",
        "CWE-639",
        "acl",
        "FUS-ACL-001",
        "Check whether user ID parameters are used directly in data queries without verifying the current user's permission, e.g. accessing other users' data by changing user_id/order_id parameters",
        "Verify the current user's access to the target resource before querying data, using an RBAC or ABAC permission model",
    ),
    AISemanticRule(
        "AI_ACL002",
        "Vertical privilege escalation",
        "Low-privilege users can access high-privilege functions",
        "high",
        "CWE-862",
        "acl",
        "FUS-ACL-002",
        "Check whether low-privilege users can call admin endpoints, e.g. the frontend hides admin buttons but the backend does not verify roles",
        "All backend admin endpoints must verify user roles; do not rely on hiding frontend features",
    ),
    AISemanticRule(
        "AI_AUTH006",
        "Missing multi-factor authentication",
        "Critical operations without multi-factor authentication",
        "medium",
        "CWE-308",
        "auth",
        "FUS-AUTH-006",
        "Check whether critical operations such as login, fund transfers and permission changes lack secondary verification, e.g. SMS codes, TOTP or email verification",
        "Add multi-factor authentication (MFA) to critical operations, e.g. TOTP for login and SMS verification for fund operations",
    ),
    AISemanticRule(
        "AI_CONF002",
        "Detailed error message disclosure",
        "Error responses contain stack traces or internal information",
        "medium",
        "CWE-209",
        "config",
        "FUS-CONF-002",
        "Check whether error handling exposes stack traces, SQL statements, internal paths or other sensitive information to users",
        "Use a unified error page in production, do not return detailed error information, and log the error details",
    ),
    AISemanticRule(
        "AI_LOGIC001",
        "Payment amount tampering",
        "Payment amounts can be tampered with by the client during the payment flow",
        "critical",
        "CWE-841",
        "logic",
        "FUS-LOGIC-001",
        "Check whether order amounts in the payment flow are read from the server rather than trusting client-submitted amount parameters",
        "Order amounts must be read from the server database; do not trust client-submitted amount parameters",
    ),
    AISemanticRule(
        "AI_LOGIC002",
        "Race condition",
        "Data inconsistency caused by concurrent operations",
        "high",
        "CWE-362",
        "logic",
        "FUS-LOGIC-002",
        "Check for unlocked concurrent operations, e.g. balance deduction, stock deduction or coupon claiming lacking atomicity guarantees",
        "Use database transactions and row-level locks for atomicity, or distributed locks for concurrent operations",
    ),
    AISemanticRule(
        "AI_LOGIC003",
        "Business flow bypass",
        "Critical business steps can be skipped",
        "high",
        "CWE-841",
        "logic",
        "FUS-LOGIC-003",
        "Check whether the business flow can be skipped, e.g. accessing later-step URLs directly to bypass prior validation or skipping approval flows",
        "Manage business flows with a state machine; validate the prior state at each step and do not rely on URL ordering to control the flow",
    ),
    AISemanticRule(
        "AI_LOGIC004",
        "Missing data integrity validation",
        "Critical data lacks integrity verification",
        "medium",
        "CWE-345",
        "logic",
        "FUS-LOGIC-004",
        "Check whether critical data lacks integrity checks during transfer or storage, e.g. signature or hash verification",
        "Add HMAC signatures or hash verification to critical data to ensure it has not been tampered with",
    ),
]
