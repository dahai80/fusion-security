from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from ...models.vulnerability import Vulnerability
from .ast_parser import ASTParser

logger = logging.getLogger(__name__)


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
    def __init__(self):
        self._rules: list[ScanRule] = []
        self._compiled: list[tuple] = []
        self._ast_parser = ASTParser()
        self._init_rules()

    def _init_rules(self) -> None:
        rules = [
            ScanRule(
                "SQL001",
                "SQL注入",
                "检测到未使用参数化查询的SQL拼接",
                "critical",
                "CWE-89",
                r"(?i)(execute\s*\(|exec\s*\(|query\s*\(|raw_query\s*\()",
                fix_template="使用参数化查询替代字符串拼接",
                prdid="FUS-INJ-001",
            ),
            ScanRule(
                "SQL002",
                "SQL注入",
                "检测到直接拼接用户输入的SQL查询",
                "critical",
                "CWE-89",
                r"(?i)(SELECT\s+.*\s+FROM\s+.*\s*\+\s*|WHERE\s+.*\s*=\s*\'?\s*\+\s*\w+)",
                fix_template="使用参数化查询或ORM替代拼接",
                prdid="FUS-INJ-001",
            ),
            ScanRule(
                "XSS001",
                "跨站脚本(XSS)",
                "检测到未转义的用户输入直接输出到HTML",
                "high",
                "CWE-79",
                r"(?i)(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)",
                fix_template="使用textContent替代innerHTML，或使用安全的转义函数",
                prdid="FUS-INJ-003",
            ),
            ScanRule(
                "XSS002",
                "跨站脚本(XSS)",
                "检测到未经过滤的用户输入渲染",
                "high",
                "CWE-79",
                r"(?i)(\.html\s*\(|\.append\(.*\w+\s*\)|v-html\s*=)",
                fix_template="使用安全的模板引擎并启用自动转义",
                prdid="FUS-INJ-003",
            ),
            ScanRule(
                "CMD001",
                "命令注入",
                "检测到使用用户输入构建系统命令",
                "critical",
                "CWE-78",
                r"(?i)(os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(.*\s*\+\s*|Runtime\.getRuntime\(\)\.exec\s*\()",
                fix_template="使用subprocess.run传入参数列表而非字符串",
                prdid="FUS-INJ-002",
            ),
            ScanRule(
                "CMD002",
                "命令注入",
                "检测到shell=True参数",
                "high",
                "CWE-78",
                r"(?i)shell\s*=\s*True",
                fix_template="避免使用shell=True，使用参数列表传递",
                prdid="FUS-INJ-002",
            ),
            ScanRule(
                "PATH001",
                "路径穿越",
                "检测到未经过滤的用户输入用于文件路径",
                "high",
                "CWE-22",
                r"(?i)(open\s*\(.*\s*\+\s*|Path\(.*\s*\+\s*|os\.path\.join\(.*\w+\s*\))",
                fix_template="对用户输入进行路径规范化检查，限制在允许目录内",
                prdid="FUS-ACL-003",
            ),
            ScanRule(
                "SEC001",
                "硬编码密钥",
                "检测到代码中硬编码的API密钥或密码",
                "high",
                "CWE-798",
                r"(?i)(api_key\s*=\s*['\"][A-Za-z0-9_\-]{20,}|password\s*=\s*['\"][^'\"]{6,}|secret\s*=\s*['\"][^'\"]{10,})",
                fix_template="使用环境变量或密钥管理服务存储敏感信息",
                prdid="FUS-AUTH-001",
            ),
            ScanRule(
                "SEC002",
                "硬编码令牌",
                "检测到硬编码的访问令牌或密钥",
                "critical",
                "CWE-798",
                r"(?i)(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36,}|AKIA[0-9A-Z]{16})",
                fix_template="从环境变量或密钥管理服务加载令牌",
                prdid="FUS-AUTH-001",
            ),
            ScanRule(
                "CRYPTO001",
                "弱加密算法",
                "检测到使用不安全的加密算法",
                "medium",
                "CWE-327",
                r"(?i)(MD5|SHA1|DES_|ECB\s*(?!.*GCM)|RSA/ECB)",
                fix_template="使用安全的加密算法如AES-GCM、SHA-256",
                prdid="FUS-CRYPTO-001",
            ),
            ScanRule(
                "AUTH001",
                "缺少鉴权",
                "检测到API端点缺少鉴权检查",
                "high",
                "CWE-862",
                r"(?i)(@app\.route|@router\.(get|post|put|delete))\s*\n(?!.*@.*auth|.*@.*login|.*@.*token)",
                fix_template="为API端点添加鉴权装饰器或中间件",
                prdid="FUS-ACL-005",
            ),
            ScanRule(
                "XXE001",
                "XML外部实体注入",
                "检测到不安全的XML解析配置",
                "high",
                "CWE-611",
                r"(?i)(XMLParser|SAXParser|DocumentBuilder).*?(resolveEntity|externalEntity|DTD)",
                fix_template="禁止外部实体解析：setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
                prdid="FUS-INJ-004",
            ),
            ScanRule(
                "REDIR001",
                "开放重定向",
                "检测到未经验证的用户输入用于重定向",
                "medium",
                "CWE-601",
                r"(?i)(redirect\s*\(.*\s*\+\s*|redirect_to\s*\(.*params|Location:\s*.*\s*\+\s*)",
                fix_template="对重定向URL进行白名单验证",
                prdid="FUS-CONF-005",
            ),
            ScanRule(
                "LOG001",
                "日志注入",
                "检测到未经过滤的用户输入写入日志",
                "medium",
                "CWE-117",
                r"(?i)(logger\.(info|warn|error|debug)\s*\(.*\s*\+\s*\w+|logging\.(info|warn|error)\s*\(.*\s*\+\s*\w+)",
                fix_template="对用户输入进行换行符过滤后再写入日志",
                prdid="FUS-DATA-002",
            ),
            # ===== 新增规则: 表达式注入 / LDAP / SSTI =====
            ScanRule(
                "EVAL001",
                "表达式注入",
                "检测到eval/exec执行用户可控输入",
                "critical",
                "CWE-94",
                r"(?i)(eval\s*\(|exec\s*\(|new\s+Function\s*\(|SpEL|OGNL|ExpressionParser)",
                fix_template="禁止使用eval/exec执行用户输入，使用安全的解析方式",
                category="injection",
                prdid="FUS-INJ-005",
            ),
            ScanRule(
                "LDAP001",
                "LDAP注入",
                "检测到LDAP查询拼接用户输入",
                "medium",
                "CWE-90",
                r"(?i)(ldap.*search|ldap.*query|ldap.*filter\s*.*\+|search_s\s*\(|search_ext\s*\()",
                fix_template="使用参数化LDAP查询，对用户输入进行LDAP特殊字符转义",
                category="injection",
                prdid="FUS-INJ-006",
            ),
            ScanRule(
                "SSTI001",
                "模板注入",
                "检测到服务端模板引擎接收用户可控内容",
                "critical",
                "CWE-94",
                r"(?i)(render_template_string\s*\(|Jinja2.*render|Template\s*\(.*\+|\.render\s*\(.*request|Mako.*template)",
                fix_template="使用固定模板字符串，不将用户输入作为模板内容",
                category="injection",
                prdid="FUS-INJ-007",
            ),
            # ===== 新增规则: 认证类 =====
            ScanRule(
                "WEAKPWD001",
                "弱密码策略",
                "检测到密码复杂度校验缺失",
                "medium",
                "CWE-521",
                r"(?i)(password.*=.*request|min_length\s*=\s*[0-5]|password.*len\s*<\s*[6-8]|check_password\s*\(.*\)\s*:)",
                fix_template="设置密码复杂度要求：最少8位，包含大小写字母、数字和特殊字符",
                category="auth",
                prdid="FUS-AUTH-002",
            ),
            ScanRule(
                "JWT001",
                "JWT配置缺陷",
                "检测到JWT签名校验禁用或弱密钥",
                "high",
                "CWE-327",
                r"(?i)(verify\s*=\s*False|algorithms\s*=\s*\[.*none|jwt.*secret\s*=\s*['\"][^'\"]{0,5}|jwt.*decode.*verify\s*=\s*False)",
                fix_template="启用JWT签名校验，使用强密钥（至少256位），限制允许的算法列表",
                category="auth",
                prdid="FUS-AUTH-003",
            ),
            ScanRule(
                "SESSFIX001",
                "会话固定攻击",
                "检测到登录后未重新生成会话ID",
                "medium",
                "CWE-384",
                r"(?i)(login.*session|session.*login|authenticate.*session)(?!.*regenerate|.*rotate|.*new_session)",
                fix_template="登录成功后调用session.regenerate()重新生成会话ID",
                category="auth",
                prdid="FUS-AUTH-004",
            ),
            ScanRule(
                "CAPTCHA001",
                "验证码缺失",
                "检测到登录/注册接口无验证码保护",
                "medium",
                "CWE-307",
                r"(?i)(@(app\.route|router)\.(post|get)\s*['\"/]*(login|register|signup|send_sms|send_code)(?!.*captcha|.*verify_code))",
                fix_template="为登录/注册/短信发送接口添加验证码校验",
                category="auth",
                prdid="FUS-AUTH-005",
            ),
            # ===== 新增规则: 访问控制类 =====
            ScanRule(
                "UPLOAD001",
                "不安全文件上传",
                "检测到文件上传功能未校验文件类型",
                "high",
                "CWE-434",
                r"(?i)(save.*file|write.*file|upload.*file|FileUpload|multipart.*file)(?!.*validate|.*check|.*whitelist|.*allowed)",
                fix_template="校验上传文件的扩展名白名单和MIME类型，禁止上传可执行文件",
                category="acl",
                prdid="FUS-ACL-004",
            ),
            ScanRule(
                "BYPASS001",
                "接口权限绕过",
                "检测到鉴权中间件存在绕过路径",
                "high",
                "CWE-862",
                r"(?i)(@app\.before_request|@middleware)(?!.*@login_required|.*@auth_required|.*@permission)|@(app\.route|router)\.(get|post|put|delete|patch)\s*['\"]/(admin|manage|config|internal|debug)",
                fix_template="为所有管理接口添加统一的鉴权中间件，避免路径绕过",
                category="acl",
                prdid="FUS-ACL-005",
            ),
            # ===== 新增规则: 敏感数据类 =====
            ScanRule(
                "PLAINTEXT001",
                "敏感数据明文存储",
                "检测到密码等敏感信息明文存储",
                "high",
                "CWE-312",
                r"(?i)(INSERT\s+INTO.*password\s+VALUES\s*['\"]|save.*password|store.*password|\.password\s*=\s*['\"])(?!.*hash|.*encrypt|.*bcrypt|.*argon)",
                fix_template="使用bcrypt/argon2对密码进行哈希后再存储，绝不存储明文密码",
                category="data",
                prdid="FUS-DATA-001",
            ),
            ScanRule(
                "LOGLEAK001",
                "日志泄露敏感信息",
                "检测到日志输出包含密码/Token等敏感数据",
                "medium",
                "CWE-532",
                r"(?i)(logger|logging|console\.log|print).*?(password|secret|token|api_key|access_key|private_key|credit_card)",
                fix_template="在日志输出前脱敏处理敏感字段，不记录密码/Token等数据",
                category="data",
                prdid="FUS-DATA-002",
            ),
            ScanRule(
                "RESLEAK001",
                "接口返回敏感信息",
                "检测到接口返回多余敏感字段",
                "medium",
                "CWE-200",
                r"(?i)(return.*password|response.*secret|json.*private_key|\.to_dict\(\)|\.to_json\(\))(?!.*exclude|.*filter|.*sanitize)",
                fix_template="接口返回数据时过滤敏感字段，使用序列化白名单机制",
                category="data",
                prdid="FUS-DATA-003",
            ),
            # ===== 新增规则: 密码学类 =====
            ScanRule(
                "INSECRAND001",
                "不安全随机数",
                "检测到使用伪随机数生成安全敏感数据",
                "medium",
                "CWE-338",
                r"(?i)(random\.(random|randint|choice|shuffle)|Math\.random\(\))(?!.*#.*not.security)",
                fix_template="使用secrets模块或os.urandom()生成Token/密钥等安全敏感随机数",
                category="crypto",
                prdid="FUS-CRYPTO-003",
            ),
            ScanRule(
                "SSLVERIFY001",
                "SSL证书校验禁用",
                "检测到HTTPS请求禁用服务端证书校验",
                "high",
                "CWE-295",
                r"(?i)(verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*=\s*False|InsecureRequestWarning|check_hostname\s*=\s*False|ssl\._create_unverified_context)",
                fix_template="启用SSL证书校验，不要设置verify=False",
                category="crypto",
                prdid="FUS-CRYPTO-004",
            ),
            # ===== 新增规则: 安全配置类 =====
            ScanRule(
                "DEFPASS001",
                "默认账号密码",
                "检测到使用默认账号密码配置",
                "high",
                "CWE-798",
                r"(?i)(admin\s*[:=]\s*['\"]admin['\"]|root\s*[:=]\s*['\"]root['\"]|password\s*[:=]\s*['\"](admin|123456|password|root|test)['\"]|default_password)",
                fix_template="修改所有默认账号密码，使用强密码并定期轮换",
                category="config",
                prdid="FUS-CONF-001",
            ),
            ScanRule(
                "CORS001",
                "CORS配置过宽",
                "检测到跨域配置允许任意来源",
                "medium",
                "CWE-942",
                r"(?i)(Access-Control-Allow-Origin\s*:\s*\*|CORS.*origin.*\*|allow_origins\s*=\s*\[.*\*|cors.*\*.\*origin)",
                fix_template="限制CORS允许的来源为已知域名白名单",
                category="config",
                prdid="FUS-CONF-003",
            ),
            ScanRule(
                "HEADER001",
                "安全响应头缺失",
                "检测到缺少安全HTTP响应头配置",
                "low",
                "CWE-693",
                r"(?i)(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security)(?!(.*present|.*set|.*true|.*deny))",
                fix_template="配置安全响应头: X-Frame-Options=DENY, X-Content-Type-Options=nosniff, CSP, HSTS",
                category="config",
                prdid="FUS-CONF-004",
            ),
            # ===== 新增规则: 反序列化/SSRF/CSRF =====
            ScanRule(
                "DESER001",
                "不安全反序列化",
                "检测到反序列化用户可控数据",
                "critical",
                "CWE-502",
                r"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\(.*Loader|unserialize\s*\(|ObjectInputStream|readObject\s*\(|marshal\.loads?\s*\()",
                fix_template="禁止反序列化不可信数据，使用JSON等安全格式替代",
                category="injection",
                prdid="FUS-DESER-001",
            ),
            ScanRule(
                "SSRF001",
                "SSRF服务端请求伪造",
                "检测到服务端请求用户可控URL",
                "high",
                "CWE-918",
                r"(?i)(requests\.(get|post)\s*\(.*request|urllib\.request\.urlopen\s*\(.*request|fetch\s*\(.*url.*request|http\.Client.*request)",
                fix_template="对用户输入的URL进行白名单校验，禁止请求内网地址",
                category="injection",
                prdid="FUS-SSRF-001",
            ),
            ScanRule(
                "CSRF001",
                "CSRF跨站请求伪造",
                "检测到状态变更接口无CSRF Token校验",
                "medium",
                "CWE-352",
                r"(?i)@router\.(post|put|delete|patch)\s*\(['\"]/(user|account|password|transfer|delete|admin)",
                fix_template="为状态变更接口添加CSRF Token校验",
                category="acl",
                prdid="FUS-CSRF-001",
            ),
            # ===== 新增规则: CRYPTO-002 / CONF-005 / DATA-004 =====
            ScanRule(
                "CRYPTO002",
                "硬编码加密密钥",
                "检测到代码中硬编码的加密密钥或AES密钥",
                "high",
                "CWE-321",
                r"(?i)(encryption_key\s*=\s*['\"][^'\"]{8,}|aes_key\s*=\s*['\"][^'\"]{8,}|secret_key\s*=\s*['\"][^'\"]{10,}|private_key_pem\s*=\s*['\"][^'\"]{20,})",
                fix_template="使用密钥管理服务(KMS)或环境变量存储加密密钥",
                category="crypto",
                prdid="FUS-CRYPTO-002",
            ),
            ScanRule(
                "DIRTRAVERS001",
                "目录遍历开放",
                "检测到静态文件或目录列表功能未限制路径",
                "medium",
                "CWE-548",
                r"(?i)(serve_directory\s*\(|StaticFile\s*\(.*directory\s*=|send_from_directory\s*\(.*\.\.\/|DirectoryApp\s*\(|autoindex\s*=\s*True|listdir\s*\()",
                fix_template="禁止目录列表功能，限制静态文件服务的访问路径",
                category="config",
                prdid="FUS-CONF-005",
            ),
            ScanRule(
                "INSECURETRANS001",
                "不安全数据传输",
                "检测到使用HTTP传输敏感数据或禁用TLS校验",
                "high",
                "CWE-319",
                r"(?i)(http://.*(?:password|token|secret|api_key|credit_card|ssn)|requests\.(get|post)\s*\(\s*['\"]http://|urlopen\s*\(\s*['\"]http://.*(?:password|token|secret))",
                fix_template="使用HTTPS传输敏感数据，确保TLS证书校验启用",
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
            logger.error(f"规则编译失败 {rule.id}: {e}")

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
                        title=f"AST检测: 危险调用 {name}",
                        description=f"检测到危险函数调用 {name}，可能存在安全风险",
                        severity=sev,
                        confidence=70,
                        file_path=str(file_path),
                        line_number=line_no,
                        code_snippet=snippet,
                        rule_id=rule_id,
                        cwe_id="CWE-000",
                        fix_suggestion="检查该调用是否使用了安全的参数传递方式",
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
                            title="AST检测: 缺少鉴权的路由",
                            description=f"路由装饰器 {dec_name} 未搭配鉴权装饰器",
                            severity="high",
                            confidence=60,
                            file_path=str(file_path),
                            line_number=line_no,
                            code_snippet=snippet,
                            rule_id="AST_AUTH001",
                            cwe_id="CWE-862",
                            fix_suggestion="为路由添加鉴权中间件或装饰器",
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
        "水平越权访问",
        "用户可访问同级别其他用户的资源",
        "high",
        "CWE-639",
        "acl",
        "FUS-ACL-001",
        "检查是否存在用户ID参数直接用于数据查询而未校验当前用户权限的情况，例如通过修改user_id/order_id参数访问他人数据",
        "在数据查询前校验当前用户是否有权访问目标资源，使用RBAC或ABAC权限模型",
    ),
    AISemanticRule(
        "AI_ACL002",
        "垂直越权访问",
        "低权限用户可访问高权限功能",
        "high",
        "CWE-862",
        "acl",
        "FUS-ACL-002",
        "检查是否存在低权限用户可调用管理接口的情况，例如前端隐藏了管理按钮但后端未做角色校验",
        "后端所有管理接口必须校验用户角色，不依赖前端隐藏功能",
    ),
    AISemanticRule(
        "AI_AUTH006",
        "多因素认证缺失",
        "关键操作未启用多因素认证",
        "medium",
        "CWE-308",
        "auth",
        "FUS-AUTH-006",
        "检查登录、资金操作、权限变更等关键操作是否缺少二次验证，如短信验证码、TOTP、邮箱验证等",
        "为关键操作添加多因素认证(MFA)，如登录添加TOTP，资金操作添加短信验证",
    ),
    AISemanticRule(
        "AI_CONF002",
        "详细错误信息泄露",
        "错误响应包含堆栈跟踪或内部信息",
        "medium",
        "CWE-209",
        "config",
        "FUS-CONF-002",
        "检查错误处理是否将堆栈跟踪、SQL语句、内部路径等敏感信息暴露给用户",
        "生产环境使用统一错误页面，不返回详细错误信息，将错误详情记录到日志",
    ),
    AISemanticRule(
        "AI_LOGIC001",
        "支付金额篡改",
        "支付流程中金额可被客户端篡改",
        "critical",
        "CWE-841",
        "logic",
        "FUS-LOGIC-001",
        "检查支付流程中订单金额是否从服务端获取，而非信任客户端提交的金额参数",
        "订单金额必须从服务端数据库读取，不信任客户端提交的金额参数",
    ),
    AISemanticRule(
        "AI_LOGIC002",
        "竞态条件",
        "并发操作导致的数据不一致",
        "high",
        "CWE-362",
        "logic",
        "FUS-LOGIC-002",
        "检查是否存在未加锁的并发操作，如余额扣减、库存扣减、优惠券领取等场景缺乏原子性保证",
        "使用数据库事务和行级锁保证原子性，或使用分布式锁处理并发操作",
    ),
    AISemanticRule(
        "AI_LOGIC003",
        "业务流程绕过",
        "关键业务步骤可被跳过",
        "high",
        "CWE-841",
        "logic",
        "FUS-LOGIC-003",
        "检查业务流程是否可被跳过，例如直接访问后续步骤URL绕过前置验证、跳过审批流程等",
        "使用状态机管理业务流程，每个步骤校验前置状态，不依赖URL顺序控制流程",
    ),
    AISemanticRule(
        "AI_LOGIC004",
        "数据完整性校验缺失",
        "关键数据缺乏完整性验证",
        "medium",
        "CWE-345",
        "logic",
        "FUS-LOGIC-004",
        "检查关键数据是否在传输或存储时缺乏完整性校验，如签名验证、哈希校验等",
        "对关键数据添加HMAC签名或哈希校验，确保数据未被篡改",
    ),
]
