"""规则引擎 — 代码安全漏洞检测规则。

对标 Claude Security 的规则覆盖：
SQL注入、XSS、命令注入、路径穿越、硬编码密钥、不安全API鉴权等。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """漏洞定义。"""
    id: str
    title: str
    description: str
    severity: str  # critical | high | medium | low
    confidence: float  # 0.0 - 1.0
    file_path: str
    line_number: int
    code_snippet: str
    rule_id: str = ""
    cwe_id: str = ""
    fix_suggestion: str = ""
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet[:200],
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "fix_suggestion": self.fix_suggestion,
            "verified": self.verified,
        }


@dataclass
class ScanRule:
    """扫描规则定义。"""
    id: str
    name: str
    description: str
    severity: str
    cwe_id: str
    pattern: str
    language: str = "all"  # all | python | javascript | java | etc.
    fix_template: str = ""
    category: str = "injection"  # injection | xss | crypto | config | auth


class RuleEngine:
    """规则引擎 — 基于正则 + 语义的漏洞检测。

    对标 Claude Security 的规则覆盖能力。
    """

    def __init__(self):
        self._rules: List[ScanRule] = []
        self._compiled: List[tuple[ScanRule, Pattern]] = []
        self._init_rules()

    def _init_rules(self) -> None:
        """初始化内置规则。"""
        rules = [
            # SQL注入
            ScanRule("SQL001", "SQL注入", "检测到未使用参数化查询的SQL拼接", "critical", "CWE-89",
                     r"(?i)(execute\s*\(|exec\s*\(|query\s*\(|raw_query\s*\()",
                     fix_template="使用参数化查询替代字符串拼接"),
            ScanRule("SQL002", "SQL注入", "检测到直接拼接用户输入的SQL查询", "critical", "CWE-89",
                     r"(?i)(SELECT\s+.*\s+FROM\s+.*\s*\+\s*|WHERE\s+.*\s*=\s*\'?\s*\+\s*\w+)",
                     fix_template="使用参数化查询或ORM替代拼接"),

            # XSS
            ScanRule("XSS001", "跨站脚本(XSS)", "检测到未转义的用户输入直接输出到HTML", "high", "CWE-79",
                     r"(?i)(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)",
                     fix_template="使用textContent替代innerHTML，或使用安全的转义函数"),
            ScanRule("XSS002", "跨站脚本(XSS)", "检测到未经过滤的用户输入渲染", "high", "CWE-79",
                     r"(?i)(\.html\s*\(|\.append\(.*\w+\s*\)|v-html\s*=)",
                     fix_template="使用安全的模板引擎并启用自动转义"),

            # 命令注入
            ScanRule("CMD001", "命令注入", "检测到使用用户输入构建系统命令", "critical", "CWE-78",
                     r"(?i)(os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(.*\s*\+\s*|Runtime\.getRuntime\(\)\.exec\s*\()",
                     fix_template="使用subprocess.run传入参数列表而非字符串"),
            ScanRule("CMD002", "命令注入", "检测到shell=True参数", "high", "CWE-78",
                     r"(?i)shell\s*=\s*True",
                     fix_template="避免使用shell=True，使用参数列表传递"),

            # 路径穿越
            ScanRule("PATH001", "路径穿越", "检测到未经过滤的用户输入用于文件路径", "high", "CWE-22",
                     r"(?i)(open\s*\(.*\s*\+\s*|Path\(.*\s*\+\s*|os\.path\.join\(.*\w+\s*\))",
                     fix_template="对用户输入进行路径规范化检查，限制在允许目录内"),

            # 硬编码密钥
            ScanRule("SEC001", "硬编码密钥", "检测到代码中硬编码的API密钥或密码", "high", "CWE-798",
                     r"(?i)(api_key\s*=\s*['\"][A-Za-z0-9_\-]{20,}|password\s*=\s*['\"][^'\"]{6,}|secret\s*=\s*['\"][^'\"]{10,})",
                     fix_template="使用环境变量或密钥管理服务存储敏感信息"),
            ScanRule("SEC002", "硬编码令牌", "检测到硬编码的访问令牌或密钥", "critical", "CWE-798",
                     r"(?i)(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36,}|AKIA[0-9A-Z]{16})",
                     fix_template="从环境变量或密钥管理服务加载令牌"),

            # 不安全加密
            ScanRule("CRYPTO001", "弱加密算法", "检测到使用不安全的加密算法", "medium", "CWE-327",
                     r"(?i)(MD5|SHA1|DES_|ECB\s*(?!.*GCM)|RSA/ECB)",
                     fix_template="使用安全的加密算法如AES-GCM、SHA-256"),

            # 不安全API鉴权
            ScanRule("AUTH001", "缺少鉴权", "检测到API端点缺少鉴权检查", "high", "CWE-862",
                     r"(?i)(@app\.route|@router\.(get|post|put|delete))\s*\n(?!.*@.*auth|.*@.*login|.*@.*token)",
                     fix_template="为API端点添加鉴权装饰器或中间件"),

            # XXE
            ScanRule("XXE001", "XML外部实体注入", "检测到不安全的XML解析配置", "high", "CWE-611",
                     r"(?i)(XMLParser|SAXParser|DocumentBuilder).*?(resolveEntity|externalEntity|DTD)",
                     fix_template="禁止外部实体解析：setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)"),

            # 重定向
            ScanRule("REDIR001", "开放重定向", "检测到未经验证的用户输入用于重定向", "medium", "CWE-601",
                     r"(?i)(redirect\s*\(.*\s*\+\s*|redirect_to\s*\(.*params|Location:\s*.*\s*\+\s*)",
                     fix_template="对重定向URL进行白名单验证"),

            # 日志注入
            ScanRule("LOG001", "日志注入", "检测到未经过滤的用户输入写入日志", "medium", "CWE-117",
                     r"(?i)(logger\.(info|warn|error|debug)\s*\(.*\s*\+\s*\w+|logging\.(info|warn|error)\s*\(.*\s*\+\s*\w+)",
                     fix_template="对用户输入进行换行符过滤后再写入日志"),
        ]

        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule: ScanRule) -> None:
        """添加规则。"""
        try:
            compiled = re.compile(rule.pattern)
            self._rules.append(rule)
            self._compiled.append((rule, compiled))
        except re.error as e:
            logger.error(f"规则编译失败 {rule.id}: {e}")

    def scan_file(self, file_path: Path, content: str) -> List[Vulnerability]:
        """扫描单个文件。"""
        findings = []
        lines = content.split("\n")

        for rule, pattern in self._compiled:
            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                snippet = content[start:end].strip()

                # 生成行号附近的代码片段
                context_start = max(0, line_no - 3)
                context_end = min(len(lines), line_no + 2)
                code_snippet = "\n".join(
                    f"{i+1}: {lines[i]}" for i in range(context_start, context_end)
                )

                vuln = Vulnerability(
                    id=f"{rule.id}_{file_path.stem}_{line_no}",
                    title=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=0.85,
                    file_path=str(file_path),
                    line_number=line_no,
                    code_snippet=code_snippet,
                    rule_id=rule.id,
                    cwe_id=rule.cwe_id,
                    fix_suggestion=rule.fix_template,
                )
                findings.append(vuln)

        return findings

    def get_rules(self, category: str = "") -> List[ScanRule]:
        """获取规则列表。"""
        if not category:
            return self._rules
        return [r for r in self._rules if r.category == category]

    def get_rule_count(self) -> int:
        return len(self._rules)