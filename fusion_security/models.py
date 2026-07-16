"""共享数据模型 — 所有模块公用的数据类。

提取自 rules/engine.py，解决跨模块引用问题。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Vulnerability:
    """漏洞定义 — 所有模块共享的数据模型。"""
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