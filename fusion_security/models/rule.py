from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Rule:
    id: str = ""
    group: str = "injection"
    name: str = ""
    description: str = ""
    severity: str = "medium"
    cwe_id: str = ""
    pattern: str = ""
    language: str = "all"
    fix_template: str = ""
    category: str = "injection"
    enabled: bool = True
    detection_type: str = "regex"  # regex | ast | taint | semantic
    source: str = "builtin"  # builtin | custom | imported
    prdid: str = ""  # PRD规则编号，如 FUS-INJ-001

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "group": self.group,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "language": self.language,
            "category": self.category,
            "enabled": self.enabled,
            "detection_type": self.detection_type,
            "source": self.source,
            "fix_template": self.fix_template,
            "prdid": self.prdid,
        }


@dataclass
class RuleSet:
    id: str = ""
    name: str = ""
    description: str = ""
    rules: list[Rule] = field(default_factory=list)
    scope: str = "global"  # global | project | team
    created_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"ruleset_{uuid.uuid4().hex[:8]}"
        if not self.created_at:
            from datetime import datetime

            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rule_count": len(self.rules),
            "scope": self.scope,
            "created_at": self.created_at,
            "rules": [r.to_dict() for r in self.rules],
        }
