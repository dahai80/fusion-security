"""Custom rule engine — user-defined rules with CRUD and gray-release."""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .engine import ScanRule

logger = logging.getLogger(__name__)


@dataclass
class CustomRule:
    id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "medium"
    rule_type: str = "regex"
    pattern: str = ""
    language: str = "*"
    enabled: bool = True
    gray_release: bool = False
    gray_percentage: int = 100
    created_by: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_scan_rule(self) -> ScanRule | None:
        if not self.enabled or not self.pattern:
            return None
        if self._is_redos_risk(self.pattern):
            logger.warning(f"[CustomRule] ReDoS 风险，跳过规则 {self.id}")
            return None
        try:
            compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.warning(f"[CustomRule] 正则编译失败 {self.id}: {e}")
            return None
        return ScanRule(
            id=self.id,
            name=self.name,
            description=self.description,
            severity=self.severity,
            cwe_id="",
            pattern=compiled,
            language=self.language,
        )

    def _is_redos_risk(self, pattern: str) -> bool:
        dangerous = re.compile(
            r"(\([^)]*[+*][^)]*\)){2,}|"
            r"(\[[^\]]*[+*][^\]]*\]){2,}|"
            r"(\(.+\))[+*]{2,}|"
            r"(\(\?:.+\))[+*]\1"
        )
        if dangerous.search(pattern):
            return True
        return len(pattern) > 500

    def should_apply(self, tenant_id: str = "") -> bool:
        if not self.enabled:
            return False
        if not self.gray_release:
            return True
        import hashlib

        hash_val = int(hashlib.md5(f"{tenant_id}:{self.id}".encode()).hexdigest()[:8], 16)
        return (hash_val % 100) < self.gray_percentage


class CustomRuleStore:
    def __init__(self, store_path: str = ""):
        self.store_path = store_path or str(Path.home() / ".fusion_security" / "custom_rules.json")
        self.rules: dict[str, CustomRule] = {}
        self._load()

    def add_rule(self, rule: CustomRule) -> CustomRule:
        self.rules[rule.id] = rule
        self._save()
        logger.info(f"[CustomRule] 添加规则: {rule.id} type={rule.rule_type}")
        return rule

    def update_rule(self, rule_id: str, **kwargs) -> CustomRule | None:
        rule = self.rules.get(rule_id)
        if not rule:
            return None
        for k, v in kwargs.items():
            if hasattr(rule, k):
                setattr(rule, k, v)
        rule.updated_at = time.time()
        self._save()
        logger.info(f"[CustomRule] 更新规则: {rule_id}")
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        if rule_id in self.rules:
            del self.rules[rule_id]
            self._save()
            logger.info(f"[CustomRule] 删除规则: {rule_id}")
            return True
        return False

    def get_rule(self, rule_id: str) -> CustomRule | None:
        return self.rules.get(rule_id)

    def list_rules(self, enabled_only: bool = False) -> list[CustomRule]:
        rules = list(self.rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules

    def get_active_rules(self, tenant_id: str = "") -> list[ScanRule]:
        scan_rules = []
        for cr in self.rules.values():
            if cr.should_apply(tenant_id) and cr.rule_type == "regex":
                sr = cr.to_scan_rule()
                if sr:
                    scan_rules.append(sr)
        return scan_rules

    def _save(self) -> None:
        try:
            Path(self.store_path).parent.mkdir(parents=True, exist_ok=True)
            data = {}
            for rid, r in self.rules.items():
                data[rid] = {
                    "id": r.id,
                    "name": r.name,
                    "description": r.description,
                    "severity": r.severity,
                    "rule_type": r.rule_type,
                    "pattern": r.pattern,
                    "language": r.language,
                    "enabled": r.enabled,
                    "gray_release": r.gray_release,
                    "gray_percentage": r.gray_percentage,
                    "created_by": r.created_by,
                    "created_at": r.created_at,
                    "updated_at": r.updated_at,
                }
            with open(self.store_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"[CustomRule] 保存失败: {e}")

    def _load(self) -> None:
        try:
            p = Path(self.store_path)
            if not p.exists():
                return
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            for rid, d in data.items():
                self.rules[rid] = CustomRule(**d)
            logger.info(f"[CustomRule] 加载 {len(self.rules)} 条自定义规则")
        except Exception as e:
            logger.warning(f"[CustomRule] 加载失败: {e}")
