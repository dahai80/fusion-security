"""Audit logging — track all security-relevant operations."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    action: str = ""
    actor: str = ""
    tenant_id: str = ""
    resource_type: str = ""
    resource_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    ip_address: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "actor": self.actor,
            "tenant_id": self.tenant_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "details": self.details,
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
        }


class AuditLogger:
    def __init__(self, log_dir: str = "", tenant_id: str = "", max_entries: int = 10000):
        self.log_dir = log_dir or str(Path.home() / ".fusion_security" / "audit")
        self.tenant_id = tenant_id
        self.max_entries = max_entries
        self.entries: list[AuditEntry] = []

    def log(
        self,
        action: str,
        actor: str = "",
        resource_type: str = "",
        resource_id: str = "",
        details: dict[str, Any] | None = None,
        ip_address: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            action=action,
            actor=actor,
            tenant_id=self.tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
        )
        self.entries.append(entry)
        if len(self.entries) > self.max_entries:
            removed = len(self.entries) - self.max_entries
            self.entries = self.entries[removed:]
            logger.info(f"[Audit] 驱逐 {removed} 条旧记录, 当前 {len(self.entries)}/{self.max_entries}")
        self._append_to_file(entry)
        logger.info(f"[Audit] {action} actor={actor} resource={resource_type}/{resource_id}")
        return entry

    def query(self, action: str = "", actor: str = "", resource_type: str = "", limit: int = 100) -> list[AuditEntry]:
        results = self.entries
        if action:
            results = [e for e in results if e.action == action]
        if actor:
            results = [e for e in results if e.actor == actor]
        if resource_type:
            results = [e for e in results if e.resource_type == resource_type]
        return results[-limit:]

    def _append_to_file(self, entry: AuditEntry) -> None:
        try:
            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
            log_file = Path(self.log_dir) / f"audit_{self.tenant_id or 'system'}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            logger.warning(f"[Audit] 写入失败: {e}")
