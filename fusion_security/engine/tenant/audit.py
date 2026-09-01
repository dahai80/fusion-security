"""Audit logging — track all security-relevant operations.

LEGACY (guard-overlap) — 租户审计记录。本模块与 fusion-guard 的 fg-store (Rust) 能力重叠，
按 issue #23 决策 A，重叠能力以 fusion-guard 为单一事实源；AuditEntry 字段已对齐
fusion-guard AuditRecord 形状（含多租户维度 tenant_id），便于机械迁移。此处保留直至
fusion-guard 达到对等、消费者迁移完成后再移除。详见仓库根 DEPRECATED.md。
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_TENANT_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_tenant_slug(tenant_id: str) -> str:
    # tenant_id 进入审计文件名，必须做路径穿越防护。
    # 仅保留字母数字及 ._-，其余替换为 _；空值回落 system。
    slug = _TENANT_SAFE.sub("_", tenant_id or "").strip("._-")
    return slug or "system"


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
            log_file = Path(self.log_dir) / f"audit_{_safe_tenant_slug(self.tenant_id)}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            logger.warning(f"[Audit] 写入失败: {e}")
