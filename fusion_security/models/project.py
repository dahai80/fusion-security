from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Project:
    id: str = ""
    name: str = ""
    repo_url: str = ""
    tech_stack: list[str] = field(default_factory=list)
    default_branch: str = "main"
    ruleset_id: str = "default"
    local_path: str = ""
    status: str = "active"  # active | archived
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"proj_{uuid.uuid4().hex[:12]}"
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "repo_url": self.repo_url,
            "tech_stack": self.tech_stack,
            "default_branch": self.default_branch,
            "ruleset_id": self.ruleset_id,
            "local_path": self.local_path,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class Scan:
    id: str = ""
    project_id: str = ""
    scan_type: str = "full"  # full | incremental
    status: str = "pending"  # pending | running | completed | failed | cancelled
    severity_threshold: str = "low"
    use_ai: bool = True
    model: str = ""
    trigger: str = "cli"  # cli | api | ci | schedule
    branch: str = ""
    base_commit: str = ""
    head_commit: str = ""
    # A-P0-2: 扫描目标原始路径,对账与队列恢复依赖。
    path: str = ""
    tenant_id: str = ""
    files_scanned: int = 0
    files_skipped: int = 0
    duration_ms: float = 0.0
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    summary: str = ""
    error_message: str = ""
    created_at: str = ""
    completed_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"scan_{uuid.uuid4().hex[:12]}"
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "severity_threshold": self.severity_threshold,
            "use_ai": self.use_ai,
            "model": self.model,
            "trigger": self.trigger,
            "branch": self.branch,
            "base_commit": self.base_commit,
            "head_commit": self.head_commit,
            "path": self.path,
            "tenant_id": self.tenant_id,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "duration_ms": round(self.duration_ms, 1),
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "summary": self.summary,
            "error_message": self.error_message,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }
