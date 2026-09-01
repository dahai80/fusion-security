from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .session import Base


def _uuid() -> str:
    return uuid.uuid4().hex[:16]


def _now() -> datetime:
    return datetime.utcnow()


class ProjectORM(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    tech_stack: Mapped[str] = mapped_column(String(200), default="")
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    ruleset_id: Mapped[str] = mapped_column(String(16), default="")
    local_path: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    scans: Mapped[list[ScanORM]] = relationship(back_populates="project", cascade="all, delete-orphan")


class ScanORM(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_project_id", "project_id"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_tenant_id", "tenant_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    # A-P0-2/FK: path-only 扫描无关联 project,project_id 可空且无 FK。
    # 此前 FK("projects.id") + default="" 在 foreign_keys=ON 时让无 project 的扫描写入失败(整个 POST /scans 不可用)。
    project_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("projects.id"), nullable=True, default=None)
    scan_type: Mapped[str] = mapped_column(String(20), default="full")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    severity_threshold: Mapped[str] = mapped_column(String(10), default="low")
    use_ai: Mapped[bool] = mapped_column(Boolean, default=True)
    model: Mapped[str] = mapped_column(String(100), default="")
    trigger: Mapped[str] = mapped_column(String(20), default="manual")
    branch: Mapped[str] = mapped_column(String(100), default="")
    base_commit: Mapped[str] = mapped_column(String(64), default="")
    head_commit: Mapped[str] = mapped_column(String(64), default="")
    # A-P0-2: 扫描目标原始路径,对账(reconcile)与队列恢复必须依赖它,此前缺失导致 project_path=""。
    path: Mapped[str] = mapped_column(String(500), default="")
    tenant_id: Mapped[str] = mapped_column(String(16), default="")
    claimed_by: Mapped[str] = mapped_column(String(64), default="")
    heartbeat: Mapped[float] = mapped_column(Float, default=0.0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    files_skipped: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    project: Mapped[ProjectORM] = relationship(back_populates="scans")
    findings: Mapped[list[FindingORM]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    patches: Mapped[list[PatchORM]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class VulnerabilityORM(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vulns_scan_id", "scan_id"),
        Index("ix_vulns_severity", "severity"),
        Index("ix_vulns_status", "status"),
        Index("ix_vulns_rule_id", "rule_id"),
        Index("ix_vulns_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    file_path: Mapped[str] = mapped_column(String(500), default="")
    line_number: Mapped[int] = mapped_column(Integer, default=0)
    code_snippet: Mapped[str] = mapped_column(Text, default="")
    rule_id: Mapped[str] = mapped_column(String(20), default="")
    cwe_id: Mapped[str] = mapped_column(String(20), default="")
    fix_suggestion: Mapped[str] = mapped_column(Text, default="")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="open")
    data_flow_path: Mapped[str] = mapped_column(Text, default="")
    scan_id: Mapped[str] = mapped_column(String(32), default="")
    tenant_id: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    findings: Mapped[list[FindingORM]] = relationship(back_populates="vulnerability")
    patches: Mapped[list[PatchORM]] = relationship(back_populates="vulnerability")


class FindingORM(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_vuln_id", "vuln_id"), Index("ix_findings_scan_id", "scan_id"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(String(32), ForeignKey("vulnerabilities.id"), default="")
    scan_id: Mapped[str] = mapped_column(String(32), ForeignKey("scans.id"), default="")
    file_path: Mapped[str] = mapped_column(String(500), default="")
    line_number: Mapped[int] = mapped_column(Integer, default=0)
    line_end: Mapped[int] = mapped_column(Integer, default=0)
    code_snippet: Mapped[str] = mapped_column(Text, default="")
    context_before: Mapped[str] = mapped_column(Text, default="")
    context_after: Mapped[str] = mapped_column(Text, default="")
    data_flow_path: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    vulnerability: Mapped[VulnerabilityORM] = relationship(back_populates="findings")
    scan: Mapped[ScanORM] = relationship(back_populates="findings")


class PatchORM(Base):
    __tablename__ = "patches"
    __table_args__ = (Index("ix_patches_vuln_id", "vuln_id"), Index("ix_patches_scan_id", "scan_id"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(String(32), ForeignKey("vulnerabilities.id"), default="")
    scan_id: Mapped[str] = mapped_column(String(32), ForeignKey("scans.id"), default="")
    diff_content: Mapped[str] = mapped_column(Text, default="")
    original_code: Mapped[str] = mapped_column(Text, default="")
    patched_code: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    strategy: Mapped[str] = mapped_column(String(20), default="template")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    vulnerability: Mapped[VulnerabilityORM] = relationship(back_populates="patches")
    scan: Mapped[ScanORM] = relationship(back_populates="patches")


class ScanCacheORM(Base):
    __tablename__ = "scan_cache"
    # A-P1-4: (project_id, file_path) 唯一约束,把并发 put 竞争转成可捕获的 IntegrityError + upsert。
    __table_args__ = (
        UniqueConstraint("project_id", "file_path", name="uq_cache_project_file"),
        Index("ix_cache_project_file", "project_id", "file_path"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(16), nullable=False)
    results_json: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)


class RuleORM(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    group: Mapped[str] = mapped_column(String(50), default="")
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(20), default="")
    pattern: Mapped[str] = mapped_column(Text, default="")
    language: Mapped[str] = mapped_column(String(20), default="all")
    fix_template: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(50), default="injection")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    detection_type: Mapped[str] = mapped_column(String(20), default="regex")
    source: Mapped[str] = mapped_column(String(20), default="builtin")
    prdid: Mapped[str] = mapped_column(String(20), default="")


class ApiKeyORM(Base):
    # P0-4/S-P0-3: API key 持久化到 DB,只存 sha256 哈希;主密钥经 FUSION_SECURITY_MASTER_KEY 稳定。
    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("key_hash", name="uq_api_key_hash"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(100), default="")
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    tenant_id: Mapped[str] = mapped_column(String(16), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_used_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)


class WebhookORM(Base):
    # Feature 5: Webhook 持久化(此前仅内存 dict,重启即丢);secret 只存哈希。
    __tablename__ = "webhooks"
    __table_args__ = (Index("ix_webhooks_enabled", "enabled"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    url: Mapped[str] = mapped_column(String(500), default="")
    events_json: Mapped[str] = mapped_column(Text, default="[]")
    secret_hash: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ScheduledScanORM(Base):
    # Feature 4: 定时扫描持久化(此前仅内存,重启即丢)。
    # frequency(project_path) 与 ScanScheduler.ScheduledScan 数据类对齐;
    # cron/project_id 保留兼容旧字段,新写入走 frequency + project_path。
    __tablename__ = "scheduled_scans"
    __table_args__ = (Index("ix_schedules_enabled", "enabled"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), default="")
    # project_id 可空且无 FK:Feature 4 以 project_path 为主,path-only 计划无关联 project。
    # 此前 FK("projects.id") 会导致无 project 的计划写入失败(整个 Feature 4 不可用)。
    project_id: Mapped[str | None] = mapped_column(String(32), nullable=True, default=None)
    project_path: Mapped[str] = mapped_column(String(500), default="")
    cron: Mapped[str] = mapped_column(String(100), default="")
    frequency: Mapped[str] = mapped_column(String(20), default="daily")
    severity: Mapped[str] = mapped_column(String(10), default="low")
    config_json: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    tenant_id: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class FeedbackORM(Base):
    # Feature 2: 反馈循环持久化(false_positive/confirmed),此前仅内存。
    __tablename__ = "feedbacks"
    __table_args__ = (Index("ix_feedback_vuln_id", "vuln_id"), Index("ix_feedback_scan_id", "scan_id"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(String(32), default="")
    scan_id: Mapped[str] = mapped_column(String(32), default="")
    flag: Mapped[str] = mapped_column(String(20), default="confirmed")
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
