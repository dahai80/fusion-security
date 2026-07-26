from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Float, Boolean, Text, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .session import Base


def _uuid() -> str:
    return uuid.uuid4().hex[:16]


def _now() -> datetime:
    return datetime.utcnow()


class ProjectORM(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    tech_stack: Mapped[str] = mapped_column(String(200), default="")
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    ruleset_id: Mapped[str] = mapped_column(String(16), default="")
    local_path: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    scans: Mapped[list["ScanORM"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class ScanORM(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_project_id", "project_id"),)

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(String(16), ForeignKey("projects.id"), default="")
    scan_type: Mapped[str] = mapped_column(String(20), default="full")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    severity_threshold: Mapped[str] = mapped_column(String(10), default="low")
    use_ai: Mapped[bool] = mapped_column(Boolean, default=True)
    model: Mapped[str] = mapped_column(String(100), default="")
    trigger: Mapped[str] = mapped_column(String(20), default="manual")
    branch: Mapped[str] = mapped_column(String(100), default="")
    base_commit: Mapped[str] = mapped_column(String(64), default="")
    head_commit: Mapped[str] = mapped_column(String(64), default="")
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

    project: Mapped["ProjectORM"] = relationship(back_populates="scans")
    findings: Mapped[list["FindingORM"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    patches: Mapped[list["PatchORM"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class VulnerabilityORM(Base):
    __tablename__ = "vulnerabilities"

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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    findings: Mapped[list["FindingORM"]] = relationship(back_populates="vulnerability")
    patches: Mapped[list["PatchORM"]] = relationship(back_populates="vulnerability")


class FindingORM(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_vuln_id", "vuln_id"), Index("ix_findings_scan_id", "scan_id"))

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(String(32), ForeignKey("vulnerabilities.id"), default="")
    scan_id: Mapped[str] = mapped_column(String(16), ForeignKey("scans.id"), default="")
    file_path: Mapped[str] = mapped_column(String(500), default="")
    line_number: Mapped[int] = mapped_column(Integer, default=0)
    line_end: Mapped[int] = mapped_column(Integer, default=0)
    code_snippet: Mapped[str] = mapped_column(Text, default="")
    context_before: Mapped[str] = mapped_column(Text, default="")
    context_after: Mapped[str] = mapped_column(Text, default="")
    data_flow_path: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    vulnerability: Mapped["VulnerabilityORM"] = relationship(back_populates="findings")
    scan: Mapped["ScanORM"] = relationship(back_populates="findings")


class PatchORM(Base):
    __tablename__ = "patches"
    __table_args__ = (Index("ix_patches_vuln_id", "vuln_id"), Index("ix_patches_scan_id", "scan_id"))

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(String(32), ForeignKey("vulnerabilities.id"), default="")
    scan_id: Mapped[str] = mapped_column(String(16), ForeignKey("scans.id"), default="")
    diff_content: Mapped[str] = mapped_column(Text, default="")
    original_code: Mapped[str] = mapped_column(Text, default="")
    patched_code: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    strategy: Mapped[str] = mapped_column(String(20), default="template")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    vulnerability: Mapped["VulnerabilityORM"] = relationship(back_populates="patches")
    scan: Mapped["ScanORM"] = relationship(back_populates="patches")


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
