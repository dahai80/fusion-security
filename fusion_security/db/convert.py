from __future__ import annotations

import logging
from datetime import datetime

from ..models.finding import Finding
from ..models.patch import Patch
from ..models.project import Project, Scan
from ..models.rule import Rule
from ..models.vulnerability import Vulnerability
from .models import (
    ApiKeyORM,
    FindingORM,
    PatchORM,
    ProjectORM,
    RuleORM,
    ScanORM,
    VulnerabilityORM,
    WebhookORM,
)

logger = logging.getLogger(__name__)


def _to_datetime(value):
    # 领域模型 created_at/updated_at 是 ISO 字符串(__post_init__ 里 isoformat)，
    # ORM DateTime 列只接受 datetime 对象；空串回退 None 让列默认值生效。
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError) as e:
        logger.warning("convert: 无法解析时间字段 %r: %s", value, e)
        return None


def vuln_to_orm(v: Vulnerability, scan_id: str = "", tenant_id: str = "") -> VulnerabilityORM:
    return VulnerabilityORM(
        id=v.id,
        title=v.title,
        description=v.description,
        severity=v.severity,
        confidence=v.confidence,
        file_path=v.file_path,
        line_number=v.line_number,
        code_snippet=v.code_snippet,
        rule_id=v.rule_id,
        cwe_id=v.cwe_id,
        fix_suggestion=v.fix_suggestion,
        verified=v.verified,
        status=v.status,
        data_flow_path=v.data_flow_path,
        scan_id=scan_id,
        tenant_id=tenant_id,
    )


def orm_to_vuln(o: VulnerabilityORM) -> Vulnerability:
    return Vulnerability(
        id=o.id,
        title=o.title,
        description=o.description,
        severity=o.severity,
        confidence=o.confidence,
        file_path=o.file_path,
        line_number=o.line_number,
        code_snippet=o.code_snippet,
        rule_id=o.rule_id,
        cwe_id=o.cwe_id,
        fix_suggestion=o.fix_suggestion,
        verified=o.verified,
        status=o.status,
        data_flow_path=o.data_flow_path,
    )


def finding_to_orm(f: Finding, scan_id: str = "") -> FindingORM:
    # 此前缺失 — 阻塞管道持久化 Finding。Finding 域模型与 FindingORM 字段 1:1。
    return FindingORM(
        id=f.id,
        vuln_id=f.vuln_id,
        scan_id=scan_id or f.scan_id,
        file_path=f.file_path,
        line_number=f.line_number,
        line_end=f.line_end,
        code_snippet=f.code_snippet[:500],
        context_before=f.context_before[:200],
        context_after=f.context_after[:200],
        data_flow_path=f.data_flow_path,
        confidence=f.confidence,
    )


def orm_to_finding(o: FindingORM) -> Finding:
    return Finding(
        id=o.id,
        vuln_id=o.vuln_id,
        scan_id=o.scan_id,
        file_path=o.file_path,
        line_number=o.line_number,
        line_end=o.line_end,
        code_snippet=o.code_snippet,
        context_before=o.context_before,
        context_after=o.context_after,
        data_flow_path=o.data_flow_path,
        confidence=o.confidence,
    )


def webhook_to_orm(url: str, events: list[str], secret_hash: str, enabled: bool = True) -> WebhookORM:
    import json

    return WebhookORM(
        url=url,
        events_json=json.dumps(events or [], ensure_ascii=False),
        secret_hash=secret_hash,
        enabled=enabled,
    )


def orm_to_webhook(o: WebhookORM) -> dict:
    # 响应里绝不返回 secret_hash(S-P0)。
    import json

    return {
        "id": o.id,
        "url": o.url,
        "events": json.loads(o.events_json or "[]"),
        "enabled": o.enabled,
        "created_at": o.created_at,
    }


def api_key_to_orm(name: str, role: str, key_hash: str, tenant_id: str = "") -> ApiKeyORM:
    return ApiKeyORM(
        name=name,
        role=role,
        key_hash=key_hash,
        tenant_id=tenant_id,
        enabled=True,
    )


def project_to_orm(p: Project) -> ProjectORM:
    return ProjectORM(
        id=p.id,
        name=p.name,
        repo_url=p.repo_url,
        tech_stack=p.tech_stack,
        default_branch=p.default_branch,
        ruleset_id=p.ruleset_id,
        local_path=p.local_path,
        status=p.status,
        created_at=_to_datetime(p.created_at),
        updated_at=_to_datetime(p.updated_at),
    )


def orm_to_project(o: ProjectORM) -> Project:
    return Project(
        id=o.id,
        name=o.name,
        repo_url=o.repo_url,
        tech_stack=o.tech_stack,
        default_branch=o.default_branch,
        ruleset_id=o.ruleset_id,
        local_path=o.local_path,
        status=o.status,
        created_at=o.created_at,
        updated_at=o.updated_at,
    )


def scan_to_orm(s: Scan) -> ScanORM:
    return ScanORM(
        id=s.id,
        project_id=s.project_id,
        scan_type=s.scan_type,
        status=s.status,
        severity_threshold=s.severity_threshold,
        use_ai=s.use_ai,
        model=s.model,
        trigger=s.trigger,
        branch=s.branch,
        base_commit=s.base_commit,
        head_commit=s.head_commit,
        path=s.path,
        tenant_id=s.tenant_id,
        files_scanned=s.files_scanned,
        files_skipped=s.files_skipped,
        duration_ms=s.duration_ms,
        total_vulnerabilities=s.total_vulnerabilities,
        critical=s.critical,
        high=s.high,
        medium=s.medium,
        low=s.low,
        summary=s.summary,
        created_at=_to_datetime(s.created_at),
        completed_at=_to_datetime(s.completed_at),
    )


def orm_to_scan(o: ScanORM) -> Scan:
    return Scan(
        id=o.id,
        project_id=o.project_id,
        scan_type=o.scan_type,
        status=o.status,
        severity_threshold=o.severity_threshold,
        use_ai=o.use_ai,
        model=o.model,
        trigger=o.trigger,
        branch=o.branch,
        base_commit=o.base_commit,
        head_commit=o.head_commit,
        path=o.path,
        tenant_id=o.tenant_id,
        files_scanned=o.files_scanned,
        files_skipped=o.files_skipped,
        duration_ms=o.duration_ms,
        total_vulnerabilities=o.total_vulnerabilities,
        critical=o.critical,
        high=o.high,
        medium=o.medium,
        low=o.low,
        summary=o.summary,
        created_at=o.created_at,
        completed_at=o.completed_at,
    )


def patch_to_orm(p: Patch) -> PatchORM:
    return PatchORM(
        id=p.id,
        vuln_id=p.vuln_id,
        scan_id=p.scan_id,
        diff_content=p.diff_content,
        original_code=p.original_code,
        patched_code=p.patched_code,
        description=p.description,
        status=p.status,
        strategy=p.strategy,
        verified=p.verified,
        needs_review=p.needs_review,
    )


def orm_to_patch(o: PatchORM) -> Patch:
    return Patch(
        id=o.id,
        vuln_id=o.vuln_id,
        scan_id=o.scan_id,
        diff_content=o.diff_content,
        original_code=o.original_code,
        patched_code=o.patched_code,
        description=o.description,
        status=o.status,
        strategy=o.strategy,
        verified=o.verified,
        needs_review=o.needs_review,
    )


def rule_to_orm(r: Rule) -> RuleORM:
    return RuleORM(
        id=r.id,
        group=r.group,
        name=r.name,
        description=r.description,
        severity=r.severity,
        cwe_id=r.cwe_id,
        pattern=r.pattern,
        language=r.language,
        fix_template=r.fix_template,
        category=r.category,
        enabled=r.enabled,
        detection_type=r.detection_type,
        source=r.source,
        prdid=r.prdid,
    )


def orm_to_rule(o: RuleORM) -> Rule:
    return Rule(
        id=o.id,
        group=o.group,
        name=o.name,
        description=o.description,
        severity=o.severity,
        cwe_id=o.cwe_id,
        pattern=o.pattern,
        language=o.language,
        fix_template=o.fix_template,
        category=o.category,
        enabled=o.enabled,
        detection_type=o.detection_type,
        source=o.source,
        prdid=o.prdid,
    )
