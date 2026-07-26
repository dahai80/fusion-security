from __future__ import annotations

from .models import (
    ProjectORM, ScanORM, VulnerabilityORM, FindingORM, PatchORM, RuleORM,
)
from ..models.vulnerability import Vulnerability
from ..models.project import Project, Scan
from ..models.finding import Finding
from ..models.patch import Patch
from ..models.rule import Rule


def vuln_to_orm(v: Vulnerability) -> VulnerabilityORM:
    return VulnerabilityORM(
        id=v.id, title=v.title, description=v.description,
        severity=v.severity, confidence=v.confidence,
        file_path=v.file_path, line_number=v.line_number,
        code_snippet=v.code_snippet, rule_id=v.rule_id,
        cwe_id=v.cwe_id, fix_suggestion=v.fix_suggestion,
        verified=v.verified, status=v.status, data_flow_path=v.data_flow_path,
    )


def orm_to_vuln(o: VulnerabilityORM) -> Vulnerability:
    return Vulnerability(
        id=o.id, title=o.title, description=o.description,
        severity=o.severity, confidence=o.confidence,
        file_path=o.file_path, line_number=o.line_number,
        code_snippet=o.code_snippet, rule_id=o.rule_id,
        cwe_id=o.cwe_id, fix_suggestion=o.fix_suggestion,
        verified=o.verified, status=o.status, data_flow_path=o.data_flow_path,
    )


def project_to_orm(p: Project) -> ProjectORM:
    return ProjectORM(
        id=p.id, name=p.name, repo_url=p.repo_url,
        tech_stack=p.tech_stack, default_branch=p.default_branch,
        ruleset_id=p.ruleset_id, local_path=p.local_path,
        status=p.status, created_at=p.created_at, updated_at=p.updated_at,
    )


def orm_to_project(o: ProjectORM) -> Project:
    return Project(
        id=o.id, name=o.name, repo_url=o.repo_url,
        tech_stack=o.tech_stack, default_branch=o.default_branch,
        ruleset_id=o.ruleset_id, local_path=o.local_path,
        status=o.status, created_at=o.created_at, updated_at=o.updated_at,
    )


def scan_to_orm(s: Scan) -> ScanORM:
    return ScanORM(
        id=s.id, project_id=s.project_id, scan_type=s.scan_type,
        status=s.status, severity_threshold=s.severity_threshold,
        use_ai=s.use_ai, model=s.model, trigger=s.trigger,
        branch=s.branch, base_commit=s.base_commit, head_commit=s.head_commit,
        files_scanned=s.files_scanned, files_skipped=s.files_skipped,
        duration_ms=s.duration_ms, total_vulnerabilities=s.total_vulnerabilities,
        critical=s.critical, high=s.high, medium=s.medium, low=s.low,
        summary=s.summary, created_at=s.created_at, completed_at=s.completed_at,
    )


def orm_to_scan(o: ScanORM) -> Scan:
    return Scan(
        id=o.id, project_id=o.project_id, scan_type=o.scan_type,
        status=o.status, severity_threshold=o.severity_threshold,
        use_ai=o.use_ai, model=o.model, trigger=o.trigger,
        branch=o.branch, base_commit=o.base_commit, head_commit=o.head_commit,
        files_scanned=o.files_scanned, files_skipped=o.files_skipped,
        duration_ms=o.duration_ms, total_vulnerabilities=o.total_vulnerabilities,
        critical=o.critical, high=o.high, medium=o.medium, low=o.low,
        summary=o.summary, created_at=o.created_at, completed_at=o.completed_at,
    )


def patch_to_orm(p: Patch) -> PatchORM:
    return PatchORM(
        id=p.id, vuln_id=p.vuln_id, scan_id=p.scan_id,
        diff_content=p.diff_content, original_code=p.original_code,
        patched_code=p.patched_code, description=p.description,
        status=p.status, strategy=p.strategy, verified=p.verified,
    )


def orm_to_patch(o: PatchORM) -> Patch:
    return Patch(
        id=o.id, vuln_id=o.vuln_id, scan_id=o.scan_id,
        diff_content=o.diff_content, original_code=o.original_code,
        patched_code=o.patched_code, description=o.description,
        status=o.status, strategy=o.strategy, verified=o.verified,
    )


def rule_to_orm(r: Rule) -> RuleORM:
    return RuleORM(
        id=r.id, group=r.group, name=r.name,
        description=r.description, severity=r.severity,
        cwe_id=r.cwe_id, pattern=r.pattern,
        language=r.language, fix_template=r.fix_template,
        category=r.category, enabled=r.enabled,
        detection_type=r.detection_type, source=r.source,
        prdid=r.prdid,
    )


def orm_to_rule(o: RuleORM) -> Rule:
    return Rule(
        id=o.id, group=o.group, name=o.name,
        description=o.description, severity=o.severity,
        cwe_id=o.cwe_id, pattern=o.pattern,
        language=o.language, fix_template=o.fix_template,
        category=o.category, enabled=o.enabled,
        detection_type=o.detection_type, source=o.source,
        prdid=o.prdid,
    )
