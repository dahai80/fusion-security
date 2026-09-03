from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_session
from ...db.convert import project_to_orm
from ...db.models import ProjectORM, ScanCacheORM, ScanORM
from ...models.project import Project
from ..auth import APIKey, require_permission

logger = logging.getLogger(__name__)
router = APIRouter()


class ProjectCreate(BaseModel):
    name: str
    repo_url: str = ""
    tech_stack: str = ""
    default_branch: str = "main"
    ruleset_id: str = ""
    local_path: str = ""


class ProjectResponse(BaseModel):
    id: str
    name: str
    repo_url: str
    tech_stack: str
    default_branch: str
    ruleset_id: str
    local_path: str
    status: str


class ProjectUpdate(BaseModel):
    name: str | None = None
    repo_url: str | None = None
    tech_stack: str | None = None
    default_branch: str | None = None
    ruleset_id: str | None = None
    local_path: str | None = None
    status: str | None = None


def _project_tenant_scope(query, api_key: APIKey):
    # Issue #32: fail-closed 租户隔离。get_principal 保证 tenant_id 非空,始终过滤。
    return query.filter(ProjectORM.tenant_id == api_key.tenant_id)


def _check_project_tenant(o: ProjectORM, api_key: APIKey) -> None:
    if (o.tenant_id or "") != (api_key.tenant_id or ""):
        raise HTTPException(status_code=404, detail="Project not found")


@router.post("", response_model=ProjectResponse)
def create_project(
    body: ProjectCreate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("project:manage")),
):
    p = Project(
        name=body.name,
        repo_url=body.repo_url,
        tech_stack=body.tech_stack,
        default_branch=body.default_branch,
        ruleset_id=body.ruleset_id,
        local_path=body.local_path,
    )
    orm = project_to_orm(p)
    orm.tenant_id = api_key.tenant_id or ""
    db.add(orm)
    db.commit()
    db.refresh(orm)
    logger.info(f"创建项目: {orm.name} ({orm.id})")
    return ProjectResponse(
        id=orm.id,
        name=orm.name,
        repo_url=orm.repo_url,
        tech_stack=orm.tech_stack,
        default_branch=orm.default_branch,
        ruleset_id=orm.ruleset_id,
        local_path=orm.local_path,
        status=orm.status,
    )


@router.get("", response_model=list[ProjectResponse])
def list_projects(
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:read")),
):
    limit = min(limit, 500)
    offset = max(offset, 0)
    q = _project_tenant_scope(db.query(ProjectORM), api_key)
    if status:
        q = q.filter(ProjectORM.status == status)
    results = q.offset(offset).limit(limit).all()
    return [
        ProjectResponse(
            id=o.id,
            name=o.name,
            repo_url=o.repo_url,
            tech_stack=o.tech_stack,
            default_branch=o.default_branch,
            ruleset_id=o.ruleset_id,
            local_path=o.local_path,
            status=o.status,
        )
        for o in results
    ]


@router.get("/{project_id}/scan-summary")
def project_scan_summary(
    project_id: str,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:read")),
):
    from sqlalchemy import func

    proj = db.query(ProjectORM).filter(ProjectORM.id == project_id).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    _check_project_tenant(proj, api_key)

    total_scans = (
        db.query(func.count(ScanORM.id))
        .filter(
            ScanORM.project_id == project_id,
            ScanORM.tenant_id == api_key.tenant_id,
        )
        .scalar()
    )

    latest = (
        db.query(ScanORM)
        .filter(
            ScanORM.project_id == project_id,
            ScanORM.tenant_id == api_key.tenant_id,
        )
        .order_by(ScanORM.created_at.desc())
        .first()
    )

    latest_scan = None
    if latest:
        latest_scan = {
            "id": latest.id,
            "status": latest.status,
            "scan_type": latest.scan_type,
            "files_scanned": latest.files_scanned,
            "total_vulnerabilities": latest.total_vulnerabilities,
            "critical": latest.critical,
            "high": latest.high,
            "medium": latest.medium,
            "low": latest.low,
            "summary": latest.summary,
            "created_at": latest.created_at.isoformat() if latest.created_at else "",
        }

    sev_rows = (
        db.query(
            ScanORM.severity_threshold,
            func.sum(ScanORM.critical),
            func.sum(ScanORM.high),
            func.sum(ScanORM.medium),
            func.sum(ScanORM.low),
        )
        .filter(ScanORM.project_id == project_id, ScanORM.tenant_id == api_key.tenant_id)
        .first()
    )

    vuln_summary = {
        "total_critical": int(sev_rows[1] or 0),
        "total_high": int(sev_rows[2] or 0),
        "total_medium": int(sev_rows[3] or 0),
        "total_low": int(sev_rows[4] or 0),
    }
    vuln_summary["total"] = sum(vuln_summary.values())

    cache_count = (
        db.query(func.count(ScanCacheORM.id))
        .filter(
            ScanCacheORM.project_id == project_id,
        )
        .scalar()
    )

    logger.info(f"项目扫描摘要: project={project_id} scans={total_scans}")
    return {
        "project_id": project_id,
        "total_scans": total_scans,
        "latest_scan": latest_scan,
        "vulnerability_summary": vuln_summary,
        "cache_stats": {"cached_files": cache_count},
    }


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str, db: Session = Depends(get_session), api_key: APIKey = Depends(require_permission("scan:read"))
):
    o = db.query(ProjectORM).filter(ProjectORM.id == project_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Project not found")
    _check_project_tenant(o, api_key)
    return ProjectResponse(
        id=o.id,
        name=o.name,
        repo_url=o.repo_url,
        tech_stack=o.tech_stack,
        default_branch=o.default_branch,
        ruleset_id=o.ruleset_id,
        local_path=o.local_path,
        status=o.status,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str,
    body: ProjectUpdate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("project:manage")),
):
    o = db.query(ProjectORM).filter(ProjectORM.id == project_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Project not found")
    _check_project_tenant(o, api_key)
    if body.name is not None:
        o.name = body.name
    if body.repo_url is not None:
        o.repo_url = body.repo_url
    if body.tech_stack is not None:
        o.tech_stack = body.tech_stack
    if body.default_branch is not None:
        o.default_branch = body.default_branch
    if body.ruleset_id is not None:
        o.ruleset_id = body.ruleset_id
    if body.local_path is not None:
        o.local_path = body.local_path
    if body.status is not None:
        o.status = body.status
    db.commit()
    db.refresh(o)
    logger.info(f"更新项目: {project_id}")
    return ProjectResponse(
        id=o.id,
        name=o.name,
        repo_url=o.repo_url,
        tech_stack=o.tech_stack,
        default_branch=o.default_branch,
        ruleset_id=o.ruleset_id,
        local_path=o.local_path,
        status=o.status,
    )


@router.delete("/{project_id}")
def delete_project(
    project_id: str, db: Session = Depends(get_session), api_key: APIKey = Depends(require_permission("project:manage"))
):
    o = db.query(ProjectORM).filter(ProjectORM.id == project_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Project not found")
    _check_project_tenant(o, api_key)
    db.delete(o)
    db.commit()
    logger.info(f"删除项目: {project_id}")
    return {"status": "deleted"}
