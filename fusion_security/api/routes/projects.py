from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_session
from ...db.models import ProjectORM
from ...db.convert import orm_to_project, project_to_orm
from ...models.project import Project

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
    name: Optional[str] = None
    repo_url: Optional[str] = None
    tech_stack: Optional[str] = None
    default_branch: Optional[str] = None
    ruleset_id: Optional[str] = None
    local_path: Optional[str] = None
    status: Optional[str] = None


@router.post("", response_model=ProjectResponse)
def create_project(body: ProjectCreate, db: Session = Depends(get_session)):
    p = Project(
        name=body.name, repo_url=body.repo_url, tech_stack=body.tech_stack,
        default_branch=body.default_branch, ruleset_id=body.ruleset_id,
        local_path=body.local_path,
    )
    orm = project_to_orm(p)
    db.add(orm)
    db.commit()
    db.refresh(orm)
    logger.info(f"创建项目: {orm.name} ({orm.id})")
    return ProjectResponse(
        id=orm.id, name=orm.name, repo_url=orm.repo_url,
        tech_stack=orm.tech_stack, default_branch=orm.default_branch,
        ruleset_id=orm.ruleset_id, local_path=orm.local_path, status=orm.status,
    )


@router.get("", response_model=List[ProjectResponse])
def list_projects(status: Optional[str] = None, limit: int = 100, offset: int = 0, db: Session = Depends(get_session)):
    limit = min(limit, 500)
    offset = max(offset, 0)
    q = db.query(ProjectORM)
    if status:
        q = q.filter(ProjectORM.status == status)
    results = q.offset(offset).limit(limit).all()
    return [
        ProjectResponse(
            id=o.id, name=o.name, repo_url=o.repo_url,
            tech_stack=o.tech_stack, default_branch=o.default_branch,
            ruleset_id=o.ruleset_id, local_path=o.local_path, status=o.status,
        )
        for o in results
    ]


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_session)):
    o = db.query(ProjectORM).filter(ProjectORM.id == project_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectResponse(
        id=o.id, name=o.name, repo_url=o.repo_url,
        tech_stack=o.tech_stack, default_branch=o.default_branch,
        ruleset_id=o.ruleset_id, local_path=o.local_path, status=o.status,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: str, body: ProjectUpdate, db: Session = Depends(get_session)):
    o = db.query(ProjectORM).filter(ProjectORM.id == project_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Project not found")
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
        id=o.id, name=o.name, repo_url=o.repo_url,
        tech_stack=o.tech_stack, default_branch=o.default_branch,
        ruleset_id=o.ruleset_id, local_path=o.local_path, status=o.status,
    )


@router.delete("/{project_id}")
def delete_project(project_id: str, db: Session = Depends(get_session)):
    o = db.query(ProjectORM).filter(ProjectORM.id == project_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(o)
    db.commit()
    logger.info(f"删除项目: {project_id}")
    return {"status": "deleted"}
