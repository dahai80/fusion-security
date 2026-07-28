from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_session
from ...db.convert import patch_to_orm
from ...db.models import PatchORM, VulnerabilityORM

logger = logging.getLogger(__name__)
router = APIRouter()


class PatchResponse(BaseModel):
    id: str
    vuln_id: str
    scan_id: str
    diff_content: str
    original_code: str
    patched_code: str
    description: str
    status: str
    strategy: str
    verified: bool


class PatchUpdate(BaseModel):
    status: str | None = None
    verified: bool | None = None


def _patch_orm_to_response(o: PatchORM) -> PatchResponse:
    return PatchResponse(
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
    )


@router.get("", response_model=list[PatchResponse])
def list_patches(
    vuln_id: str | None = None,
    scan_id: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_session),
):
    q = db.query(PatchORM)
    if vuln_id:
        q = q.filter(PatchORM.vuln_id == vuln_id)
    if scan_id:
        q = q.filter(PatchORM.scan_id == scan_id)
    if status:
        q = q.filter(PatchORM.status == status)
    return [_patch_orm_to_response(o) for o in q.all()]


@router.get("/{patch_id}", response_model=PatchResponse)
def get_patch(patch_id: str, db: Session = Depends(get_session)):
    o = db.query(PatchORM).filter(PatchORM.id == patch_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Patch not found")
    return _patch_orm_to_response(o)


@router.patch("/{patch_id}", response_model=PatchResponse)
def update_patch(patch_id: str, body: PatchUpdate, db: Session = Depends(get_session)):
    o = db.query(PatchORM).filter(PatchORM.id == patch_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Patch not found")
    if body.status is not None:
        o.status = body.status
    if body.verified is not None:
        o.verified = body.verified
    db.commit()
    db.refresh(o)
    return _patch_orm_to_response(o)


@router.post("/{patch_id}/apply", response_model=PatchResponse)
def apply_patch(patch_id: str, db: Session = Depends(get_session)):
    o = db.query(PatchORM).filter(PatchORM.id == patch_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Patch not found")
    o.status = "applied"
    db.commit()
    db.refresh(o)
    logger.info(f"补丁已应用: {patch_id}")
    return _patch_orm_to_response(o)


class PatchVerifyRequest(BaseModel):
    test_result: str = "passed"
    notes: str = ""


@router.post("/{patch_id}/verify", response_model=PatchResponse)
def verify_patch(patch_id: str, body: PatchVerifyRequest, db: Session = Depends(get_session)):
    o = db.query(PatchORM).filter(PatchORM.id == patch_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Patch not found")
    o.verified = body.test_result == "passed"
    o.status = "verified" if o.verified else "failed"
    db.commit()
    db.refresh(o)
    logger.info(f"补丁验证: {patch_id} -> {o.status}")
    return _patch_orm_to_response(o)


@router.post("/generate/{vuln_id}")
def generate_patch(vuln_id: str, db: Session = Depends(get_session)):
    vuln_orm = db.query(VulnerabilityORM).filter(VulnerabilityORM.id == vuln_id).first()
    if not vuln_orm:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from ...db.convert import orm_to_vuln
    from ...engine.fix.fix_generator import FixGenerator

    vuln = orm_to_vuln(vuln_orm)
    generator = FixGenerator()
    patches = generator.generate(vuln)

    results = []
    for p in patches:
        orm = patch_to_orm(p)
        orm.vuln_id = vuln_id
        db.add(orm)
        results.append({"id": orm.id, "strategy": orm.strategy})

    db.commit()
    logger.info(f"生成补丁: vuln={vuln_id}, count={len(results)}")
    return {"patches": results}
