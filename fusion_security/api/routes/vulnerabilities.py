from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_session
from ...db.models import VulnerabilityORM

logger = logging.getLogger(__name__)
router = APIRouter()


class VulnResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    code_snippet: str
    rule_id: str
    cwe_id: str
    fix_suggestion: str
    verified: bool
    status: str
    data_flow_path: str


class VulnUpdate(BaseModel):
    status: str | None = None


class VulnStatusUpdate(BaseModel):
    status: str


def _orm_to_response(o: VulnerabilityORM) -> VulnResponse:
    return VulnResponse(
        id=o.id,
        title=o.title,
        description=o.description,
        severity=o.severity,
        confidence=o.confidence,
        file_path=o.file_path,
        line_number=o.line_number,
        code_snippet=o.code_snippet[:500],
        rule_id=o.rule_id,
        cwe_id=o.cwe_id,
        fix_suggestion=o.fix_suggestion,
        verified=o.verified,
        status=o.status,
        data_flow_path=o.data_flow_path,
    )


@router.get("", response_model=list[VulnResponse])
def list_vulnerabilities(
    severity: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
    file_path: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_session),
):
    q = db.query(VulnerabilityORM)
    if severity:
        q = q.filter(VulnerabilityORM.severity == severity)
    if status:
        q = q.filter(VulnerabilityORM.status == status)
    if rule_id:
        q = q.filter(VulnerabilityORM.rule_id == rule_id)
    if file_path:
        q = q.filter(VulnerabilityORM.file_path.contains(file_path))
    results = q.order_by(VulnerabilityORM.created_at.desc()).offset(offset).limit(limit).all()
    return [_orm_to_response(o) for o in results]


@router.get("/stats/summary")
def vulnerability_stats(db: Session = Depends(get_session)):
    from sqlalchemy import func

    total = db.query(func.count(VulnerabilityORM.id)).scalar()
    by_severity = {}
    for row in (
        db.query(VulnerabilityORM.severity, func.count(VulnerabilityORM.id)).group_by(VulnerabilityORM.severity).all()
    ):
        by_severity[row[0]] = row[1]
    by_status = {}
    for row in (
        db.query(VulnerabilityORM.status, func.count(VulnerabilityORM.id)).group_by(VulnerabilityORM.status).all()
    ):
        by_status[row[0]] = row[1]
    return {"total": total, "by_severity": by_severity, "by_status": by_status}


@router.get("/findings/recent")
def recent_findings(hours: int = 24, limit: int = 50, db: Session = Depends(get_session)):
    from datetime import datetime, timedelta

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    results = (
        db.query(VulnerabilityORM)
        .filter(VulnerabilityORM.created_at >= cutoff)
        .order_by(VulnerabilityORM.created_at.desc())
        .limit(limit)
        .all()
    )
    return {"count": len(results), "findings": [_orm_to_response(o).dict() for o in results]}


@router.get("/findings/by-rule")
def findings_by_rule(db: Session = Depends(get_session)):
    from sqlalchemy import func

    rows = db.query(VulnerabilityORM.rule_id, func.count(VulnerabilityORM.id)).group_by(VulnerabilityORM.rule_id).all()
    return {"rules": [{"rule_id": r[0], "count": r[1]} for r in rows]}


@router.get("/export")
def export_vulnerabilities(
    severity: str | None = None,
    status: str | None = None,
    format: str = "json",
    db: Session = Depends(get_session),
):
    q = db.query(VulnerabilityORM)
    if severity:
        q = q.filter(VulnerabilityORM.severity == severity)
    if status:
        q = q.filter(VulnerabilityORM.status == status)
    results = q.all()
    items = [_orm_to_response(o).dict() for o in results]
    if format == "csv":
        import csv
        import io

        output = io.StringIO()
        if items:
            writer = csv.DictWriter(output, fieldnames=items[0].keys())
            writer.writeheader()
            writer.writerows(items)
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(content=output.getvalue(), media_type="text/csv")
    from fastapi.responses import JSONResponse

    return JSONResponse(content={"total": len(items), "vulnerabilities": items})


@router.get("/{vuln_id}", response_model=VulnResponse)
def get_vulnerability(vuln_id: str, db: Session = Depends(get_session)):
    o = db.query(VulnerabilityORM).filter(VulnerabilityORM.id == vuln_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return _orm_to_response(o)


@router.patch("/{vuln_id}", response_model=VulnResponse)
def update_vulnerability(vuln_id: str, body: VulnUpdate, db: Session = Depends(get_session)):
    o = db.query(VulnerabilityORM).filter(VulnerabilityORM.id == vuln_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    if body.status:
        o.status = body.status
    db.commit()
    db.refresh(o)
    logger.info(f"更新漏洞状态: {vuln_id} -> {o.status}")
    return _orm_to_response(o)


@router.put("/{vuln_id}/status", response_model=VulnResponse)
def update_vuln_status(vuln_id: str, body: VulnStatusUpdate, db: Session = Depends(get_session)):
    valid = {"open", "fixing", "fixed", "ignored", "false_positive"}
    if body.status not in valid:
        raise HTTPException(status_code=400, detail=f"无效状态，可选: {', '.join(valid)}")
    o = db.query(VulnerabilityORM).filter(VulnerabilityORM.id == vuln_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    o.status = body.status
    db.commit()
    db.refresh(o)
    logger.info(f"更新漏洞状态(PUT): {vuln_id} -> {o.status}")
    return _orm_to_response(o)


@router.post("/{vuln_id}/false-positive", response_model=VulnResponse)
def mark_false_positive(vuln_id: str, reason: str = "", db: Session = Depends(get_session)):
    o = db.query(VulnerabilityORM).filter(VulnerabilityORM.id == vuln_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    o.status = "false_positive"
    db.commit()
    db.refresh(o)
    logger.info(f"标记误报: {vuln_id}, 原因: {reason}")
    return _orm_to_response(o)
