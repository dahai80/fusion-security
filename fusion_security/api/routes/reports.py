from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_session
from ...db.convert import orm_to_vuln
from ...db.models import ScanORM
from ...report.report import ReportGenerator
from ...report.sarif import vulnerabilities_to_sarif

logger = logging.getLogger(__name__)
router = APIRouter()


class ReportRequest(BaseModel):
    scan_id: str = ""
    format: str = "md"


@router.post("/generate")
def generate_report(body: ReportRequest, db: Session = Depends(get_session)):
    scan_orm = db.query(ScanORM).filter(ScanORM.id == body.scan_id).first()
    if not scan_orm:
        raise HTTPException(status_code=404, detail="Scan not found")

    from ...engine.scanner import ScanResult, ScanTarget

    target = ScanTarget(scan_orm.project_id or ".")
    result = ScanResult(target)
    result.files_scanned = scan_orm.files_scanned
    result.files_skipped = scan_orm.files_skipped
    result.duration_ms = scan_orm.duration_ms
    result.critical = scan_orm.critical
    result.high = scan_orm.high
    result.medium = scan_orm.medium
    result.low = scan_orm.low
    result.summary = scan_orm.summary

    seen_vuln_ids: set[str] = set()
    result.vulnerabilities = []
    for finding in scan_orm.findings:
        if not finding.vulnerability or finding.vuln_id in seen_vuln_ids:
            continue
        seen_vuln_ids.add(finding.vuln_id)
        result.vulnerabilities.append(orm_to_vuln(finding.vulnerability))
    logger.info(
        f"报告 scan={scan_orm.id}: {len(result.vulnerabilities)} 个漏洞 (过滤前 total={scan_orm.total_vulnerabilities})"
    )

    reporter = ReportGenerator()

    if body.format == "json":
        data = reporter.generate_json(result)
        return JSONResponse(content=data)
    elif body.format == "html":
        html = reporter.generate_html(result)
        return PlainTextResponse(content=html, media_type="text/html")
    else:
        md = reporter.generate_markdown(result)
        return PlainTextResponse(content=md, media_type="text/markdown")


@router.get("/scans/{scan_id}/sarif")
def scan_sarif(scan_id: str, db: Session = Depends(get_session)):
    scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
    if not scan_orm:
        raise HTTPException(status_code=404, detail="Scan not found")
    seen_vuln_ids: set[str] = set()
    vulns = []
    for finding in scan_orm.findings:
        if not finding.vulnerability or finding.vuln_id in seen_vuln_ids:
            continue
        seen_vuln_ids.add(finding.vuln_id)
        vulns.append(orm_to_vuln(finding.vulnerability))
    sarif_data = vulnerabilities_to_sarif(vulns)
    return JSONResponse(content=sarif_data)
