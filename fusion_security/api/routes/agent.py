"""Agent-security routes (evolution plan P1.1/P2.x)."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...engine.agent.injection import detect as injection_detect
from ...engine.agent.injection import validate_rules
from ..auth import require_permission

logger = logging.getLogger(__name__)
router = APIRouter()


class InjectionScanRequest(BaseModel):
    text: str = Field(default="", max_length=200_000)
    path: str = ""
    use_llm: bool = False


@router.post("/injection-scan")
def run_injection_scan(req: InjectionScanRequest, _=Depends(require_permission("scan:read"))):
    """Scan free text or a file for prompt-injection payloads (offline)."""
    text = req.text
    if req.path:
        target = Path(req.path).expanduser()
        if not target.is_file():
            raise HTTPException(status_code=404, detail=f"file not found: {req.path}")
        if target.stat().st_size > 5_000_000:
            raise HTTPException(status_code=413, detail="file too large for injection scan (>5MB)")
        text = target.read_text(encoding="utf-8", errors="ignore")
    if not text.strip():
        raise HTTPException(status_code=422, detail="provide 'text' or a readable 'path'")
    logger.info(f"injection-scan request: chars={len(text)} use_llm={req.use_llm}")
    result = injection_detect(text, use_llm=req.use_llm)
    return result


@router.get("/injection-rules")
def list_injection_rules(_=Depends(require_permission("scan:read"))):
    """List built-in injection rules with their validator status."""
    validation = validate_rules()
    return {
        "rule_count": validation["rules"],
        "validators_ok": validation["ok"],
        "rules": [
            {
                "rule_id": r.rule_id,
                "family": r.family,
                "name": r.name,
                "severity": r.severity,
                "description": r.description,
            }
            for r in __import__("fusion_security.engine.agent.injection", fromlist=["RULES"]).RULES
        ],
    }
