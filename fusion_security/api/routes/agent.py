"""Agent-security routes (evolution plan P1.1/P2.x)."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...engine.agent.injection import RULES, validate_rules
from ...engine.agent.injection import detect_async as injection_detect_async
from ..auth import require_permission

logger = logging.getLogger(__name__)
router = APIRouter()


class InjectionScanRequest(BaseModel):
    text: str = Field(default="", max_length=200_000)
    path: str = ""
    use_llm: bool = False


@router.post("/injection-scan")
async def run_injection_scan(req: InjectionScanRequest, _=Depends(require_permission("scan:read"))):
    """Scan free text or a file for prompt-injection payloads. Rule tier is
    offline; use_llm=true escalates to fusion-mlx and degrades to rule
    results when the engine is unavailable."""
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
    if req.use_llm:
        from ...engine.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        try:
            result = await injection_detect_async(text, analyzer=analyzer, use_llm=True)
        finally:
            await analyzer.aclose()
    else:
        result = await injection_detect_async(text)
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
            for r in RULES
        ],
    }
