"""Agent-security routes (evolution plan P1.1/P2.x)."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...engine.agent.assets.signatures import SignatureLibrary
from ...engine.agent.injection import INJECTION_CONTRACT_VERSION, RULES, validate_rules
from ...engine.agent.injection import detect_async as injection_detect_async
from ...engine.tenant.audit import get_audit_logger
from ..auth import require_permission

logger = logging.getLogger(__name__)
router = APIRouter()


class InjectionScanRequest(BaseModel):
    text: str = Field(default="", max_length=200_000)
    path: str = ""
    use_llm: bool = False


class InjectionBatchRequest(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=50)
    use_llm: bool = False


class AssetScanRequest(BaseModel):
    path: str
    signatures: str = ""


class RiskScoreRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=200)
    arguments: dict = Field(default_factory=dict)
    caller: dict = Field(default_factory=dict)
    tenant_id: str = Field(default="default", max_length=100)
    signatures: str = ""


class DecisionEventRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=200)
    decision: str
    caller: dict = Field(default_factory=dict)
    reason: str = ""
    tenant_id: str = Field(default="default", max_length=100)
    trace_id: str = ""


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
    result["contract_version"] = INJECTION_CONTRACT_VERSION
    return result


@router.post("/injection-scan/batch")
async def run_injection_scan_batch(req: InjectionBatchRequest, _=Depends(require_permission("scan:read"))):
    """Batch prompt-injection scan for service consumers (issue #85).

    Rule+heuristic tiers only (offline, deterministic); the LLM tier is
    not available in batch mode. Response shape is pinned by
    INJECTION_CONTRACT_VERSION — Rust consumers pin against it.
    """
    from ...engine.agent.injection import MAX_INJECTION_TEXT_CHARS

    for i, text in enumerate(req.texts):
        if len(text) > MAX_INJECTION_TEXT_CHARS:
            raise HTTPException(status_code=413, detail=f"texts[{i}] exceeds {MAX_INJECTION_TEXT_CHARS} chars")
    results = []
    for i, text in enumerate(req.texts):
        verdict = await injection_detect_async(text)
        results.append({"index": i, "contract_version": INJECTION_CONTRACT_VERSION, **verdict})
    flagged = sum(1 for r in results if r["is_injection"])
    logger.info(f"injection-scan batch: items={len(results)} flagged={flagged}")
    return {
        "contract_version": INJECTION_CONTRACT_VERSION,
        "scanned": len(results),
        "flagged": flagged,
        "results": results,
    }


@router.post("/asset-scan")
def run_asset_scan(req: AssetScanRequest, _=Depends(require_permission("scan:read"))):
    """Scan a server-local directory for malicious MCP servers / skills /
    agent configs. Fully offline; signature library is local (manual bundle
    import only)."""
    from ...engine.agent.assets import SignatureLibrary, scan_assets

    target = Path(req.path).expanduser()
    if not target.is_dir():
        raise HTTPException(status_code=404, detail=f"directory not found: {req.path}")
    lib = SignatureLibrary.load(req.signatures) if req.signatures else None
    inventory, findings = scan_assets(target, sigs=lib)
    logger.info(
        f"asset-scan request: path={req.path} servers={len(inventory.mcp_servers)} "
        f"skills={len(inventory.skills)} findings={len(findings)}"
    )
    return {
        "files_scanned": inventory.files_scanned,
        "mcp_servers": len(inventory.mcp_servers),
        "skills": len(inventory.skills),
        "findings": [
            {
                "rule_id": v.rule_id,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
                "file_path": v.file_path,
                "code_snippet": v.code_snippet,
                "fix_suggestion": v.fix_suggestion,
            }
            for v in findings
        ],
    }


@router.post("/risk-score")
def score_tool(req: RiskScoreRequest, _=Depends(require_permission("scan:read"))):
    """Score an agent tool-call request (P2.2 contract,
    schemas/agent-risk-score.v1.json). Deterministic + offline; policy
    hints are advisory — harness remains the deny-first executor."""
    from ...engine.agent.risk_score import score_tool_request

    sigs = SignatureLibrary.load(req.signatures) if req.signatures else SignatureLibrary.load()
    result = score_tool_request(
        tool_name=req.tool_name,
        arguments=req.arguments,
        caller=req.caller,
        sigs=sigs,
        tenant_id=req.tenant_id,
    )
    audit_logger = get_audit_logger(req.tenant_id)
    audit_logger.log(
        action="agent.risk_score",
        actor=str(req.caller.get("agent_id", "unknown")),
        resource_type="agent_tool",
        resource_id=req.tool_name,
        details={"score": result["score"], "risk_class": result["risk_class"]},
        risk_level="high" if result["risk_class"] in {"high", "critical"} else "info",
    )
    return result


@router.post("/decisions")
def push_decision(req: DecisionEventRequest, _=Depends(require_permission("scan:run"))):
    """Ingest a harness allow/deny decision event into the audit stream
    (closed feedback loop: denials feed tool reputation)."""
    if req.decision not in {"allow", "deny"}:
        raise HTTPException(status_code=422, detail="decision must be 'allow' or 'deny'")
    audit_logger = get_audit_logger(req.tenant_id)
    audit_logger.log(
        action="agent.tool.decision",
        actor="fusion-harness",
        resource_type="agent_tool",
        resource_id=req.tool_name,
        details={"decision": req.decision, "reason": req.reason, "caller": req.caller},
        risk_level="high" if req.decision == "deny" else "info",
        trace_id=req.trace_id,
    )
    logger.info(f"decision event: {req.decision} tool={req.tool_name} tenant={req.tenant_id}")
    return {"accepted": True, "tool_name": req.tool_name, "decision": req.decision}


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
