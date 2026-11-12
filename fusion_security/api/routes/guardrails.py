"""Guardrails routes (evolution plan P2.3) — LLM input/output filtering.

Multi-tenant quotas inherit from the chassis middleware; every block is
appended to the per-tenant audit stream.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...engine.tenant.audit import get_audit_logger
from ..auth import require_permission

logger = logging.getLogger(__name__)
router = APIRouter()

_MAX_TEXT = 200_000


class GuardrailRequest(BaseModel):
    text: str = Field(min_length=1, max_length=_MAX_TEXT)
    tenant_id: str = Field(default="default", max_length=100)
    use_llm: bool = False


@router.post("/input")
def inspect_input_route(req: GuardrailRequest, _=Depends(require_permission("scan:read"))):
    """Filter LLM input (prompt-injection, rule tier; LLM tier opt-in)."""
    from ...engine.guardrails import inspect_input

    if req.use_llm:
        raise HTTPException(status_code=501, detail="llm tier is opt-in per tenant and not enabled on this deployment")
    verdict = inspect_input(req.text)
    if verdict.action == "block":
        get_audit_logger(req.tenant_id).log(
            action="guardrail.block",
            actor="guardrails",
            resource_type="llm_input",
            details={"reasons": verdict.reasons, "latency_ms": round(verdict.latency_ms, 3)},
            risk_level="high",
        )
    return verdict.to_dict()


@router.post("/output")
def inspect_output_route(req: GuardrailRequest, _=Depends(require_permission("scan:read"))):
    """Filter LLM output (secret leakage, tool-invocation text, exfil patterns)."""
    from ...engine.guardrails import inspect_output

    verdict = inspect_output(req.text)
    if verdict.action == "block":
        get_audit_logger(req.tenant_id).log(
            action="guardrail.block",
            actor="guardrails",
            resource_type="llm_output",
            details={"reasons": verdict.reasons, "latency_ms": round(verdict.latency_ms, 3)},
            risk_level="high",
        )
    return verdict.to_dict()
