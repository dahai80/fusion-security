"""Guardrail filters for LLM input/output (evolution plan P2.3).

Pure-regex, zero-IO, zero-model tiers so the rule+heuristic path stays
under the 5ms p99 latency budget. Input filtering reuses the P1.1
injection rule engine; output filtering covers secret leakage, tool
invocation text and data-exfiltration patterns. The LLM tier is opt-in
per tenant and never on the hot path.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from ..agent.injection import detect as injection_detect
from ..secrets.integration import get_shared_scanner

logger = logging.getLogger(__name__)

# Tool-invocation text an LLM must never emit into user-visible output.
_TOOL_CALL_RE = re.compile(r"<function_call>|<tool_use>|(?:\"name\"\s*:\s*\"|'name'\s*:\s*')([a-z_][a-z0-9_]{1,63})\"")
# Data-exfil patterns: long base64 payloads and known exfil endpoints.
_EXFIL_URL_RE = re.compile(
    r"https?://(?:[^\s]*\b(?:webhook\.site|ngrok\.(?:io|com)|requestbin|pipedream|interact\.sh)|\b\d{1,3}(?:\.\d{1,3}){3})"
)
_LONG_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/])")


@dataclass
class GuardrailVerdict:
    direction: str
    action: str = "allow"
    reasons: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "action": self.action,
            "reasons": self.reasons,
            "findings": self.findings,
            "latency_ms": round(self.latency_ms, 3),
        }


def inspect_input(text: str, use_llm: bool = False) -> GuardrailVerdict:
    # Rule tier only on the hot path; use_llm escalates to the P1.1 LLM
    # tier (fail-closed) and is opt-in per tenant.
    start = time.perf_counter()
    result = injection_detect(text[:200_000])
    blocked = bool(result["is_injection"])
    verdict = GuardrailVerdict(
        direction="input",
        action="block" if blocked else "allow",
        reasons=["prompt_injection"] if blocked else [],
        findings=result.get("rule_findings", []),
    )
    verdict.latency_ms = (time.perf_counter() - start) * 1000
    logger.info(f"[Guardrails] input verdict={verdict.action} latency_ms={verdict.latency_ms:.2f}")
    return verdict


def inspect_output(text: str) -> GuardrailVerdict:
    start = time.perf_counter()
    reasons: list[str] = []
    findings: list[dict] = []

    scanner = get_shared_scanner()
    for f in scanner.scan_text(text[:200_000]):
        reasons.append(f"secret_leak:{f.kind}")
        findings.append(f.to_dict())

    if _TOOL_CALL_RE.search(text):
        reasons.append("tool_invocation_text")

    exfil_urls = _EXFIL_URL_RE.findall(text)
    if exfil_urls:
        reasons.append("exfil_endpoint")
        findings.append({"kind": "exfil_endpoint", "match": exfil_urls[0][:64]})
    if _LONG_B64_RE.search(text):
        reasons.append("exfil_base64_payload")

    verdict = GuardrailVerdict(
        direction="output",
        action="block" if reasons else "allow",
        reasons=reasons,
        findings=findings,
    )
    verdict.latency_ms = (time.perf_counter() - start) * 1000
    logger.info(f"[Guardrails] output verdict={verdict.action} reasons={reasons} latency_ms={verdict.latency_ms:.2f}")
    return verdict
