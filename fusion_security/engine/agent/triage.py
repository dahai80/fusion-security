"""Laya first-pass event triage (issue #103).

Routes event triage/classification through the fusion-mlx typed-decision
API (POST /v1/laya/decide, model aac6fef/laya-multilingual-mlx, <15ms P50)
instead of a full LLM turn per event. The LLM pipeline stays the escalation
tier and the arbiter: any noul answer, low confidence, timeout, or an
unreachable decision API escalates — fail-closed, never auto-decided.

Confidence contract:
- at least one dimension confident (>= min confidence) -> local decision;
  low-confidence dimensions (harm_severity is server-side discounted by
  design) are ignored unless none is confident. Binary guard dimensions
  answer through the noul field (positive-class probability; verified
  live against the pinned laya model)
- no confident dimension OR timeout/unreachable -> escalate to the LLM
  pipeline, which stays the arbiter — escalation never guesses
Thresholds are env-configurable; loopback-only egress via the shared MLX url.
"""

from __future__ import annotations

import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)

TRIAGE_SCHEMA_VERSION = 1
# Model max_len is 1024 — triage input is a compact extract, never full payloads.
LAYA_MAX_INPUT_CHARS = 1024
DECIDE_PATH = "/v1/laya/decide"
GUARD_PRESET = "guard"
MODERATION_PRESET = "moderation"
VALID_PRESETS = (GUARD_PRESET, MODERATION_PRESET)

MIN_CONFIDENCE_ENV = "FUSION_SECURITY_LAYA_MIN_CONFIDENCE"
TIMEOUT_ENV = "FUSION_SECURITY_LAYA_TIMEOUT_MS"
DEFAULT_MIN_CONFIDENCE = 0.80
DEFAULT_TIMEOUT_MS = 5_000


def _resolve_mlx_url() -> str:
    # Same resolution chain as engine.ai.analyzer (MLX_BASE_URL canonical,
    # compose/helm aliases kept) so triage and AI share one egress point.
    for var in ("MLX_BASE_URL", "FUSION_AI_URL", "FUSION_MLX_URL"):
        val = os.environ.get(var, "").strip()
        if val:
            return val.rstrip("/")
    return "http://localhost:11432/v1"


def min_confidence() -> float:
    raw = os.environ.get(MIN_CONFIDENCE_ENV, "").strip()
    try:
        val = float(raw) if raw else DEFAULT_MIN_CONFIDENCE
    except ValueError:
        logger.warning(f"[Triage] invalid {MIN_CONFIDENCE_ENV}={raw!r}, using default {DEFAULT_MIN_CONFIDENCE}")
        val = DEFAULT_MIN_CONFIDENCE
    return min(max(val, 0.0), 1.0)


def timeout_seconds() -> float:
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    try:
        val = float(raw) if raw else DEFAULT_TIMEOUT_MS
    except ValueError:
        logger.warning(f"[Triage] invalid {TIMEOUT_ENV}={raw!r}, using default {DEFAULT_TIMEOUT_MS}")
        val = DEFAULT_TIMEOUT_MS
    return max(val, 100.0) / 1000.0


def compact_extract(text: str, limit: int = LAYA_MAX_INPUT_CHARS) -> str:
    # Compact extract: strip + collapse whitespace, hard truncate to max_len.
    collapsed = " ".join(text.split())
    if len(collapsed) > limit:
        collapsed = collapsed[:limit]
        logger.debug(f"[Triage] input truncated to {limit} chars (model max_len)")
    return collapsed


async def decide(
    text: str,
    preset: str = GUARD_PRESET,
    questions: list[str] | None = None,
    *,
    base_url: str = "",
    api_key: str = "",
) -> dict:
    # Raw /v1/laya/decide round-trip. Returns the envelope verbatim plus
    # "_latency_ms"; raises on transport/HTTP failure so callers decide
    # their own escalation (no silent fallback here).
    base = (base_url or _resolve_mlx_url()).rstrip("/")
    # Base may carry the /v1 suffix (analyzer convention) — decide path is
    # absolute under the API root, avoid /v1/v1 duplication.
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    url = base + DECIDE_PATH
    body: dict = {"prompt": compact_extract(text), "preset": preset}
    if questions:
        body["questions"] = list(questions)[:64]
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    started = time.perf_counter()
    async with httpx.AsyncClient(timeout=timeout_seconds()) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        payload = resp.json()
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    logger.info(f"[Triage] decide ok: preset={preset} latency={elapsed_ms:.1f}ms")
    payload["_latency_ms"] = round(elapsed_ms, 2)
    return payload


async def triage_event(
    text: str,
    preset: str = GUARD_PRESET,
    questions: list[str] | None = None,
    *,
    base_url: str = "",
    api_key: str = "",
) -> dict:
    """First-pass triage with escalation policy applied.

    Returns {schema_version, tier, suspicious, decision, reasons, latency_ms}
    where tier is "local" (decided by laya within threshold) or "escalate"
    (noul / low confidence / timeout / unreachable -> LLM pipeline is the
    arbiter). Escalation never guesses a verdict.
    """
    started = time.perf_counter()
    if not text or not text.strip():
        # Nothing to decide on — never auto-clear an empty event.
        logger.warning("[Triage] empty input; escalating")
        return {
            "schema_version": TRIAGE_SCHEMA_VERSION,
            "tier": "escalate",
            "suspicious": None,
            "decision": None,
            "reasons": ["empty_input"],
            "latency_ms": round((time.perf_counter() - started) * 1000.0, 2),
        }
    try:
        envelope = await decide(text, preset, questions, base_url=base_url, api_key=api_key)
    except Exception as e:
        logger.warning(f"[Triage] decide unavailable ({type(e).__name__}: {e}); escalating")
        return {
            "schema_version": TRIAGE_SCHEMA_VERSION,
            "tier": "escalate",
            "suspicious": None,
            "decision": None,
            "reasons": [f"decision_api_unavailable: {type(e).__name__}"],
            "latency_ms": round((time.perf_counter() - started) * 1000.0, 2),
        }

    answers = envelope.get("answers") or {}
    threshold = min_confidence()
    reasons: list[str] = []
    suspicious = False
    confident_dims = 0
    malformed = False
    for dim, ans in answers.items():
        if not isinstance(ans, dict):
            malformed = True
            reasons.append(f"malformed_answer:{dim}")
            continue
        confidence = float(ans.get("confidence", 0.0))
        if confidence < threshold:
            # Not decision-grade on its own (harm_severity is server-side
            # discounted by design) — it is ignored unless no dim is
            # confident, in which case the whole event is mid-band.
            reasons.append(f"ignored_low_confidence:{dim}:{confidence:.3f}<{threshold}")
            continue
        confident_dims += 1
        # Guard dimensions: noul carries the positive-class probability
        # (verified live: injection text -> prompt_injection noul=0.93;
        # benign text -> sensitive_data noul=0.02). High noul = flagged.
        if dim in ("jailbreak", "prompt_injection", "sensitive_data"):
            positive = (
                float(ans.get("noul", 1.0))
                if ans.get("type") == "noul"
                else (1.0 if str(ans.get("choice", "")).lower() in ("yes", "true", "flagged") else 0.0)
            )
            if positive >= 0.5:
                suspicious = True
                reasons.append(f"flagged:{dim}:p={positive:.3f}")
        elif dim == "harm_severity":
            score = float(ans.get("score", 0.0))
            if score >= 2.0:
                suspicious = True
                reasons.append(f"flagged:{dim}:score={score}")
    latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
    local_ok = confident_dims > 0 and not malformed
    tier = "local" if local_ok else "escalate"
    if local_ok and not any(r.startswith("flagged") for r in reasons):
        reasons.append("clean:no_confident_flag")
    logger.info(f"[Triage] triage tier={tier} suspicious={suspicious} dims={len(answers)} latency={latency_ms}ms")
    return {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "tier": tier,
        "suspicious": suspicious if local_ok else None,
        "decision": {d: a for d, a in answers.items() if isinstance(a, dict)},
        "reasons": reasons,
        "latency_ms": latency_ms,
        "model": envelope.get("model", ""),
        "usage": envelope.get("usage", {}),
    }
