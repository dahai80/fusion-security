"""Agent tool-call risk scoring for the harness IAM loop (evolution plan P2.2).

Contract-first: schemas/agent-risk-score.v1.json is the versioned exchange
schema (dahai80/fusion-harness#24). Scoring is fully deterministic and
offline — no model calls on the hot path. Policy hints are advisory only;
fusion-harness remains the deny-first executor.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from .assets.checks import _CMD_RISK_RE, _ENV_SECRET_RE, _WIDE_FS_RE
from .assets.signatures import SignatureLibrary

logger = logging.getLogger(__name__)

RISK_SCHEMA_VERSION = 1

_TOOL_CLASS_PATTERNS = [
    ("shell", re.compile(r"(?i)(?<![a-z0-9])(bash|zsh|shell|exec|command|popen|subprocess|terminal)(?![a-z0-9])")),
    (
        "fs_write",
        re.compile(r"(?i)(?<![a-z0-9])(write|edit|delete|remove|mkdir|rmdir|move|rename|chmod|chown)(?![a-z0-9])"),
    ),
    ("network", re.compile(r"(?i)(?<![a-z0-9])(fetch|curl|wget|https?|web|download|upload|socket|net)(?![a-z0-9])")),
    (
        "secret",
        re.compile(r"(?i)(?<![a-z0-9])(credential|token|secret|password|api[_-]?key|private[_-]?key|ssh)(?![a-z0-9])"),
    ),
    ("package", re.compile(r"(?i)(?<![a-z0-9])(install|pip3?|npm|npx|uvx|brew|apt)(?![a-z0-9])")),
]

_BASE_SCORE = {"shell": 50, "fs_write": 30, "network": 25, "secret": 40, "package": 20}

# Reputation weights: each recorded denial for the same tool raises the
# score (capped) so repeated abuse compounds across sessions.
_DENIAL_WEIGHT = 8
_DENIAL_CAP = 24
_REPUTATION_TAIL_BYTES = 65536

_CLASS_THRESHOLDS = [(75, "critical"), (50, "high"), (25, "medium"), (0, "low")]


def _risk_class(score: int) -> str:
    for threshold, cls in _CLASS_THRESHOLDS:
        if score >= threshold:
            return cls
    return "low"


_POLICY_HINTS = {
    "critical": ["deny"],
    "high": ["require_approval", "sandbox"],
    "medium": ["require_approval"],
    "low": ["allow"],
}


def _iter_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


def _denial_count(tenant_id: str, tool_name: str) -> int:
    # Reputation reads the tenant audit jsonl (last tail only — the file is
    # append-only and may grow); unreadable → 0, scoring never fails on IO.
    try:
        from ...engine.tenant.audit import _safe_tenant_slug, audit_log_dir

        path = Path(audit_log_dir()) / f"audit_{_safe_tenant_slug(tenant_id)}.jsonl"
        if not path.exists():
            return 0
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - _REPUTATION_TAIL_BYTES))
            lines = f.read().decode("utf-8", errors="ignore").split("\n")[1:]
        count = 0
        for line in lines:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                rec.get("action") == "agent.tool.decision"
                and rec.get("resource_id") == tool_name
                and str(rec.get("details", {}).get("decision", "")) == "deny"
            ):
                count += 1
        return count
    except Exception as e:
        logger.warning(f"[RiskScore] reputation read failed for {tool_name}: {e}")
        return 0


def score_tool_request(
    tool_name: str,
    arguments: dict | None = None,
    caller: dict | None = None,
    sigs: SignatureLibrary | None = None,
    tenant_id: str = "default",
) -> dict:
    sigs = sigs or SignatureLibrary.load()
    args_text = json.dumps(arguments or {}, ensure_ascii=False)[:4000]
    strings = list(_iter_strings(arguments or {}))

    score = 0
    signals: list[str] = []

    for cls, rx in _TOOL_CLASS_PATTERNS:
        if rx.search(tool_name):
            score += _BASE_SCORE[cls]
            signals.append(f"tool_class:{cls}")

    if _CMD_RISK_RE.search(args_text):
        score += 35
        signals.append("risky_command_pattern")

    wide = [s for s in strings if _wide_fs(s)]
    if wide:
        score += 25
        signals.append("wide_filesystem_scope")

    secret_hits = [s for s in strings if _ENV_SECRET_RE.search(s) and _looks_like_secret_value(s)]
    if secret_hits:
        score += 25
        signals.append("secret_material_in_args")

    indicators = sigs.match_command(args_text) + sigs.match_package(args_text)
    if indicators:
        score += 40
        signals.append(f"signature_match:{indicators[0]}")

    denials = _denial_count(tenant_id, tool_name)
    if denials:
        rep = min(_DENIAL_WEIGHT * denials, _DENIAL_CAP)
        score += rep
        signals.append(f"denial_reputation:{denials}")

    score = max(0, min(100, score))
    risk_class = _risk_class(score)
    result = {
        "schema_version": RISK_SCHEMA_VERSION,
        "tool_name": tool_name,
        "score": score,
        "risk_class": risk_class,
        "policy_hints": list(_POLICY_HINTS[risk_class]),
        "signals": signals,
        "caller": caller or {},
    }
    logger.info(f"[RiskScore] {tool_name} score={score} class={risk_class} signals={signals}")
    return result


def _wide_fs(value: str) -> bool:
    v = value.strip().strip('"')
    return bool(_WIDE_FS_RE.match(v) or v in {"*", "~/*", "/*"})


def _looks_like_secret_value(value: str) -> bool:
    # Only flag when the string plausibly IS a secret material reference
    # (a value assignment), not a mere key name in prose.
    return bool(
        re.search(r"(?i)(api[_-]?keys?|secrets?|tokens?|passwords?|credentials?|aws|ssh|private[_-]?keys?)", value)
    ) and ("=" in value or ":" in value or len(value) > 24)
