"""Posture checklist — security posture zone (Issue #60).

Each check item = {id, title, title_en, state, detail}: state ∈ ok/warn/todo/todo_roadmap.
Actionable items (todo/warn) carry a route deep link; items depending on upstream land as
todo_roadmap with the ticket number noted — never a fabricated ok. Every check is locally
decidable (config/env/DB) and never blocks on identity.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

from ...db.session import get_session

logger = logging.getLogger(__name__)


def _check_retention() -> dict:
    # Audit retention in this repo is append-only jsonl with no auto-purge — a todo if
    # no retention days are configured.
    days = os.environ.get("FUSION_AUDIT_RETENTION_DAYS", "").strip()
    if days.isdigit() and int(days) > 0:
        return {"state": "ok", "detail": f"Audit retention set to {days} days"}
    return {
        "state": "todo",
        "detail": "Audit retention days not configured (FUSION_AUDIT_RETENTION_DAYS)",
        "route": "/audit",
    }


def _check_rate_limit() -> dict:
    if os.environ.get("FUSION_RATE_LIMIT_DISABLE", "").strip() in ("1", "true", "True"):
        return {"state": "warn", "detail": "API rate limiting is globally disabled"}
    return {"state": "ok", "detail": "API rate limiting enabled"}


def _check_jwt_verify() -> dict:
    # JWT verification depends on the identity service token; missing = dual mode
    # degrades to API-key-only (audit logs a warn).
    if os.environ.get("FUSION_IDENTITY_SERVICE_TOKEN", "").strip():
        return {"state": "ok", "detail": "JWT verification wired to fusion-identity"}
    return {"state": "todo", "detail": "FUSION_IDENTITY_SERVICE_TOKEN not configured; JWT verification unavailable"}


def _check_master_key() -> dict:
    # A dedicated env for the master key counts as explicit management; the default
    # random key rotates on every restart (warned here).
    if os.environ.get("FUSION_SECURITY_MASTER_KEY", "").strip():
        return {"state": "ok", "detail": "master key explicitly configured"}
    return {
        "state": "warn",
        "detail": "master key not explicitly configured; existing API keys become invalid after restart",
    }


def _check_key_expiry_policy() -> dict:
    # Check for local keys carrying an expiry; all never-expiring = prompt for an expiry policy.
    try:
        db = get_session()
        try:
            from ...db.models import ApiKeyORM

            keys = db.query(ApiKeyORM).filter(ApiKeyORM.enabled == True).all()  # noqa: E712
            now = datetime.utcnow()
            soon = now + timedelta(days=14)
            expiring = [k for k in keys if k.expires_at and k.expires_at <= soon]
            no_expiry = [k for k in keys if not k.expires_at]
            if expiring:
                return {
                    "state": "warn",
                    "detail": f"{len(expiring)} keys expiring soon or already expired",
                    "route": "/keys",
                }
            if no_expiry:
                return {"state": "todo", "detail": f"{len(no_expiry)} keys have no expiry set", "route": "/keys"}
            return {"state": "ok", "detail": "all keys are within their validity period"}
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"[Posture] key expiry check failed: {e}")
        return {"state": "todo", "detail": "key expiry check unavailable", "route": "/keys"}


def build_posture_checklist(idp_summary: dict) -> list[dict]:
    # idp_summary comes from IdentityAdminClient (possibly degraded); the SSO item reports it as-is.
    checks: list[dict] = []

    if idp_summary.get("available"):
        if idp_summary.get("configured"):
            types = ",".join(idp_summary.get("types", [])) or "unknown"
            checks.append({"id": "sso", "state": "ok", "detail": f"SSO configured ({types})"})
        else:
            checks.append({"id": "sso", "state": "todo", "detail": "SSO not configured", "route": "/keys"})
    else:
        checks.append(
            {
                "id": "sso",
                "state": "todo_roadmap",
                "detail": f"SSO status unreadable: {idp_summary.get('reason', 'identity unreachable')}",
            }
        )

    checks.append({"id": "retention", **_check_retention()})
    checks.append({"id": "rate_limit", **_check_rate_limit()})
    checks.append({"id": "jwt_verify", **_check_jwt_verify()})
    checks.append({"id": "master_key", **_check_master_key()})
    checks.append({"id": "key_expiry", **_check_key_expiry_policy()})

    return [
        {
            "id": c["id"],
            "state": c["state"],
            "detail": c["detail"],
            "route": c.get("route", ""),
        }
        for c in checks
    ]
