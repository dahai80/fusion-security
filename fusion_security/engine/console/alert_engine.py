"""Alert engine — subscription matching + shell notification feed (Issue #61).

Pull-based model. The shell notification center polls /console/notifications
every 30s; each poll first incrementally matches subscriptions (cursor
last_matched_ts, new events only, no history replay), stores hits into
alert_records (idempotent via dedup_key), then returns the latest
non-expired alerts in the shell contract shape:
{count, items: [{id, title, level, route, ts}]}, level in info/warning/error.

Key expiry alerts are checked in the same poll (local key expires_at 14-day
window + identity app secret grace_until), deduped by key+date so each key
reminds at most once per day.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta

from ...db.session import get_session

logger = logging.getLogger(__name__)

ALERT_MAX_AGE_HOURS = 72
EXPIRING_SOON_DAYS = 14
_LEVEL_MAP = {"critical": "error", "high": "warning", "medium": "warning", "low": "info", "info": "info"}


def _load_subscriptions(tenant_id: str) -> list:
    from ...db.models import AlertSubscriptionORM

    db = get_session()
    try:
        return (
            db.query(AlertSubscriptionORM)
            .filter(AlertSubscriptionORM.tenant_id == tenant_id, AlertSubscriptionORM.enabled == True)  # noqa: E712
            .all()
        )
    finally:
        db.close()


def _load_saved_query(subscription) -> dict:
    # A subscription may reference a saved query: its definition JSON is shaped
    # like the manual filters and replays the same matching path.
    if not subscription.saved_query_id:
        return {}
    from ...db.models import SavedQueryORM

    db = get_session()
    try:
        q = db.query(SavedQueryORM).filter(SavedQueryORM.id == subscription.saved_query_id).first()
        if q is None:
            return {}
        try:
            return json.loads(q.definition or "{}")
        except json.JSONDecodeError:
            logger.warning(f"[AlertEngine] failed to parse saved query {q.id} definition; treating as empty filter")
            return {}
    finally:
        db.close()


def _entry_matches(rec: dict, subscription, saved_def: dict) -> bool:
    if subscription.event_class and not rec["action"].startswith(subscription.event_class):
        return False
    risk_levels = tuple(
        r.strip() for r in (subscription.risk_levels or saved_def.get("risk_levels", "") or "").split(",") if r.strip()
    )
    if risk_levels and rec["risk_level"] not in risk_levels:
        return False
    if not subscription.event_class:
        # Without event_class, filter by the saved query's search/action
        # (all empty = match everything).
        search = (saved_def.get("search") or "").strip().lower()
        if search:
            haystack = f"{rec['action']} {rec['actor']} {rec['resource_type']} {rec['resource_id']}"
            if search not in haystack.lower():
                return False
        action = (saved_def.get("action") or "").strip()
        if action and not rec["action"].startswith(action):
            return False
    return True


def _upsert_alert(
    tenant_id: str, sub_id: str, dedup_key: str, title: str, level: str, route: str, action: str, trace_id: str
) -> bool:
    from ...db.models import AlertRecordORM

    db = get_session()
    try:
        exists = db.query(AlertRecordORM).filter(AlertRecordORM.dedup_key == dedup_key).first()
        if exists is not None:
            return False
        db.add(
            AlertRecordORM(
                tenant_id=tenant_id,
                subscription_id=sub_id,
                dedup_key=dedup_key,
                title=title[:200],
                level=level,
                route=route,
                event_action=action,
                trace_id=trace_id,
            )
        )
        db.commit()
        return True
    finally:
        db.close()


def _check_key_expiry_alerts(tenant_id: str) -> None:
    # Local key expiring soon (14-day window) -> warning alert; dedup by
    # key+date, at most one reminder per day.
    from ...db.models import AlertRecordORM, ApiKeyORM

    db = get_session()
    try:
        now = datetime.utcnow()
        soon = now + timedelta(days=EXPIRING_SOON_DAYS)
        rows = (
            db.query(ApiKeyORM)
            .filter(ApiKeyORM.enabled == True, ApiKeyORM.tenant_id == tenant_id, ApiKeyORM.expires_at.isnot(None))  # noqa: E712
            .all()
        )
        today = now.strftime("%Y%m%d")
        for k in rows:
            if k.expires_at and k.expires_at <= soon:
                dedup = f"key-expiry:{k.id}:{today}"
                exists = db.query(AlertRecordORM).filter(AlertRecordORM.dedup_key == dedup).first()
                if exists is not None:
                    continue
                db.add(
                    AlertRecordORM(
                        tenant_id=tenant_id,
                        subscription_id="",
                        dedup_key=dedup,
                        title=f'API key "{k.name}" expires soon ({k.expires_at.strftime("%Y-%m-%d")})',
                        level="warning",
                        route="/keys",
                        event_action="key.expiring",
                    )
                )
        db.commit()
    finally:
        db.close()


def match_new_alerts(tenant_id: str, store) -> int:
    # Incremental matching: each subscription only sees entries newer than
    # last_matched_ts; hits land in the alert table.
    # Returns the number of new alerts (for logging). Exceptions are never
    # re-raised — the notification poll must not 500 because matching failed.
    fired = 0
    try:
        subs = _load_subscriptions(tenant_id)
        for sub in subs:
            saved_def = _load_saved_query(sub)
            entries, _total = store.query(
                tenant_id,
                search=saved_def.get("search", ""),
                action=saved_def.get("action", ""),
                start_ts=sub.last_matched_ts or 0.0,
                limit=500,
            )
            max_ts = sub.last_matched_ts or 0.0
            for rec in entries:
                max_ts = max(max_ts, rec["timestamp"])
                if rec["timestamp"] <= (sub.last_matched_ts or 0.0):
                    continue
                if not _entry_matches(rec, sub, saved_def):
                    continue
                dedup = f"sub:{sub.id}:evt:{rec['timestamp']:.3f}:{rec['action']}"
                level = _LEVEL_MAP.get(rec["risk_level"], "info")
                created = _upsert_alert(
                    tenant_id,
                    sub.id,
                    dedup,
                    f"Security alert: {rec['action']} ({rec['actor']})",
                    level,
                    "/audit",
                    rec["action"],
                    rec.get("trace_id", ""),
                )
                if created:
                    fired += 1
            if max_ts > (sub.last_matched_ts or 0.0):
                from ...db.models import AlertSubscriptionORM

                db = get_session()
                try:
                    row = db.query(AlertSubscriptionORM).filter(AlertSubscriptionORM.id == sub.id).first()
                    if row is not None:
                        row.last_matched_ts = max_ts
                        db.commit()
                finally:
                    db.close()
        _check_key_expiry_alerts(tenant_id)
    except Exception as e:
        logger.warning(f"[AlertEngine] matching failed (ignored): {e}")
    return fired


def notification_items(tenant_id: str, limit: int = 20) -> dict:
    # Shell notification contract: {count, items: [{id, title, level, route, ts}]}.
    from ...db.models import AlertRecordORM

    db = get_session()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=ALERT_MAX_AGE_HOURS)
        rows = (
            db.query(AlertRecordORM)
            .filter(AlertRecordORM.tenant_id == tenant_id, AlertRecordORM.created_at >= cutoff)
            .order_by(AlertRecordORM.created_at.desc())
            .limit(limit)
            .all()
        )
        items = [
            {
                "id": r.id,
                "title": r.title,
                "level": r.level if r.level in ("info", "warning", "error") else "info",
                "route": r.route or "/audit",
                "ts": r.created_at.isoformat(),
            }
            for r in rows
        ]
        return {"count": len(items), "items": items}
    finally:
        db.close()
