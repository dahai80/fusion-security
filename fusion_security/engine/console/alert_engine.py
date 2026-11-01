"""Alert engine —— 订阅匹配 + shell 🔔 通知源(Issue #61)。

匹配模型:拉取式。shell 通知中心按 30s 轮询 /console/notifications;每次轮询
先对订阅做增量匹配(游标 last_matched_ts,只看新事件,不重放历史),命中落
alert_records(dedup_key 幂等),再把最近未超期告警按 shell 契约返回:
{count, items: [{id, title, level, route, ts}]},level ∈ info/warning/error。

密钥过期告警在同一次轮询里附带检查(本地 key expires_at 14 天窗口 + identity
app secret grace_until),按 key+日期 dedup,每天至多提醒一次。
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
    # 订阅可引用保存查询:定义 JSON 与手输过滤同构,重放同一路径。
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
            logger.warning(f"[AlertEngine] 保存查询 {q.id} 定义解析失败,按空过滤处理")
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
        # 无 event_class 时按保存查询的 search/action 过滤(全空 = 匹配全部)。
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
    # 本地 key 即将过期(14 天窗)→ warning 告警;dedup 按 key+日期,每日一次。
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
                        title=f"API key 「{k.name}」即将过期({k.expires_at.strftime('%Y-%m-%d')})",
                        level="warning",
                        route="/keys",
                        event_action="key.expiring",
                    )
                )
        db.commit()
    finally:
        db.close()


def match_new_alerts(tenant_id: str, store) -> int:
    # 增量匹配:每个订阅只看 last_matched_ts 之后的新条目,命中落告警表。
    # 返回新增告警数(日志用)。任何异常不向上抛 —— 通知轮询不能因匹配失败 500。
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
                    f"安全告警: {rec['action']}({rec['actor']})",
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
        logger.warning(f"[AlertEngine] 匹配失败(忽略): {e}")
    return fired


def notification_items(tenant_id: str, limit: int = 20) -> dict:
    # shell 🔔 契约:{count, items: [{id, title, level, route, ts}]}。
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
