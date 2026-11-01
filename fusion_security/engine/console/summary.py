"""Console summary —— Admin Console 首页四分区聚合(Issue #60,帧 S1)。

数据源:identity admin 聚合(成员/SSO/key 台账,可降级)+ 本地审计 jsonl +
本地 api_keys 表。所有分区的 degraded 状态显式带 reason,前端渲染降级卡。
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from ...db.session import get_session
from ..tenant.audit import audit_log_dir
from .audit_store import AuditStore
from .identity_admin import get_identity_admin_client
from .posture import build_posture_checklist

logger = logging.getLogger(__name__)

EXPIRING_SOON_DAYS = 14


def _key_zone(tenant_id: str) -> dict:
    # 本地 key 计数(当前租户);identity app 台账数量一并给出(可降级)。
    active = 0
    expiring = 0
    try:
        db = get_session()
        try:
            from ...db.models import ApiKeyORM

            rows = (
                db.query(ApiKeyORM)
                .filter(ApiKeyORM.enabled == True, ApiKeyORM.tenant_id == tenant_id)  # noqa: E712
                .all()
            )
            now = datetime.utcnow()
            soon = now + timedelta(days=EXPIRING_SOON_DAYS)
            active = len(rows)
            expiring = len([k for k in rows if k.expires_at and k.expires_at <= soon])
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"[Console] key 计数失败: {e}")

    inventory = get_identity_admin_client().app_secret_inventory()
    return {
        "local_active": active,
        "local_expiring_soon": expiring,
        "identity_inventory": inventory,
        "route": "/keys",
    }


def build_console_summary(tenant_id: str) -> dict:
    store = AuditStore(audit_log_dir())
    idc = get_identity_admin_client()

    members = idc.member_summary(tenant_id)
    idp = idc.idp_summary(tenant_id)
    audit_counts = store.today_counts(tenant_id)
    posture = build_posture_checklist(idp)
    high_risk_events = store.latest_high_risk(tenant_id, limit=3)

    todo_count = len([c for c in posture if c["state"] in ("todo", "warn")])
    logger.info(
        "[Console] summary tenant=%s audit_today=%d high=%d members_available=%s",
        tenant_id,
        audit_counts["total"],
        audit_counts["high_risk"],
        members.get("available"),
    )
    return {
        "tenant_id": tenant_id,
        "members": {**members, "route": "/console"},
        "audit": {
            "available": True,
            "today_total": audit_counts["total"],
            "today_high_risk": audit_counts["high_risk"],
            "route": "/audit",
        },
        "keys": _key_zone(tenant_id),
        "posture": {"available": True, "todo_count": todo_count, "items": posture, "route": "/keys"},
        "high_risk_events": [
            {
                "action": e["action"],
                "actor": e["actor"],
                "risk_level": e["risk_level"],
                "timestamp": e["timestamp"],
                "details": e["details"],
                "trace_id": e["trace_id"],
            }
            for e in high_risk_events
        ],
    }
