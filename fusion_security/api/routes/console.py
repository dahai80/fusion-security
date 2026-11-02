"""Console routes —— Admin Console 聚合面(Issue #60/#61/#62)。

GET  /console/summary                 四分区聚合 + 高风险速览(#60)
GET  /console/tenants                 租户选择器(identity admin 面,可降级)
GET  /console/audit/events            审计检索:全文/时间窗/类型/风险 + 保存查询重放(#61)
GET  /console/audit/export            过滤窗口 CSV 流式导出(#61)
*    /console/audit/saved-queries     保存查询 CRUD(#61)
*    /console/alerts/subscriptions    告警订阅 CRUD(#61)
GET  /console/notifications           shell 🔔 通知源(拉取式匹配 + 告警表)(#61)
GET  /console/keys                    key 台账:本地 + identity app secrets(#62)
POST /console/keys/rotate             模块 key 轮换(grace 窗口,经 identity)(#62)
POST /console/keys/revoke             模块 key 吊销(依赖上游 #35)(#62)
PATCH /console/keys/local/{key_id}    本地 key 过期/启停(#62)
GET  /console/sso                     SSO 能力面(identity idps summary)(#62)

权限:全部 system:manage(管理台为 admin 面)。审计事件本身也进审计流
(key 操作 medium,订阅/查询管理 low)—— 工作台可见自身操作痕迹。
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ...db.models import AlertSubscriptionORM, AuditMarkORM, SavedQueryORM
from ...db.session import get_session
from ...engine.console import build_console_summary, get_identity_admin_client
from ...engine.console.alert_engine import match_new_alerts, notification_items
from ...engine.console.audit_store import RISK_LEVELS, AuditStore, event_key_candidates
from ...engine.tenant.audit import audit_log_dir, get_audit_logger
from ..auth import APIKey, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()


def _store() -> AuditStore:
    return AuditStore(audit_log_dir())


def _parse_risk(raw: str) -> tuple[str, ...]:
    levels = tuple(x.strip() for x in raw.split(",") if x.strip())
    invalid = [x for x in levels if x not in RISK_LEVELS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"未知风险等级: {invalid}")
    return levels


def _parse_ts(raw: str) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"时间参数需为 epoch 秒: {raw}") from None


def _audit(key: APIKey, action: str, resource_id: str = "", details: dict | None = None, risk: str = "low") -> None:
    try:
        get_audit_logger(key.tenant_id or "system").log(
            action=action,
            actor=key.name,
            resource_type="console",
            resource_id=resource_id,
            details=details or {},
            risk_level=risk,
        )
    except Exception as e:
        logger.warning(f"[Console] 审计记录失败: {e}")


@router.get("/summary")
def console_summary(key: APIKey = Depends(require_permission("system:manage"))):
    logger.info(f"[Console] summary 请求 tenant={key.tenant_id} actor={key.name}")
    return build_console_summary(key.tenant_id)


@router.get("/tenants")
def console_tenants(_=Depends(require_permission("system:manage"))):
    result = get_identity_admin_client().list_tenants()
    logger.info(f"[Console] tenants 请求 available={result.get('available')} count={len(result.get('tenants', []))}")
    return result


def _resolve_filters(
    key: APIKey,
    search: str = "",
    action: str = "",
    risk: str = "",
    start: str = "",
    end: str = "",
    saved_query_id: str = "",
) -> dict:
    # 保存查询定义作为默认过滤;显式传参覆盖之(重放 = 不传参只给 saved_query_id)。
    filters = {"search": search, "action": action, "risk": risk, "start": start, "end": end}
    if saved_query_id:
        db = get_session()
        try:
            q = db.query(SavedQueryORM).filter(SavedQueryORM.id == saved_query_id).first()
        finally:
            db.close()
        if q is None or q.tenant_id != key.tenant_id:
            raise HTTPException(status_code=404, detail="保存查询不存在")
        try:
            definition = json.loads(q.definition or "{}")
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="保存查询定义损坏") from None
        for name in filters:
            if not filters[name]:
                filters[name] = str(definition.get(name, ""))
    return {
        "search": filters["search"],
        "action": filters["action"],
        "risk_levels": _parse_risk(filters["risk"]) if filters["risk"] else (),
        "start_ts": _parse_ts(filters["start"]) if filters["start"] else 0.0,
        "end_ts": _parse_ts(filters["end"]) if filters["end"] else 0.0,
    }


def _marked_keys(tenant_id: str) -> frozenset[str]:
    # Issue #65: 租户已标记事件键集(标记表 → 过滤用)。
    db = get_session()
    try:
        rows = db.query(AuditMarkORM).filter(AuditMarkORM.tenant_id == tenant_id).all()
        return frozenset(r.event_key for r in rows)
    finally:
        db.close()


@router.get("/audit/events")
def audit_events(
    search: str = "",
    action: str = "",
    risk: str = "",
    start: str = "",
    end: str = "",
    saved_query_id: str = "",
    trace_id: str = "",
    resource_id: str = "",
    marked_only: bool = False,
    limit: int = 50,
    offset: int = 0,
    key: APIKey = Depends(require_permission("system:manage")),
):
    limit = max(1, min(limit, 1000))
    filters = _resolve_filters(key, search, action, risk, start, end, saved_query_id)
    marks = _marked_keys(key.tenant_id)
    entries, total = _store().query(
        key.tenant_id,
        offset=offset,
        limit=limit,
        trace_id=trace_id,
        resource_id=resource_id,
        marked_keys=marks,
        marked_only=marked_only,
        **filters,
    )
    for e in entries:
        new_key, legacy = event_key_candidates(e)
        e["event_key"] = new_key
        e["marked"] = bool({new_key, legacy} & marks)
    logger.info(f"[Console] audit 检索 tenant={key.tenant_id} total={total} marked={len(marks)} filters={filters}")
    return {"items": entries, "total": total, "limit": limit, "offset": offset}


@router.get("/audit/export")
def audit_export(
    search: str = "",
    action: str = "",
    risk: str = "",
    start: str = "",
    end: str = "",
    saved_query_id: str = "",
    trace_id: str = "",
    resource_id: str = "",
    key: APIKey = Depends(require_permission("system:manage")),
):
    # 流式 CSV:逐行生成,不在内存攒全量(大时间窗不 OOM)。BOM 头保 Excel 中文。
    filters = _resolve_filters(key, search, action, risk, start, end, saved_query_id)
    tenant_id = key.tenant_id
    _audit(key, "audit.export", details={"filters": {k: str(v) for k, v in filters.items()}}, risk="low")
    store = _store()

    def _rows():
        buf = io.StringIO()
        yield "\ufeff"
        offset = 0
        writer = csv.writer(buf)
        writer.writerow(
            [
                "timestamp",
                "action",
                "actor",
                "risk_level",
                "resource_type",
                "resource_id",
                "trace_id",
                "ip_address",
                "details",
            ]
        )
        yield buf.getvalue()
        while True:
            entries, total = store.query(
                tenant_id, offset=offset, limit=500, trace_id=trace_id, resource_id=resource_id, **filters
            )
            if not entries:
                break
            for rec in entries:
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(
                    [
                        datetime.fromtimestamp(rec["timestamp"]).isoformat(),
                        rec["action"],
                        rec["actor"],
                        rec["risk_level"],
                        rec["resource_type"],
                        rec["resource_id"],
                        rec["trace_id"],
                        rec["ip_address"],
                        json.dumps(rec["details"], ensure_ascii=False),
                    ]
                )
                yield buf.getvalue()
            if offset + 500 >= total:
                break
            offset += 500

    filename = f"audit_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        _rows(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


class SavedQueryBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    search: str = ""
    action: str = ""
    risk: str = ""
    start: str = ""
    end: str = ""


@router.get("/audit/saved-queries")
def list_saved_queries(key: APIKey = Depends(require_permission("system:manage"))):
    db = get_session()
    try:
        rows = (
            db.query(SavedQueryORM)
            .filter(SavedQueryORM.tenant_id == key.tenant_id)
            .order_by(SavedQueryORM.created_at.desc())
            .all()
        )
        return {
            "items": [
                {
                    "id": r.id,
                    "name": r.name,
                    "definition": json.loads(r.definition or "{}"),
                    "created_by": r.created_by,
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ]
        }
    finally:
        db.close()


@router.post("/audit/saved-queries")
def create_saved_query(body: SavedQueryBody, key: APIKey = Depends(require_permission("system:manage"))):
    _parse_risk(body.risk) if body.risk else None
    definition = {"search": body.search, "action": body.action, "risk": body.risk, "start": body.start, "end": body.end}
    db = get_session()
    try:
        row = SavedQueryORM(
            tenant_id=key.tenant_id, name=body.name, definition=json.dumps(definition), created_by=key.name
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    finally:
        db.close()
    _audit(key, "saved_query.create", row.id, {"name": body.name})
    return {"id": row.id, "name": row.name, "definition": definition}


@router.delete("/audit/saved-queries/{query_id}")
def delete_saved_query(query_id: str, key: APIKey = Depends(require_permission("system:manage"))):
    db = get_session()
    try:
        row = db.query(SavedQueryORM).filter(SavedQueryORM.id == query_id).first()
        if row is None or row.tenant_id != key.tenant_id:
            raise HTTPException(status_code=404, detail="保存查询不存在")
        db.delete(row)
        db.commit()
    finally:
        db.close()
    _audit(key, "saved_query.delete", query_id)
    return {"ok": True}


class AuditMarkBody(BaseModel):
    event_key: str = Field(min_length=1, max_length=255)
    marked: bool = True


@router.post("/audit/marks")
def set_audit_mark(body: AuditMarkBody, key: APIKey = Depends(require_permission("system:manage"))):
    # Issue #65: 标记复核 —— 审计 jsonl append-only,分诊态落 audit_review_marks 表,
    # (tenant_id, event_key) 唯一,重复标记幂等。标记/取消均进审计流。
    # Issue #68 R2: 拒绝悬空 event_key(拼写错/过期键)—— 不存在的键静默消失
    # 会让"仅看已标记"无声丢项,这里 fail-fast 404。
    if body.event_key not in _store().known_mark_keys(key.tenant_id):
        raise HTTPException(status_code=404, detail="事件不存在或已被清理")
    db = get_session()
    try:
        if body.marked:
            exists = (
                db.query(AuditMarkORM)
                .filter(AuditMarkORM.tenant_id == key.tenant_id, AuditMarkORM.event_key == body.event_key)
                .first()
            )
            if exists is None:
                db.add(AuditMarkORM(tenant_id=key.tenant_id, event_key=body.event_key, marked_by=key.name))
                db.commit()
        else:
            db.query(AuditMarkORM).filter(
                AuditMarkORM.tenant_id == key.tenant_id, AuditMarkORM.event_key == body.event_key
            ).delete(synchronize_session=False)
            db.commit()
    finally:
        db.close()
    action = "audit.mark_review" if body.marked else "audit.unmark_review"
    _audit(key, action, body.event_key)
    logger.info(f"[Console] 标记复核 {action} event_key={body.event_key} actor={key.name}")
    return {"ok": True, "marked": body.marked}


class AlertSubscriptionBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    event_class: str = ""
    saved_query_id: str = ""
    risk_levels: str = ""


@router.get("/alerts/subscriptions")
def list_alert_subscriptions(key: APIKey = Depends(require_permission("system:manage"))):
    db = get_session()
    try:
        rows = (
            db.query(AlertSubscriptionORM)
            .filter(AlertSubscriptionORM.tenant_id == key.tenant_id)
            .order_by(AlertSubscriptionORM.created_at.desc())
            .all()
        )
        return {
            "items": [
                {
                    "id": r.id,
                    "name": r.name,
                    "event_class": r.event_class,
                    "saved_query_id": r.saved_query_id,
                    "risk_levels": r.risk_levels,
                    "enabled": r.enabled,
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ]
        }
    finally:
        db.close()


@router.post("/alerts/subscriptions")
def create_alert_subscription(body: AlertSubscriptionBody, key: APIKey = Depends(require_permission("system:manage"))):
    if not body.event_class and not body.saved_query_id:
        raise HTTPException(status_code=400, detail="event_class 与 saved_query_id 至少提供一项")
    if body.risk_levels:
        _parse_risk(body.risk_levels)
    db = get_session()
    try:
        row = AlertSubscriptionORM(
            tenant_id=key.tenant_id,
            name=body.name,
            event_class=body.event_class,
            saved_query_id=body.saved_query_id,
            risk_levels=body.risk_levels,
            created_by=key.name,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    finally:
        db.close()
    _audit(key, "alert_subscription.create", row.id, {"name": body.name, "event_class": body.event_class})
    return {"id": row.id, "name": row.name}


@router.delete("/alerts/subscriptions/{sub_id}")
def delete_alert_subscription(sub_id: str, key: APIKey = Depends(require_permission("system:manage"))):
    db = get_session()
    try:
        row = db.query(AlertSubscriptionORM).filter(AlertSubscriptionORM.id == sub_id).first()
        if row is None or row.tenant_id != key.tenant_id:
            raise HTTPException(status_code=404, detail="订阅不存在")
        db.delete(row)
        db.commit()
    finally:
        db.close()
    _audit(key, "alert_subscription.delete", sub_id)
    return {"ok": True}


@router.get("/notifications")
def console_notifications(key: APIKey = Depends(require_permission("system:manage"))):
    # shell 🔔 轮询入口:先增量匹配订阅(拉取式"推送"),再返回告警表。
    fired = match_new_alerts(key.tenant_id, _store())
    result = notification_items(key.tenant_id)
    logger.info(f"[Console] notifications tenant={key.tenant_id} fired={fired} count={result['count']}")
    return result


@router.get("/keys")
def key_inventory(key: APIKey = Depends(require_permission("system:manage"))):
    from ...db.models import ApiKeyORM

    db = get_session()
    try:
        rows = (
            db.query(ApiKeyORM).filter(ApiKeyORM.tenant_id == key.tenant_id).order_by(ApiKeyORM.created_at.desc()).all()
        )
        local = [
            {
                "id": r.id,
                "name": r.name,
                "role": r.role,
                "enabled": r.enabled,
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else "",
                "expires_at": r.expires_at.isoformat() if r.expires_at else "",
            }
            for r in rows
        ]
    finally:
        db.close()
    inventory = get_identity_admin_client().app_secret_inventory()
    return {"local": local, "identity": inventory}


class RotateBody(BaseModel):
    app_id: str = Field(min_length=1, max_length=100)
    grace_seconds: int = Field(default=3600, ge=0, le=30 * 86400)


@router.post("/keys/rotate")
def rotate_key(body: RotateBody, key: APIKey = Depends(require_permission("api_key:manage"))):
    # 轮换经 identity(旧版本进 grace 窗口);新 secret 只随响应返回一次,
    # 不落库不落日志。前端展示后即不可再取。
    result = get_identity_admin_client().rotate_app_secret(body.app_id, body.grace_seconds)
    if not result.get("ok"):
        _audit(key, "key.rotate_failed", body.app_id, {"reason": result.get("reason", "")}, risk="medium")
        raise HTTPException(status_code=502, detail=result.get("reason", "identity 轮换失败"))
    _audit(
        key,
        "key.rotate",
        body.app_id,
        {"grace_seconds": body.grace_seconds, "version": result.get("version")},
        risk="medium",
    )
    logger.info(f"[Console] key 轮换 app={body.app_id} v={result.get('version')} actor={key.name}")
    return result


class RevokeBody(BaseModel):
    app_id: str = Field(min_length=1, max_length=100)
    version: int = Field(ge=1)


@router.post("/keys/revoke")
def revoke_key(body: RevokeBody, key: APIKey = Depends(require_permission("api_key:manage"))):
    result = get_identity_admin_client().revoke_app_secret(body.app_id, body.version)
    if not result.get("ok"):
        _audit(
            key,
            "key.revoke_failed",
            body.app_id,
            {"reason": result.get("reason", ""), "version": body.version},
            risk="medium",
        )
        raise HTTPException(status_code=502, detail=result.get("reason", "identity 吊销失败"))
    _audit(key, "key.revoke", body.app_id, {"version": body.version}, risk="medium")
    return {"ok": True}


class LocalKeyPatchBody(BaseModel):
    expires_at: str = ""
    enabled: bool | None = None


@router.patch("/keys/local/{key_id}")
def patch_local_key(key_id: str, body: LocalKeyPatchBody, key: APIKey = Depends(require_permission("api_key:manage"))):
    from ...db.models import ApiKeyORM

    db = get_session()
    try:
        row = db.query(ApiKeyORM).filter(ApiKeyORM.id == key_id).first()
        if row is None or row.tenant_id != key.tenant_id:
            raise HTTPException(status_code=404, detail="key 不存在")
        if "expires_at" in body.model_fields_set:
            if body.expires_at:
                try:
                    row.expires_at = datetime.fromisoformat(body.expires_at)
                except ValueError:
                    raise HTTPException(status_code=400, detail="expires_at 需为 ISO 格式") from None
            else:
                row.expires_at = None
        if body.enabled is not None:
            row.enabled = body.enabled
        db.commit()
        db.refresh(row)
    finally:
        db.close()
    _audit(key, "key.update", key_id, {"enabled": body.enabled, "expires_at": body.expires_at}, risk="medium")
    return {"ok": True}


@router.get("/sso")
def sso_surface(key: APIKey = Depends(require_permission("system:manage"))):
    # Issue #62: SSO 面按 identity 真实能力渲染 —— 可读且已配置 = enabled 状态;
    # 未配置 = 明确引导;不可读(上游 #35 未上线)= disabled + roadmap 说明,
    # 绝不出现假可用控件。
    summary = get_identity_admin_client().idp_summary(key.tenant_id)
    if not summary.get("available"):
        return {
            "state": "unavailable",
            "reason": summary.get("reason", ""),
            "detail": "SSO 聚合端点待上游提供(fusion-identity#35)",
        }
    if summary.get("configured"):
        return {
            "state": "configured",
            "types": summary.get("types", []),
            "count": summary.get("count", 0),
            "auto_provision": summary.get("auto_provision", False),
        }
    return {
        "state": "not_configured",
        "reason": "租户未配置 IdP",
        "detail": "在 fusion-identity 完成 IdP 配置后此处显示 SSO 状态",
    }
