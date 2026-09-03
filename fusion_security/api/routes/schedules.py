"""Scheduled scan CRUD — DB-backed persistence (Feature 4)."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.session import get_session
from ..auth import APIKey, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()

_scheduler = None


def set_scheduler(sched) -> None:
    global _scheduler
    _scheduler = sched


def get_scheduler():
    return _scheduler


class ScheduleCreate(BaseModel):
    name: str = ""
    project_path: str = ""
    frequency: str = "daily"
    severity: str = "low"
    enabled: bool = True
    config: dict = {}


class ScheduleUpdate(BaseModel):
    name: str | None = None
    project_path: str | None = None
    frequency: str | None = None
    severity: str | None = None
    enabled: bool | None = None
    config: dict | None = None


_VALID_FREQ = {"hourly", "daily", "weekly", "monthly"}


def _orm_to_dict(o) -> dict:
    return {
        "id": o.id,
        "name": o.name,
        "project_path": getattr(o, "project_path", "") or "",
        "frequency": getattr(o, "frequency", "") or o.cron or "daily",
        "severity": o.severity,
        "enabled": bool(o.enabled),
        "tenant_id": o.tenant_id,
        "last_run_at": o.last_run_at.isoformat() if o.last_run_at else None,
        "next_run_at": o.next_run_at.isoformat() if o.next_run_at else None,
    }


@router.get("", summary="列出所有定时扫描计划")
async def list_schedules(
    db: Session = Depends(get_session), api_key: APIKey = Depends(require_permission("scan:read"))
):
    from ...db.models import ScheduledScanORM

    q = db.query(ScheduledScanORM)
    # Issue #32: fail-closed。按调用方 tenant_id 过滤,始终生效。
    tenant_id = api_key.tenant_id or ""
    q = q.filter(ScheduledScanORM.tenant_id == tenant_id)
    rows = q.all()
    return {"schedules": [_orm_to_dict(r) for r in rows]}


@router.post("", summary="创建定时扫描计划")
async def create_schedule(
    body: ScheduleCreate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    from ...db.models import ScheduledScanORM
    from ...engine.scheduler import ScheduledScan, ScheduleFrequency

    if body.frequency not in _VALID_FREQ:
        raise HTTPException(status_code=400, detail=f"非法 frequency: {body.frequency} (允许 {sorted(_VALID_FREQ)})")
    if not body.project_path:
        raise HTTPException(status_code=400, detail="project_path 不能为空")

    tenant_id = api_key.tenant_id or ""
    sid = uuid.uuid4().hex[:16]
    sched = ScheduledScan(
        id=sid,
        name=body.name or f"schedule-{sid[:8]}",
        project_path=body.project_path,
        frequency=ScheduleFrequency(body.frequency),
        enabled=body.enabled,
        severity=body.severity,
        tenant_id=tenant_id,
        config=body.config or {},
    )
    # 用 scheduler 落库 + 进内存(它计算 next_run 并持久化)。
    if _scheduler is not None:
        _scheduler.schedules[sid] = sched
        _scheduler._persist(sched)
    else:
        # scheduler 未启动(如 CLI 直连):直接落库,启动后 load_from_db 会载入。
        sched.next_run = sched.compute_next_run()
        from ...engine.scheduler import _schedule_to_orm

        orm = ScheduledScanORM(id=sid)
        db.add(orm)
        _schedule_to_orm(orm, sched)
        db.commit()
    logger.info(f"[Schedule] 创建计划 {sid} path={body.project_path} freq={body.frequency} tenant={tenant_id}")
    return {"id": sid, "status": "created"}


@router.patch("/{schedule_id}", summary="更新定时扫描计划")
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    from ...db.models import ScheduledScanORM

    row = db.query(ScheduledScanORM).filter(ScheduledScanORM.id == schedule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="计划不存在")
    # P1-1 IDOR: 校验租户归属,跨租户不可改。
    tenant_id = api_key.tenant_id or ""
    if (row.tenant_id or "") != tenant_id:
        raise HTTPException(status_code=404, detail="计划不存在")
    if body.frequency is not None and body.frequency not in _VALID_FREQ:
        raise HTTPException(status_code=400, detail=f"非法 frequency: {body.frequency}")
    if body.name is not None:
        row.name = body.name
    if body.project_path is not None:
        row.project_path = body.project_path
    if body.frequency is not None:
        row.frequency = body.frequency
    if body.severity is not None:
        row.severity = body.severity
    if body.enabled is not None:
        row.enabled = body.enabled
    db.commit()
    # 同步内存中的 scheduler 副本。
    if _scheduler is not None:
        from ...engine.scheduler import _orm_to_schedule

        _scheduler.schedules[schedule_id] = _orm_to_schedule(row)
    logger.info(f"[Schedule] 更新计划 {schedule_id}")
    return {"id": schedule_id, "status": "updated"}


@router.delete("/{schedule_id}", summary="删除定时扫描计划")
async def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    from ...db.models import ScheduledScanORM

    row = db.query(ScheduledScanORM).filter(ScheduledScanORM.id == schedule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="计划不存在")
    # P1-1 IDOR: 校验租户归属,跨租户不可删。
    tenant_id = api_key.tenant_id or ""
    if (row.tenant_id or "") != tenant_id:
        raise HTTPException(status_code=404, detail="计划不存在")
    db.delete(row)
    db.commit()
    if _scheduler is not None:
        _scheduler.remove_schedule(schedule_id)
    logger.info(f"[Schedule] 删除计划 {schedule_id}")
    return {"id": schedule_id, "status": "deleted"}
