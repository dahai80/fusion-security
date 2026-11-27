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


@router.get("", summary="List all scheduled scans")
async def list_schedules(
    db: Session = Depends(get_session), api_key: APIKey = Depends(require_permission("scan:read"))
):
    from ...db.models import ScheduledScanORM

    q = db.query(ScheduledScanORM)
    # Issue #32: fail-closed. Always filter by the caller's tenant_id.
    tenant_id = api_key.tenant_id or ""
    q = q.filter(ScheduledScanORM.tenant_id == tenant_id)
    rows = q.all()
    return {"schedules": [_orm_to_dict(r) for r in rows]}


@router.post("", summary="Create a scheduled scan")
async def create_schedule(
    body: ScheduleCreate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    from ...db.models import ScheduledScanORM
    from ...engine.scheduler import ScheduledScan, ScheduleFrequency

    if body.frequency not in _VALID_FREQ:
        raise HTTPException(
            status_code=400, detail=f"Invalid frequency: {body.frequency} (allowed {sorted(_VALID_FREQ)})"
        )
    if not body.project_path:
        raise HTTPException(status_code=400, detail="project_path must not be empty")

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
    # Persist via the scheduler and load it into memory (it computes next_run and persists).
    if _scheduler is not None:
        _scheduler.schedules[sid] = sched
        _scheduler._persist(sched)
    else:
        # Scheduler not started (e.g. direct CLI usage): persist directly; load_from_db will pick it up at startup.
        sched.next_run = sched.compute_next_run()
        from ...engine.scheduler import _schedule_to_orm

        orm = ScheduledScanORM(id=sid)
        db.add(orm)
        _schedule_to_orm(orm, sched)
        db.commit()
    logger.info(f"[Schedule] schedule created {sid} path={body.project_path} freq={body.frequency} tenant={tenant_id}")
    return {"id": sid, "status": "created"}


@router.patch("/{schedule_id}", summary="Update a scheduled scan")
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    from ...db.models import ScheduledScanORM

    row = db.query(ScheduledScanORM).filter(ScheduledScanORM.id == schedule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # P1-1 IDOR: verify tenant ownership; cross-tenant modification is not allowed.
    tenant_id = api_key.tenant_id or ""
    if (row.tenant_id or "") != tenant_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if body.frequency is not None and body.frequency not in _VALID_FREQ:
        raise HTTPException(status_code=400, detail=f"Invalid frequency: {body.frequency}")
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
    # Sync the in-memory scheduler copy.
    if _scheduler is not None:
        from ...engine.scheduler import _orm_to_schedule

        _scheduler.schedules[schedule_id] = _orm_to_schedule(row)
    logger.info(f"[Schedule] schedule updated {schedule_id}")
    return {"id": schedule_id, "status": "updated"}


@router.delete("/{schedule_id}", summary="Delete a scheduled scan")
async def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    from ...db.models import ScheduledScanORM

    row = db.query(ScheduledScanORM).filter(ScheduledScanORM.id == schedule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # P1-1 IDOR: verify tenant ownership; cross-tenant deletion is not allowed.
    tenant_id = api_key.tenant_id or ""
    if (row.tenant_id or "") != tenant_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(row)
    db.commit()
    if _scheduler is not None:
        _scheduler.remove_schedule(schedule_id)
    logger.info(f"[Schedule] schedule deleted {schedule_id}")
    return {"id": schedule_id, "status": "deleted"}
