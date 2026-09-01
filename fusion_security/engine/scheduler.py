"""Scheduled scan — periodic scan execution with cron-like scheduling."""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class ScheduleFrequency(StrEnum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


FREQUENCY_SECONDS = {
    ScheduleFrequency.HOURLY: 3600,
    ScheduleFrequency.DAILY: 86400,
    ScheduleFrequency.WEEKLY: 604800,
    ScheduleFrequency.MONTHLY: 2592000,
}


@dataclass
class ScheduledScan:
    id: str = ""
    name: str = ""
    project_path: str = ""
    project_id: str = ""
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    severity: str = "low"
    tenant_id: str = ""
    config: dict[str, Any] = field(default_factory=dict)

    def compute_next_run(self) -> float:
        interval = FREQUENCY_SECONDS.get(self.frequency, 86400)
        jitter = random.uniform(0, min(interval * 0.1, 900))
        return (self.last_run + interval + jitter) if self.last_run else (time.time() + jitter)


def _orm_to_schedule(o) -> ScheduledScan:
    freq = ScheduleFrequency(o.frequency) if o.frequency in FREQUENCY_SECONDS else ScheduleFrequency.DAILY
    config: dict[str, Any] = {}
    if getattr(o, "config_json", ""):
        try:
            config = json.loads(o.config_json)
        except (json.JSONDecodeError, TypeError):
            config = {}
    last_run = o.last_run_at.timestamp() if o.last_run_at else 0.0
    next_run = o.next_run_at.timestamp() if o.next_run_at else 0.0
    return ScheduledScan(
        id=o.id,
        name=o.name,
        project_path=getattr(o, "project_path", "") or "",
        project_id=o.project_id or "",
        frequency=freq,
        enabled=bool(o.enabled),
        last_run=last_run,
        next_run=next_run,
        severity=o.severity or "low",
        tenant_id=o.tenant_id or "",
        config=config,
    )


def _schedule_to_orm(o, schedule: ScheduledScan) -> None:
    o.name = schedule.name
    # 空 project_id 写 NULL,避免 FK 约束失败(path-only 计划)。
    o.project_id = schedule.project_id or None
    o.project_path = schedule.project_path
    o.frequency = schedule.frequency.value
    o.severity = schedule.severity
    o.enabled = schedule.enabled
    o.tenant_id = schedule.tenant_id
    o.config_json = json.dumps(schedule.config, ensure_ascii=False)
    o.last_run_at = datetime.fromtimestamp(schedule.last_run, tz=UTC) if schedule.last_run else None
    o.next_run_at = datetime.fromtimestamp(schedule.next_run, tz=UTC) if schedule.next_run else None


class ScanScheduler:
    # Feature 4: 计划扫描此前仅内存,重启即丢。现以 ScheduledScanORM 持久化,
    # start() 从 DB 载入 enabled 计划,tick 执行后回写 last_run/next_run。
    def __init__(self, db=None):
        self.schedules: dict[str, ScheduledScan] = {}
        self._running = False
        self._task: asyncio.Task | None = None
        self._db = db

    def _get_db(self):
        if self._db is not None:
            return self._db
        from ..db.session import get_session

        return get_session()

    def _owns_db(self) -> bool:
        # 未注入 db 时,每次操作自行开/关 session;注入时由调用方管理生命周期。
        return self._db is None

    def add_schedule(self, schedule: ScheduledScan) -> None:
        schedule.next_run = schedule.compute_next_run()
        self.schedules[schedule.id] = schedule
        self._persist(schedule)
        logger.info(f"[Scheduler] 添加计划扫描: {schedule.id} freq={schedule.frequency.value}")

    def remove_schedule(self, schedule_id: str) -> bool:
        removed = self.schedules.pop(schedule_id, None) is not None
        db_deleted = self._delete_persisted(schedule_id)
        if removed or db_deleted:
            logger.info(f"[Scheduler] 删除计划扫描: {schedule_id}")
            return True
        return False

    def list_schedules(self) -> list[dict[str, Any]]:
        return [
            {
                "id": s.id,
                "name": s.name,
                "project_path": s.project_path,
                "frequency": s.frequency.value,
                "enabled": s.enabled,
                "last_run": s.last_run,
                "next_run": s.next_run,
                "severity": s.severity,
                "tenant_id": s.tenant_id,
            }
            for s in self.schedules.values()
        ]

    def load_from_db(self) -> int:
        # 从 DB 载入 enabled 计划到内存(供 start 调用)。
        from ..db.models import ScheduledScanORM

        db = self._get_db()
        owns = self._owns_db()
        count = 0
        try:
            rows = db.query(ScheduledScanORM).filter(ScheduledScanORM.enabled.is_(True)).all()
            for row in rows:
                sched = _orm_to_schedule(row)
                if not sched.next_run:
                    sched.next_run = sched.compute_next_run()
                self.schedules[sched.id] = sched
                count += 1
            logger.info(f"[Scheduler] 从 DB 载入 {count} 个 enabled 计划")
        except Exception as e:
            logger.warning(f"[Scheduler] 载入计划失败: {e}")
        finally:
            if owns:
                db.close()
        return count

    def _persist(self, schedule: ScheduledScan) -> None:
        from ..db.models import ScheduledScanORM

        db = self._get_db()
        owns = self._owns_db()
        try:
            row = db.query(ScheduledScanORM).filter(ScheduledScanORM.id == schedule.id).first()
            if not row:
                row = ScheduledScanORM(id=schedule.id)
                db.add(row)
            _schedule_to_orm(row, schedule)
            db.commit()
        except Exception as e:
            logger.warning(f"[Scheduler] 持久化计划失败 {schedule.id}: {e}")
            if owns:
                db.rollback()
        finally:
            if owns:
                db.close()

    def _delete_persisted(self, schedule_id: str) -> bool:
        from ..db.models import ScheduledScanORM

        db = self._get_db()
        owns = self._owns_db()
        deleted = False
        try:
            row = db.query(ScheduledScanORM).filter(ScheduledScanORM.id == schedule_id).first()
            if row:
                db.delete(row)
                db.commit()
                deleted = True
        except Exception as e:
            logger.warning(f"[Scheduler] 删除持久化计划失败 {schedule_id}: {e}")
            if owns:
                db.rollback()
        finally:
            if owns:
                db.close()
        return deleted

    def _mark_run(self, schedule: ScheduledScan) -> None:
        # tick 执行后回写 last_run/next_run,保持内存与 DB 一致。
        self._persist(schedule)

    async def start(self, scan_callback: Callable | None = None) -> None:
        if self._running:
            return
        self.load_from_db()
        self._running = True
        self._task = asyncio.create_task(self._run_loop(scan_callback))
        logger.info("[Scheduler] 启动计划扫描服务")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("[Scheduler] 停止计划扫描服务")

    async def _run_loop(self, scan_callback: Callable | None = None) -> None:
        while self._running:
            now = time.time()
            for sid, schedule in list(self.schedules.items()):
                if not schedule.enabled:
                    continue
                if now >= schedule.next_run:
                    logger.info(f"[Scheduler] 执行计划扫描: {sid}")
                    schedule.last_run = now
                    schedule.next_run = schedule.compute_next_run()
                    self._mark_run(schedule)
                    if scan_callback:
                        try:
                            await scan_callback(schedule)
                        except Exception as e:
                            logger.warning(f"[Scheduler] 扫描回调失败: {e}")
            await asyncio.sleep(60)
