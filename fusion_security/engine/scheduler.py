"""Scheduled scan — periodic scan execution with cron-like scheduling."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
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
    project_path: str = ""
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    config: dict[str, Any] = field(default_factory=dict)

    def compute_next_run(self) -> float:
        interval = FREQUENCY_SECONDS.get(self.frequency, 86400)
        jitter = random.uniform(0, min(interval * 0.1, 900))
        return (self.last_run + interval + jitter) if self.last_run else (time.time() + jitter)


class ScanScheduler:
    def __init__(self):
        self.schedules: dict[str, ScheduledScan] = {}
        self._running = False
        self._task: asyncio.Task | None = None

    def add_schedule(self, schedule: ScheduledScan) -> None:
        schedule.next_run = schedule.compute_next_run()
        self.schedules[schedule.id] = schedule
        logger.info(f"[Scheduler] 添加计划扫描: {schedule.id} freq={schedule.frequency.value}")

    def remove_schedule(self, schedule_id: str) -> bool:
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            logger.info(f"[Scheduler] 删除计划扫描: {schedule_id}")
            return True
        return False

    def list_schedules(self) -> list[dict[str, Any]]:
        return [
            {
                "id": s.id,
                "project_path": s.project_path,
                "frequency": s.frequency.value,
                "enabled": s.enabled,
                "last_run": s.last_run,
                "next_run": s.next_run,
            }
            for s in self.schedules.values()
        ]

    async def start(self, scan_callback: Callable | None = None) -> None:
        if self._running:
            return
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
                    if scan_callback:
                        try:
                            await scan_callback(schedule)
                        except Exception as e:
                            logger.warning(f"[Scheduler] 扫描回调失败: {e}")
            await asyncio.sleep(60)
