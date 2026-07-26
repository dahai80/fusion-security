from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class TaskPriority(IntEnum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


class TaskStatus(str):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(order=True)
class ScanTask:
    sort_key: tuple = field(init=False)
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    priority: TaskPriority = TaskPriority.NORMAL
    project_path: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    status: str = TaskStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    progress: float = 0.0

    def __post_init__(self):
        self.sort_key = (self.priority, self.created_at)


class TaskQueue:
    def __init__(self, maxsize: int = 1000, max_completed: int = 1000):
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=maxsize)
        self._tasks: Dict[str, ScanTask] = {}
        self._lock = asyncio.Lock()
        self._max_completed = max_completed

    async def enqueue(self, task: ScanTask) -> str:
        async with self._lock:
            self._tasks[task.task_id] = task
        await self._queue.put(task)
        logger.info(f"[TaskQueue] 入队: {task.task_id} priority={task.priority.name} path={task.project_path}")
        return task.task_id

    async def dequeue(self, timeout: float = 30.0) -> Optional[ScanTask]:
        try:
            task = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            return task
        except asyncio.TimeoutError:
            return None

    async def update_status(self, task_id: str, status: str, **kwargs) -> None:
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = status
                for k, v in kwargs.items():
                    setattr(self._tasks[task_id], k, v)
                logger.info(f"[TaskQueue] 状态更新: {task_id} -> {status}")
        if status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
            await self._cleanup_completed()

    async def get_task(self, task_id: str) -> Optional[ScanTask]:
        async with self._lock:
            return self._tasks.get(task_id)

    async def list_tasks(self, status: Optional[str] = None) -> List[ScanTask]:
        async with self._lock:
            tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        return tasks

    async def cancel_task(self, task_id: str) -> bool:
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = TaskStatus.CANCELLED
                logger.info(f"[TaskQueue] 取消任务: {task_id}")
                return True
        return False

    @property
    def size(self) -> int:
        return self._queue.qsize()

    @property
    def pending_count(self) -> int:
        return sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING)

    async def _cleanup_completed(self) -> None:
        async with self._lock:
            completed = [
                tid for tid, t in self._tasks.items()
                if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
            ]
            if len(completed) > self._max_completed:
                remove = completed[:len(completed) - self._max_completed]
                for tid in remove:
                    del self._tasks[tid]
                logger.debug(f"[TaskQueue] 清理 {len(remove)} 个已完成任务")


class WorkerPool:
    def __init__(self, queue: TaskQueue, workers: int = 4,
                 executor: Optional[Callable[[ScanTask], Coroutine]] = None):
        self._queue = queue
        self._workers = workers
        self._executor = executor
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._active: Dict[str, asyncio.Task] = {}

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        for i in range(self._workers):
            t = asyncio.create_task(self._worker_loop(i))
            self._tasks.append(t)
        logger.info(f"[WorkerPool] 启动 {self._workers} 个工作线程")

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
        self._active.clear()
        logger.info("[WorkerPool] 已停止")

    async def _worker_loop(self, worker_id: int) -> None:
        logger.info(f"[Worker-{worker_id}] 启动")
        while self._running:
            task = await self._queue.dequeue(timeout=5.0)
            if task is None:
                continue
            if task.status == TaskStatus.CANCELLED:
                continue
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()
            await self._queue.update_status(task.task_id, TaskStatus.RUNNING)
            self._active[task.task_id] = asyncio.current_task()
            try:
                if self._executor:
                    result = await self._executor(task)
                    task.result = result
                    task.status = TaskStatus.COMPLETED
                    task.completed_at = time.time()
                    await self._queue.update_status(
                        task.task_id, TaskStatus.COMPLETED,
                        result=result, completed_at=task.completed_at,
                    )
                    logger.info(f"[Worker-{worker_id}] 完成: {task.task_id}")
                else:
                    task.status = TaskStatus.FAILED
                    task.error = "No executor configured"
                    await self._queue.update_status(
                        task.task_id, TaskStatus.FAILED, error=task.error,
                    )
            except asyncio.CancelledError:
                task.status = TaskStatus.CANCELLED
                await self._queue.update_status(task.task_id, TaskStatus.CANCELLED)
                break
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.completed_at = time.time()
                await self._queue.update_status(
                    task.task_id, TaskStatus.FAILED,
                    error=str(e), completed_at=task.completed_at,
                )
                logger.error(f"[Worker-{worker_id}] 任务失败: {task.task_id} error={e}")
            finally:
                self._active.pop(task.task_id, None)

    @property
    def active_count(self) -> int:
        return len(self._active)

    @property
    def is_running(self) -> bool:
        return self._running
