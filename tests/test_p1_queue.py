from __future__ import annotations

import asyncio

import pytest

from fusion_security.engine.queue import ScanTask, TaskPriority, TaskQueue, TaskStatus, WorkerPool


@pytest.fixture
def queue():
    return TaskQueue(maxsize=10)


class TestScanTask:
    def test_default_values(self):
        task = ScanTask()
        assert task.task_id
        assert task.priority == TaskPriority.NORMAL
        assert task.status == TaskStatus.PENDING
        assert task.progress == 0.0

    def test_priority_ordering(self):
        t_low = ScanTask(priority=TaskPriority.LOW)
        t_high = ScanTask(priority=TaskPriority.HIGH)
        t_critical = ScanTask(priority=TaskPriority.CRITICAL)
        tasks = sorted([t_low, t_high, t_critical])
        assert tasks[0].priority == TaskPriority.CRITICAL
        assert tasks[1].priority == TaskPriority.HIGH
        assert tasks[2].priority == TaskPriority.LOW

    def test_custom_path_and_config(self):
        task = ScanTask(project_path="/tmp/test", config={"key": "val"})
        assert task.project_path == "/tmp/test"
        assert task.config["key"] == "val"


class TestTaskQueue:
    @pytest.mark.asyncio
    async def test_enqueue_dequeue(self, queue):
        task = ScanTask(project_path="/tmp/a")
        task_id = await queue.enqueue(task)
        assert task_id == task.task_id
        dequeued = await queue.dequeue(timeout=1.0)
        assert dequeued is not None
        assert dequeued.task_id == task_id

    @pytest.mark.asyncio
    async def test_dequeue_timeout(self, queue):
        result = await queue.dequeue(timeout=0.1)
        assert result is None

    @pytest.mark.asyncio
    async def test_priority_order(self, queue):
        low = ScanTask(priority=TaskPriority.LOW, project_path="low")
        high = ScanTask(priority=TaskPriority.HIGH, project_path="high")
        normal = ScanTask(priority=TaskPriority.NORMAL, project_path="normal")
        await queue.enqueue(low)
        await queue.enqueue(high)
        await queue.enqueue(normal)
        first = await queue.dequeue(timeout=1.0)
        second = await queue.dequeue(timeout=1.0)
        third = await queue.dequeue(timeout=1.0)
        assert first.priority == TaskPriority.HIGH
        assert second.priority == TaskPriority.NORMAL
        assert third.priority == TaskPriority.LOW

    @pytest.mark.asyncio
    async def test_update_status(self, queue):
        task = ScanTask()
        await queue.enqueue(task)
        await queue.update_status(task.task_id, TaskStatus.RUNNING)
        t = await queue.get_task(task.task_id)
        assert t.status == TaskStatus.RUNNING

    @pytest.mark.asyncio
    async def test_get_task(self, queue):
        task = ScanTask(project_path="/tmp/x")
        await queue.enqueue(task)
        found = await queue.get_task(task.task_id)
        assert found.project_path == "/tmp/x"
        missing = await queue.get_task("nonexistent")
        assert missing is None

    @pytest.mark.asyncio
    async def test_list_tasks(self, queue):
        t1 = ScanTask(project_path="a")
        t2 = ScanTask(project_path="b")
        await queue.enqueue(t1)
        await queue.enqueue(t2)
        all_tasks = await queue.list_tasks()
        assert len(all_tasks) == 2

    @pytest.mark.asyncio
    async def test_list_tasks_by_status(self, queue):
        t1 = ScanTask()
        t2 = ScanTask()
        await queue.enqueue(t1)
        await queue.enqueue(t2)
        await queue.update_status(t1.task_id, TaskStatus.RUNNING)
        running = await queue.list_tasks(status=TaskStatus.RUNNING)
        assert len(running) == 1

    @pytest.mark.asyncio
    async def test_cancel_task(self, queue):
        task = ScanTask()
        await queue.enqueue(task)
        ok = await queue.cancel_task(task.task_id)
        assert ok is True
        t = await queue.get_task(task.task_id)
        assert t.status == TaskStatus.CANCELLED
        ok2 = await queue.cancel_task("nonexistent")
        assert ok2 is False

    @pytest.mark.asyncio
    async def test_size_and_pending(self, queue):
        t1 = ScanTask()
        t2 = ScanTask()
        await queue.enqueue(t1)
        await queue.enqueue(t2)
        assert queue.pending_count == 2
        await queue.dequeue(timeout=1.0)
        await queue.update_status(t1.task_id, TaskStatus.RUNNING)
        assert queue.pending_count == 1


class TestWorkerPool:
    @pytest.mark.asyncio
    async def test_pool_start_stop(self, queue):
        pool = WorkerPool(queue, workers=2)
        await pool.start()
        assert pool.is_running is True
        assert pool.active_count == 0
        await pool.stop()
        assert pool.is_running is False

    @pytest.mark.asyncio
    async def test_pool_executes_task(self, queue):
        results = []

        async def executor(task):
            results.append(task.project_path)
            return {"done": True}

        pool = WorkerPool(queue, workers=1, executor=executor)
        task = ScanTask(project_path="/tmp/worker-test")
        await queue.enqueue(task)
        await pool.start()
        await asyncio.sleep(0.5)
        await pool.stop()
        assert "/tmp/worker-test" in results

    @pytest.mark.asyncio
    async def test_pool_skips_cancelled(self, queue):
        executed = []

        async def executor(task):
            executed.append(task.task_id)
            return {}

        pool = WorkerPool(queue, workers=1, executor=executor)
        task = ScanTask(project_path="/tmp/cancel-test")
        await queue.enqueue(task)
        await queue.cancel_task(task.task_id)
        await pool.start()
        await asyncio.sleep(0.5)
        await pool.stop()
        assert task.task_id not in executed

    @pytest.mark.asyncio
    async def test_pool_handles_error(self, queue):
        async def bad_executor(task):
            raise ValueError("boom")

        pool = WorkerPool(queue, workers=1, executor=bad_executor)
        task = ScanTask(project_path="/tmp/err-test")
        await queue.enqueue(task)
        await pool.start()
        await asyncio.sleep(0.5)
        await pool.stop()
        t = await queue.get_task(task.task_id)
        assert t.status == TaskStatus.FAILED
        assert "boom" in t.error
