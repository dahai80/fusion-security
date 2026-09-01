from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_session
from ...db.convert import scan_to_orm
from ...db.models import ScanORM
from ...engine.scanner import Scanner, ScanTarget

logger = logging.getLogger(__name__)
router = APIRouter()


class ScanCreate(BaseModel):
    project_id: str = ""
    path: str = ""
    scan_type: str = "full"
    severity_threshold: str = "low"
    use_ai: bool = True
    model: str = ""
    trigger: str = "manual"
    branch: str = ""
    changed_files: list[str] = []


class IncrementalScanCreate(BaseModel):
    project_id: str = ""
    path: str = ""
    base: str = "HEAD~1"
    head: str = "HEAD"
    severity_threshold: str = "low"
    use_ai: bool = True
    model: str = ""


class ScanResponse(BaseModel):
    id: str
    project_id: str
    scan_type: str
    status: str
    severity_threshold: str
    use_ai: bool
    model: str
    trigger: str
    branch: str
    files_scanned: int
    files_skipped: int
    duration_ms: float
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    summary: str


def _scan_orm_to_response(o: ScanORM) -> ScanResponse:
    return ScanResponse(
        id=o.id,
        project_id=o.project_id,
        scan_type=o.scan_type,
        status=o.status,
        severity_threshold=o.severity_threshold,
        use_ai=o.use_ai,
        model=o.model,
        trigger=o.trigger,
        branch=o.branch,
        files_scanned=o.files_scanned,
        files_skipped=o.files_skipped,
        duration_ms=o.duration_ms,
        total_vulnerabilities=o.total_vulnerabilities,
        critical=o.critical,
        high=o.high,
        medium=o.medium,
        low=o.low,
        summary=o.summary,
    )


async def _run_scan(
    scan_id: str, path: str, scan_type: str, severity_threshold: str, use_ai: bool, model: str, changed_files: list[str]
):
    from ...db import get_session
    from ...db.convert import vuln_to_orm

    db = get_session()
    try:
        scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
        if not scan_orm:
            return
        scan_orm.status = "running"
        db.commit()

        target = ScanTarget(path)
        scanner = Scanner(use_ai=use_ai, model=model, project_id=scan_orm.project_id, db=db)

        if scan_type == "incremental" and changed_files:
            result = await scanner.scan_incremental(target, changed_files, severity_threshold)
        else:
            result = await scanner.scan(target, severity_threshold)

        scan_model = result.to_scan_model()
        scan_model.id = scan_id
        for attr in [
            "status",
            "files_scanned",
            "files_skipped",
            "duration_ms",
            "total_vulnerabilities",
            "critical",
            "high",
            "medium",
            "low",
            "summary",
        ]:
            setattr(scan_orm, attr, getattr(scan_model, attr))

        scan_orm.status = "completed"
        from datetime import datetime

        scan_orm.completed_at = datetime.utcnow()

        for v in result.vulnerabilities:
            db.add(vuln_to_orm(v))

        db.commit()
        logger.info(f"扫描完成: {scan_id}, {len(result.vulnerabilities)} 个漏洞")
    except Exception as e:
        logger.error(f"扫描失败 {scan_id}: {e}")
        try:
            scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
            if scan_orm:
                scan_orm.status = "failed"
                scan_orm.summary = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.post("", response_model=ScanResponse)
def create_scan(body: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_session)):
    from ...models.project import Scan

    s = Scan(
        project_id=body.project_id,
        scan_type=body.scan_type,
        severity_threshold=body.severity_threshold,
        use_ai=body.use_ai,
        model=body.model,
        trigger=body.trigger,
        branch=body.branch,
    )
    orm = scan_to_orm(s)
    orm.status = "pending"
    db.add(orm)
    db.commit()
    db.refresh(orm)

    if body.path:
        background_tasks.add_task(
            _run_scan,
            orm.id,
            body.path,
            body.scan_type,
            body.severity_threshold,
            body.use_ai,
            body.model,
            body.changed_files,
        )

    return _scan_orm_to_response(orm)


# ===== Queue endpoints =====

_queue_instance = None


def _get_queue():
    global _queue_instance
    if _queue_instance is None:
        from ...engine.queue import TaskQueue

        _queue_instance = TaskQueue()
    return _queue_instance


_pool_instance = None


def _get_pool():
    global _pool_instance
    if _pool_instance is None:
        from ...engine.queue import WorkerPool

        _pool_instance = WorkerPool(_get_queue(), workers=4, executor=_scan_executor)
    return _pool_instance


async def _scan_executor(task):
    await _run_scan(
        task.config.get("scan_id", ""),
        task.project_path,
        task.config.get("scan_type", "full"),
        task.config.get("severity_threshold", "low"),
        task.config.get("use_ai", True),
        task.config.get("model", ""),
        task.config.get("changed_files", []),
    )
    return {"scan_id": task.config.get("scan_id", ""), "status": "completed"}


class QueueScanCreate(BaseModel):
    project_id: str = ""
    path: str = ""
    scan_type: str = "full"
    severity_threshold: str = "low"
    use_ai: bool = True
    model: str = ""
    priority: int = 2


@router.post("/queue", summary="提交扫描到队列")
async def enqueue_scan(body: QueueScanCreate, db: Session = Depends(get_session)):
    from ...engine.queue import ScanTask, TaskPriority
    from ...models.project import Scan

    s = Scan(
        project_id=body.project_id,
        scan_type=body.scan_type,
        severity_threshold=body.severity_threshold,
        use_ai=body.use_ai,
        model=body.model,
        trigger="queued",
    )
    orm = scan_to_orm(s)
    orm.status = "queued"
    db.add(orm)
    db.commit()
    db.refresh(orm)

    prio = TaskPriority(body.priority) if 0 <= body.priority <= 3 else TaskPriority.NORMAL
    task = ScanTask(
        priority=prio,
        project_path=body.path,
        config={
            "scan_id": orm.id,
            "scan_type": body.scan_type,
            "severity_threshold": body.severity_threshold,
            "use_ai": body.use_ai,
            "model": body.model,
            "changed_files": [],
        },
    )
    queue = _get_queue()
    task_id = await queue.enqueue(task)
    logger.info(f"扫描已入队: scan={orm.id} task={task_id}")
    return {"scan_id": orm.id, "task_id": task_id, "status": "queued"}


@router.get("/queue/status", summary="查询队列状态")
async def queue_status():
    queue = _get_queue()
    pool = _get_pool()
    tasks = await queue.list_tasks()
    by_status = {}
    for t in tasks:
        by_status.setdefault(t.status, 0)
        by_status[t.status] += 1
    return {
        "queue_size": queue.size,
        "pending": queue.pending_count,
        "pool_active": pool.active_count,
        "pool_running": pool.is_running,
        "by_status": by_status,
    }


@router.get("/queue/tasks", summary="列出队列任务")
async def list_queue_tasks(status: str | None = None):
    queue = _get_queue()
    tasks = await queue.list_tasks(status=status)
    return {
        "tasks": [
            {
                "task_id": t.task_id,
                "priority": t.priority,
                "status": t.status,
                "project_path": t.project_path,
                "created_at": t.created_at,
                "progress": t.progress,
            }
            for t in tasks
        ]
    }


@router.post("/queue/{task_id}/cancel", summary="取消队列任务")
async def cancel_queue_task(task_id: str):
    queue = _get_queue()
    ok = await queue.cancel_task(task_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task_id, "status": "cancelled"}


@router.post("/queue/pool/start", summary="启动工作池")
async def start_pool():
    pool = _get_pool()
    await pool.start()
    return {"status": "started", "workers": pool._workers}


@router.post("/queue/pool/stop", summary="停止工作池")
async def stop_pool():
    pool = _get_pool()
    await pool.stop()
    return {"status": "stopped"}


async def startup_reconcile_scans() -> dict:
    # 进程重启后回收孤儿扫描:running 是上次崩溃遗留(无在途执行器),queued 需重入队。
    # 不回收 running 会导致 dashboard 永远显示一个假扫描;不重入队 queued 则任务永久挂起。
    from ...db import get_session
    from ...db.models import ScanORM
    from ...engine.queue import ScanTask, TaskPriority

    db = get_session()
    revived = 0
    failed = 0
    try:
        running = db.query(ScanORM).filter(ScanORM.status == "running").all()
        for s in running:
            s.status = "failed"
            s.summary = "进程重启回收:上次异常退出未完成"
            failed += 1
        db.commit()

        queued = db.query(ScanORM).filter(ScanORM.status == "queued").all()
        queue = _get_queue()
        for s in queued:
            task = ScanTask(
                priority=TaskPriority.NORMAL,
                project_path="",
                config={
                    "scan_id": s.id,
                    "scan_type": s.scan_type,
                    "severity_threshold": s.severity_threshold,
                    "use_ai": s.use_ai,
                    "model": s.model,
                    "changed_files": [],
                },
            )
            await queue.enqueue(task)
            revived += 1
        if revived or failed:
            logger.info(f"[Startup] 孤儿扫描回收: running->failed={failed} queued->reenqueue={revived}")
    finally:
        db.close()
    return {"failed": failed, "reenqueued": revived}


@router.get("/checkpoints", summary="列出所有断点")
def list_checkpoints():
    from ...engine.resume import CheckpointManager

    mgr = CheckpointManager()
    cps = mgr.list_checkpoints()
    return {
        "checkpoints": [
            {
                "scan_id": cp.scan_id,
                "project_path": cp.project_path,
                "completed_stage": cp.completed_stage,
                "updated_at": cp.updated_at,
                "errors": cp.errors,
            }
            for cp in cps
        ]
    }


class ResumeRequest(BaseModel):
    scan_id: str
    path: str
    changed_files: list[str] = []


@router.post("/resume", summary="断点续扫")
def resume_scan(body: ResumeRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_session)):
    from ...engine.resume import CheckpointManager

    mgr = CheckpointManager()
    cp = mgr.load(body.scan_id)
    if not cp:
        raise HTTPException(status_code=404, detail="Checkpoint not found")

    scan_orm = db.query(ScanORM).filter(ScanORM.id == body.scan_id).first()
    if not scan_orm:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan_orm.status = "running"
    db.commit()

    background_tasks.add_task(
        _run_pipeline_resume,
        body.scan_id,
        body.path,
        body.changed_files,
    )
    return {"scan_id": body.scan_id, "status": "resuming", "resume_from": cp.completed_stage}


async def _run_pipeline_resume(scan_id: str, path: str, changed_files: list[str]):
    from ...db import get_session as get_db
    from ...db.models import ScanORM
    from ...engine.pipeline import ScanPipeline

    db = get_db()
    try:
        scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
        if not scan_orm:
            return

        pipeline = ScanPipeline(db=db, project_id=scan_orm.project_id)
        ctx = await pipeline.run(path, changed_files=changed_files or None, scan_id=scan_id)

        scan_orm.status = "completed"
        scan_orm.files_scanned = len(ctx.files)
        scan_orm.summary = f"续扫完成, {len(ctx.vulnerabilities)} 个漏洞"
        from datetime import datetime

        scan_orm.completed_at = datetime.utcnow()
        db.commit()
        logger.info(f"续扫完成: {scan_id}")
    except Exception as e:
        logger.error(f"续扫失败 {scan_id}: {e}")
        try:
            scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
            if scan_orm:
                scan_orm.status = "failed"
                scan_orm.summary = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.get("", response_model=list[ScanResponse])
def list_scans(project_id: str | None = None, status: str | None = None, db: Session = Depends(get_session)):
    q = db.query(ScanORM)
    if project_id:
        q = q.filter(ScanORM.project_id == project_id)
    if status:
        q = q.filter(ScanORM.status == status)
    results = q.order_by(ScanORM.created_at.desc()).all()
    return [_scan_orm_to_response(o) for o in results]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_session)):
    o = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_orm_to_response(o)


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_session)):
    o = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(o)
    db.commit()
    return {"status": "deleted"}


@router.post("/incremental", response_model=ScanResponse)
def create_incremental_scan(
    body: IncrementalScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_session)
):
    try:
        from ...engine.vcs.git import GitHelper

        git = GitHelper(body.path)
        diff = git.get_changed_files(base=body.base, head=body.head)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    from ...models.project import Scan

    s = Scan(
        project_id=body.project_id,
        scan_type="incremental",
        severity_threshold=body.severity_threshold,
        use_ai=body.use_ai,
        model=body.model,
        trigger="incremental",
        branch=git.get_current_branch(),
    )
    orm = scan_to_orm(s)
    orm.status = "pending"
    orm.base_commit = diff.base_commit
    orm.head_commit = diff.head_commit
    db.add(orm)
    db.commit()
    db.refresh(orm)

    if body.path and diff.changed_files:
        background_tasks.add_task(
            _run_scan,
            orm.id,
            body.path,
            "incremental",
            body.severity_threshold,
            body.use_ai,
            body.model,
            diff.changed_files,
        )
    else:
        orm.status = "completed"
        orm.summary = "无代码变更"
        db.commit()

    return _scan_orm_to_response(orm)
