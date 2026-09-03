from __future__ import annotations

import contextlib
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_session
from ...db.convert import scan_to_orm
from ...db.models import ScanORM
from ..auth import APIKey, require_permission

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
    project_id: str | None = None
    scan_type: str
    status: str
    severity_threshold: str
    use_ai: bool
    model: str
    trigger: str
    branch: str
    path: str
    files_scanned: int
    files_skipped: int
    duration_ms: float
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    summary: str
    created_at: str


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
        path=getattr(o, "path", "") or "",
        files_scanned=o.files_scanned,
        files_skipped=o.files_skipped,
        duration_ms=o.duration_ms,
        total_vulnerabilities=o.total_vulnerabilities,
        critical=o.critical,
        high=o.high,
        medium=o.medium,
        low=o.low,
        summary=o.summary,
        created_at=o.created_at.isoformat() if o.created_at else "",
    )


def _scan_tenant_scope(query, api_key: APIKey):
    # Issue #32: fail-closed 租户隔离。get_principal 保证 tenant_id 非空,始终过滤。
    tenant_id = api_key.tenant_id or ""
    return query.filter(ScanORM.tenant_id == tenant_id)


def _check_scan_tenant(o: ScanORM, api_key: APIKey) -> None:
    # Issue #32: fail-closed。tenant_id 必非空,跨租户访问一律 404。
    tenant_id = api_key.tenant_id or ""
    if (o.tenant_id or "") != tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")


async def _run_scan(
    scan_id: str,
    path: str,
    scan_type: str,
    severity_threshold: str,
    use_ai: bool,
    model: str,
    changed_files: list[str],
    tenant_id: str = "",
):
    # Wave 3/4: pipeline 权威路径。Legacy Scanner 已从 API 退役(仅 CLI check/gate/sarif 保留)。
    # 持久化 vulnerabilities + findings + patches,完成后触发 webhook(Feature 5)。
    from datetime import datetime

    from ...db.convert import finding_to_orm, patch_to_orm, vuln_to_orm
    from ...engine.pipeline import PipelineConfig, ScanPipeline

    db = get_session()
    try:
        scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
        if not scan_orm:
            return
        scan_orm.status = "running"
        db.commit()

        config = PipelineConfig(
            use_ai=use_ai,
            model=model,
            severity_threshold=severity_threshold,
        )
        pipeline = ScanPipeline(config=config, db=db, project_id=scan_orm.project_id, tenant_id=tenant_id)
        ctx = await pipeline.run(
            path,
            changed_files=changed_files if (scan_type == "incremental" and changed_files) else None,
            scan_id=scan_id,
        )
        result = pipeline.to_scan_result(ctx)

        scan_orm.files_scanned = result.files_scanned
        scan_orm.files_skipped = result.files_skipped
        scan_orm.duration_ms = result.duration_ms
        scan_orm.total_vulnerabilities = len(result.vulnerabilities)
        scan_orm.critical = sum(1 for v in result.vulnerabilities if v.severity == "critical")
        scan_orm.high = sum(1 for v in result.vulnerabilities if v.severity == "high")
        scan_orm.medium = sum(1 for v in result.vulnerabilities if v.severity == "medium")
        scan_orm.low = sum(1 for v in result.vulnerabilities if v.severity == "low")
        scan_orm.summary = result.summary

        # pipeline 中断(stage 最终失败)记 failed/partial,不再无条件 completed。
        failed_stage = ctx.stage_results.get("pipeline", {}).get("failed_stage")
        if failed_stage:
            scan_orm.status = "failed" if failed_stage in ("recon", "discover") else "partial"
            scan_orm.summary = f"流水线在 {failed_stage} 阶段失败: {'; '.join(ctx.errors[-3:])}"
        else:
            scan_orm.status = "completed"
        scan_orm.completed_at = datetime.utcnow()

        # FK 顺序: vulnerabilities 先落库并 flush,再写 findings/patches(它们 FK 引用 vuln_id)。
        # 单 commit 内 UoW 通常能按依赖排序,但跨表 FK + 无 relationship 关联时偶发 flush 乱序,
        # 显式分两阶段提交更稳。
        for v in result.vulnerabilities:
            db.add(vuln_to_orm(v, scan_id=scan_id, tenant_id=tenant_id))
        db.flush()
        for f in result.findings:
            db.add(finding_to_orm(f, scan_id=scan_id))
        for p in result.patches:
            db.add(patch_to_orm(p))

        db.commit()
        logger.info(
            f"扫描完成: {scan_id}, vulns={len(result.vulnerabilities)} findings={len(result.findings)} patches={len(result.patches)}"
        )

        # Issue #32: best-effort 用量上报到 fusion-identity(失败仅告警,不影响扫描完成)。
        with contextlib.suppress(Exception):
            from ...identity.client import get_identity_client

            await get_identity_client().report_usage(
                tenant_id,
                {
                    "scan_id": scan_id,
                    "vulns": len(result.vulnerabilities),
                    "files_scanned": result.files_scanned,
                    "duration_ms": result.duration_ms,
                },
            )

        # Feature 5: 扫描完成后触发已启用 webhook(scan.completed 事件)。
        with contextlib.suppress(Exception):
            await _notify_webhooks(scan_orm, ctx)
    except Exception as e:
        logger.error(f"扫描失败 {scan_id}: {e}")
        try:
            scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
            if scan_orm:
                scan_orm.status = "failed"
                # P1-5: 异常文本不写入 summary(对外可见),日志已记明细。
                scan_orm.summary = "scan failed: internal error"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


async def _notify_webhooks(scan_orm, ctx) -> None:
    # Feature 5: 从 DB 加载启用的 webhook,过滤 scan.completed 事件后通知。
    # P0-5: secret 从 Fernet 密文解密,传入 WebhookConfig 供 _send 计算 HMAC 签名。
    import json

    from ...db.models import WebhookORM
    from ...engine.ci._crypto import decrypt_secret
    from ...engine.ci.webhook import WebhookConfig, WebhookNotifier

    db = get_session()
    try:
        rows = (
            db.query(WebhookORM)
            .filter(WebhookORM.enabled.is_(True), WebhookORM.tenant_id == (scan_orm.tenant_id or ""))
            .all()
        )
        configs = []
        for row in rows:
            events = json.loads(row.events_json or "[]")
            if "scan.completed" not in events:
                continue
            configs.append(WebhookConfig(url=row.url, secret=decrypt_secret(row.secret_hash or ""), events=events))
        if not configs:
            return
        notifier = WebhookNotifier(configs)
        # notify_scan_complete 是同步(urlopen);放线程池避免阻塞事件循环。
        import asyncio

        await asyncio.to_thread(
            notifier.notify_scan_complete,
            scan_orm.id,
            scan_orm.total_vulnerabilities,
            scan_orm.critical,
            scan_orm.high,
            scan_orm.medium,
            scan_orm.low,
            True,
        )
    finally:
        db.close()


@router.post("", response_model=ScanResponse)
async def create_scan(
    body: ScanCreate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    # P0-6: 路由前先做租户并发配额校验,超限 409。
    from ..middleware import enforce_scan_quota

    try:
        enforce_scan_quota(api_key.tenant_id or "")
    except Exception:
        raise HTTPException(status_code=409, detail="已达到租户最大并发扫描数,请等待现有扫描完成") from None

    from ...engine.queue import ScanTask, TaskPriority
    from ...models.project import Scan

    s = Scan(
        project_id=body.project_id or None,
        scan_type=body.scan_type,
        severity_threshold=body.severity_threshold,
        use_ai=body.use_ai,
        model=body.model,
        trigger=body.trigger,
        branch=body.branch,
    )
    orm = scan_to_orm(s)
    orm.status = "queued"
    orm.path = body.path
    orm.tenant_id = api_key.tenant_id or ""
    db.add(orm)
    db.commit()
    db.refresh(orm)

    # P0-6: 不再用自由 BackgroundTasks 协程(绕过 WorkerPool 并发控制),
    # 改为入队由 WorkerPool 统一调度,与 /queue 路径共用同一并发池。
    if body.path:
        task = ScanTask(
            priority=TaskPriority.NORMAL,
            project_path=body.path,
            config={
                "scan_id": orm.id,
                "scan_type": body.scan_type,
                "severity_threshold": body.severity_threshold,
                "use_ai": body.use_ai,
                "model": body.model,
                "changed_files": body.changed_files,
                "tenant_id": orm.tenant_id,
            },
        )
        queue = _get_queue()
        await queue.enqueue(task)
        logger.info(f"扫描已入队(直连路径): scan={orm.id} tenant={orm.tenant_id}")

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
        task.config.get("tenant_id", ""),
    )
    # A-P0-2: 此前无条件返回 completed,与 DB 实际状态脱节。回查真实状态。
    db = get_session()
    try:
        scan_orm = db.query(ScanORM).filter(ScanORM.id == task.config.get("scan_id", "")).first()
        status = scan_orm.status if scan_orm else "completed"
    finally:
        db.close()
    return {"scan_id": task.config.get("scan_id", ""), "status": status}


class QueueScanCreate(BaseModel):
    project_id: str = ""
    path: str = ""
    scan_type: str = "full"
    severity_threshold: str = "low"
    use_ai: bool = True
    model: str = ""
    priority: int = 2


@router.post("/queue", summary="提交扫描到队列")
async def enqueue_scan(
    body: QueueScanCreate,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    # P0-6: 租户并发配额校验,超限 409。
    from ..middleware import enforce_scan_quota

    try:
        enforce_scan_quota(api_key.tenant_id or "")
    except Exception:
        raise HTTPException(status_code=409, detail="已达到租户最大并发扫描数,请等待现有扫描完成") from None

    from ...engine.queue import ScanTask, TaskPriority
    from ...models.project import Scan

    s = Scan(
        project_id=body.project_id or None,
        scan_type=body.scan_type,
        severity_threshold=body.severity_threshold,
        use_ai=body.use_ai,
        model=body.model,
        trigger="queued",
    )
    orm = scan_to_orm(s)
    orm.status = "queued"
    orm.path = body.path
    orm.tenant_id = api_key.tenant_id or ""
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
            "tenant_id": orm.tenant_id,
        },
    )
    queue = _get_queue()
    task_id = await queue.enqueue(task)
    logger.info(f"扫描已入队: scan={orm.id} task={task_id} tenant={orm.tenant_id}")
    return {"scan_id": orm.id, "task_id": task_id, "status": "queued"}


@router.get("/queue/status", summary="查询队列状态")
async def queue_status(_=Depends(require_permission("scan:read"))):
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
async def list_queue_tasks(status: str | None = None, _=Depends(require_permission("scan:read"))):
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
async def cancel_queue_task(
    task_id: str, db: Session = Depends(get_session), api_key: APIKey = Depends(require_permission("scan:run"))
):
    # A-P0: 此前仅标队列任务 CANCELLED,不更新 ScanORM.status,运行中任务也不中断。
    queue = _get_queue()
    pool = _get_pool()
    task = await queue.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    await queue.cancel_task(task_id)
    with contextlib.suppress(Exception):
        await pool.cancel_active(task_id)
    # 同步 ScanORM 状态:cancelled(若存在对应 scan)。
    scan_id = task.config.get("scan_id", "")
    if scan_id:
        scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
        if scan_orm and scan_orm.status not in ("completed", "failed"):
            # P1-1: 跨租户不可取消他人扫描。
            _check_scan_tenant(scan_orm, api_key)
            scan_orm.status = "cancelled"
            scan_orm.summary = "用户取消"
            db.commit()
            logger.info(f"取消扫描: scan={scan_id} task={task_id}")
    return {"task_id": task_id, "status": "cancelled"}


@router.post("/queue/pool/start", summary="启动工作池")
async def start_pool(_=Depends(require_permission("system:manage"))):
    pool = _get_pool()
    await pool.start()
    return {"status": "started", "workers": pool._workers}


@router.post("/queue/pool/stop", summary="停止工作池")
async def stop_pool(_=Depends(require_permission("system:manage"))):
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
            # A-P0-2: 用 ScanORM.path 重入队,此前 project_path="" 导致执行器空路径扫描。
            task = ScanTask(
                priority=TaskPriority.NORMAL,
                project_path=getattr(s, "path", "") or "",
                config={
                    "scan_id": s.id,
                    "scan_type": s.scan_type,
                    "severity_threshold": s.severity_threshold,
                    "use_ai": s.use_ai,
                    "model": s.model,
                    "changed_files": [],
                    "tenant_id": s.tenant_id or "",
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
def list_checkpoints(_=Depends(require_permission("system:manage"))):
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
def resume_scan(
    body: ResumeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    # P0-6: 续扫也占用并发槽位,先做配额校验。
    from ..middleware import enforce_scan_quota

    try:
        enforce_scan_quota(api_key.tenant_id or "")
    except Exception:
        raise HTTPException(status_code=409, detail="已达到租户最大并发扫描数,请等待现有扫描完成") from None

    from ...engine.resume import CheckpointManager

    mgr = CheckpointManager()
    cp = mgr.load(body.scan_id)
    if not cp:
        raise HTTPException(status_code=404, detail="Checkpoint not found")

    scan_orm = db.query(ScanORM).filter(ScanORM.id == body.scan_id).first()
    if not scan_orm:
        raise HTTPException(status_code=404, detail="Scan not found")
    # P1-1 IDOR: 跨租户不可续扫他人扫描。
    _check_scan_tenant(scan_orm, api_key)
    scan_orm.status = "running"
    scan_orm.path = body.path
    if not scan_orm.tenant_id:
        scan_orm.tenant_id = api_key.tenant_id or ""
    db.commit()

    background_tasks.add_task(
        _run_pipeline_resume,
        body.scan_id,
        body.path,
        body.changed_files,
    )
    return {"scan_id": body.scan_id, "status": "resuming", "resume_from": cp.completed_stage}


async def _run_pipeline_resume(scan_id: str, path: str, changed_files: list[str]):
    from datetime import datetime

    from ...db.convert import finding_to_orm, patch_to_orm, vuln_to_orm
    from ...engine.pipeline import ScanPipeline

    db = get_session()
    try:
        scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
        if not scan_orm:
            return

        pipeline = ScanPipeline(db=db, project_id=scan_orm.project_id, tenant_id=scan_orm.tenant_id or "")
        ctx = await pipeline.run(path, changed_files=changed_files or None, scan_id=scan_id)
        result = pipeline.to_scan_result(ctx)

        # 续扫同 scan_id:先删旧漏洞/findings/patches,避免新旧结果叠加产生重复计数。
        from ...db.models import FindingORM, PatchORM, VulnerabilityORM

        db.query(VulnerabilityORM).filter(VulnerabilityORM.scan_id == scan_id).delete()
        db.query(FindingORM).filter(FindingORM.scan_id == scan_id).delete()
        db.query(PatchORM).filter(PatchORM.scan_id == scan_id).delete()

        scan_orm.files_scanned = result.files_scanned
        scan_orm.files_skipped = result.files_skipped
        scan_orm.duration_ms = result.duration_ms
        scan_orm.total_vulnerabilities = len(result.vulnerabilities)
        scan_orm.critical = sum(1 for v in result.vulnerabilities if v.severity == "critical")
        scan_orm.high = sum(1 for v in result.vulnerabilities if v.severity == "high")
        scan_orm.medium = sum(1 for v in result.vulnerabilities if v.severity == "medium")
        scan_orm.low = sum(1 for v in result.vulnerabilities if v.severity == "low")
        scan_orm.summary = result.summary

        failed_stage = ctx.stage_results.get("pipeline", {}).get("failed_stage")
        scan_orm.status = "failed" if failed_stage else "completed"
        if failed_stage:
            scan_orm.summary = f"续扫在 {failed_stage} 阶段失败"
        scan_orm.completed_at = datetime.utcnow()

        for v in result.vulnerabilities:
            db.add(vuln_to_orm(v, scan_id=scan_id, tenant_id=scan_orm.tenant_id or ""))
        for f in result.findings:
            db.add(finding_to_orm(f, scan_id=scan_id))
        for p in result.patches:
            db.add(patch_to_orm(p))

        db.commit()
        logger.info(f"续扫完成: {scan_id}, vulns={len(result.vulnerabilities)}")

        # Issue #32: best-effort 用量上报到 fusion-identity。
        with contextlib.suppress(Exception):
            from ...identity.client import get_identity_client

            await get_identity_client().report_usage(
                scan_orm.tenant_id or "",
                {
                    "scan_id": scan_id,
                    "vulns": len(result.vulnerabilities),
                    "files_scanned": result.files_scanned,
                    "duration_ms": result.duration_ms,
                    "resume": True,
                },
            )
    except Exception as e:
        logger.error(f"续扫失败 {scan_id}: {e}")
        try:
            scan_orm = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
            if scan_orm:
                scan_orm.status = "failed"
                # P1-5: 异常文本不写入 summary(对外可见),日志已记明细。
                scan_orm.summary = "scan failed: internal error"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.get("", response_model=list[ScanResponse])
def list_scans(
    project_id: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:read")),
):
    q = _scan_tenant_scope(db.query(ScanORM), api_key)
    if project_id:
        q = q.filter(ScanORM.project_id == project_id)
    if status:
        q = q.filter(ScanORM.status == status)
    results = q.order_by(ScanORM.created_at.desc()).all()
    return [_scan_orm_to_response(o) for o in results]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str, db: Session = Depends(get_session), api_key: APIKey = Depends(require_permission("scan:read"))
):
    o = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Scan not found")
    _check_scan_tenant(o, api_key)
    return _scan_orm_to_response(o)


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: str, db: Session = Depends(get_session), api_key: APIKey = Depends(require_permission("scan:run"))
):
    o = db.query(ScanORM).filter(ScanORM.id == scan_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="Scan not found")
    _check_scan_tenant(o, api_key)
    db.delete(o)
    db.commit()
    return {"status": "deleted"}


@router.post("/incremental", response_model=ScanResponse)
def create_incremental_scan(
    body: IncrementalScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
    api_key: APIKey = Depends(require_permission("scan:run")),
):
    # P0-6: 增量扫描同样占用并发槽位,先做配额校验。
    from ..middleware import enforce_scan_quota

    try:
        enforce_scan_quota(api_key.tenant_id or "")
    except Exception:
        raise HTTPException(status_code=409, detail="已达到租户最大并发扫描数,请等待现有扫描完成") from None

    try:
        from ...engine.vcs.git import GitHelper

        git = GitHelper(body.path)
        diff = git.get_changed_files(base=body.base, head=body.head)
    except ValueError as e:
        # P1-6: 不回显内部路径/错误,日志保留明细。
        logger.warning(f"incremental scan 路径非法: {e}")
        raise HTTPException(status_code=400, detail="invalid scan path or not a git repository") from e

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
    orm.path = body.path
    orm.tenant_id = api_key.tenant_id or ""
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
            orm.tenant_id,
        )
    else:
        orm.status = "completed"
        orm.summary = "无代码变更"
        db.commit()

    return _scan_orm_to_response(orm)
