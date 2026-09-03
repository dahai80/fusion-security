from __future__ import annotations

import contextlib
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .auth import ROLES, auth_manager, get_current_key, require_permission
from .routes import integrations, patches, projects, reports, scans, schedules, system, vulnerabilities

try:
    from .. import __version__ as _PKG_VERSION
except Exception:
    _PKG_VERSION = "0.0.0"

logger = logging.getLogger(__name__)

_AUTH = [Depends(get_current_key)]


async def _dispatch_scheduled_scan(schedule) -> None:
    # Feature 4 tick 回调:把计划扫描入队执行(复用 scans 队列路径)。
    from ..engine.queue import ScanTask, TaskPriority
    from ..models.project import Scan
    from .routes import scans as _scans

    scan = Scan(project_id=schedule.project_id, scan_type="full", trigger="scheduled")
    from ..db.convert import scan_to_orm
    from ..db.session import get_session

    db = get_session()
    try:
        orm = scan_to_orm(scan)
        orm.status = "queued"
        orm.path = schedule.project_path
        orm.tenant_id = schedule.tenant_id or ""
        db.add(orm)
        db.commit()
        db.refresh(orm)
        task = ScanTask(
            priority=TaskPriority.LOW,
            project_path=schedule.project_path,
            config={
                "scan_id": orm.id,
                "scan_type": "full",
                "severity_threshold": schedule.severity,
                "use_ai": False,
                "changed_files": [],
                "tenant_id": orm.tenant_id,
            },
        )
        queue = _scans._get_queue()
        await queue.enqueue(task)
        logger.info(f"[Scheduler] 计划 {schedule.id} 已入队 scan={orm.id}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from ..db import init_db

    init_db()
    # S-P0-3: 绝不记录 master key 明文,只记录就绪状态。
    auth_manager.ensure_master_key()
    logger.info("Fusion-Security API 已启动, master key 已就绪")

    # Issue #32: 本地 TenantManager 已退役,租户注册归 fusion-identity。检查 identity 就绪。
    import os as _os

    if _os.environ.get("FUSION_IDENTITY_SERVICE_TOKEN", "").strip():
        logger.info("[Startup] fusion-identity 服务令牌已配置,JWT 校验启用")
    else:
        logger.warning("[Startup] FUSION_IDENTITY_SERVICE_TOKEN 未设置,JWT 校验不可用(仅 API Key 模式)")

    # 自动启动 WorkerPool,否则入队扫描永久 PENDING;回收上次崩溃遗留的孤儿扫描。
    try:
        from .routes import scans as _scans

        await _scans.startup_reconcile_scans()
        await _scans._get_pool().start()
        logger.info("[Startup] WorkerPool 已自动启动")
    except Exception as e:
        logger.error(f"[Startup] WorkerPool 自动启动失败: {e}")

    # Feature 4: 启动定时扫描调度器(此前从未启动)。单例存于 routes/schedules 供 CRUD。
    scheduler = None
    try:
        from ..engine.scheduler import ScanScheduler
        from .routes import schedules as _schedules

        scheduler = ScanScheduler()
        _schedules.set_scheduler(scheduler)
        await scheduler.start(_dispatch_scheduled_scan)
        logger.info("[Startup] ScanScheduler 已启动")
    except Exception as e:
        logger.warning(f"[Startup] ScanScheduler 启动失败(非致命): {e}")

    yield

    # 优雅停机:停调度器,停工作池,在途任务带 timeout drain。
    if scheduler is not None:
        with contextlib.suppress(Exception):
            await scheduler.stop()
    with contextlib.suppress(Exception):
        from .routes import scans as _scans

        await _scans._get_pool().stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Fusion-Security API",
        description="本地 AI 代码安全审计工具 API — 100% 离线",
        version=_PKG_VERSION,
        lifespan=lifespan,
    )

    cors_origins = [
        o.strip()
        for o in os.environ.get("FUSION_CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
        if o.strip()
    ]
    # P1-3: allow_credentials=True 时通配源非法且危险(任意源可携 cookie),显式拒绝。
    if "*" in cors_origins:
        raise RuntimeError("FUSION_CORS_ORIGINS=* not allowed with allow_credentials=True")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["X-API-Key", "X-Tenant-Id", "Content-Type"],
    )

    # P0-6: 限流中间件注册(最外层,先于路由执行)。add_middleware 后注册先执行。
    from .middleware import rate_limit_middleware

    app.middleware("http")(rate_limit_middleware)

    # Issue #32: 接入 fusion-identity。TenantMiddleware 强制 X-Tenant-Id 存在,
    # 校验 Bearer JWT(tid↔header 匹配),fail-closed。require_jwt=False = 双模式:
    # 纯 API Key 请求放行(由 get_principal 再做 fail-closed 租户校验),JWT 请求走 verify_jwt。
    from fusion_core.tenant import install_tenant_middleware

    from ..identity import make_verify_jwt

    install_tenant_middleware(
        app,
        exempt_paths=frozenset({"/api/v1/system/health", "/docs", "/openapi.json", "/redoc"}),
        verify_jwt=make_verify_jwt(),
        require_jwt=False,
    )
    logger.info("[Startup] TenantMiddleware 已接入 fusion-identity")

    app.include_router(projects.router, prefix="/api/v1/projects", tags=["Projects"], dependencies=_AUTH)
    app.include_router(system.public_router, prefix="/api/v1/system", tags=["System"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"], dependencies=_AUTH)
    app.include_router(
        vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"], dependencies=_AUTH
    )
    app.include_router(system.router, prefix="/api/v1/system", tags=["System"], dependencies=_AUTH)
    app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["Integrations"], dependencies=_AUTH)
    app.include_router(patches.router, prefix="/api/v1/patches", tags=["Patches"], dependencies=_AUTH)
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"], dependencies=_AUTH)
    app.include_router(schedules.router, prefix="/api/v1/schedules", tags=["Schedules"], dependencies=_AUTH)

    @app.post("/api/v1/keys", tags=["Auth"], dependencies=[Depends(require_permission("api_key:manage"))])
    async def create_api_key(name: str = "default", roles: str = "viewer"):
        role_list = [r.strip() for r in roles.split(",") if r.strip()]
        invalid = [r for r in role_list if r not in ROLES]
        if invalid:
            raise HTTPException(status_code=400, detail=f"未知角色: {invalid}")
        key = auth_manager.create_api_key(name, role_list)
        return {"api_key": key, "name": name, "roles": role_list}

    @app.get("/api/v1/keys", tags=["Auth"], dependencies=[Depends(require_permission("api_key:manage"))])
    async def list_api_keys():
        return {"keys": auth_manager.list_keys()}

    return app


app = create_app()
