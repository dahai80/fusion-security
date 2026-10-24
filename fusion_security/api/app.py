from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .auth import ROLES, auth_manager, get_current_key, require_permission
from .routes import integrations, patches, projects, reports, scans, schedules, system, vulnerabilities

try:
    from .. import __version__ as _PKG_VERSION
except Exception:
    _PKG_VERSION = "0.0.0"

logger = logging.getLogger(__name__)

_AUTH = [Depends(get_current_key)]

# Issue #40: gateway /shell 代理把 /shell/fusion-security/<rest> 转发到后端 /<rest>
# (剥离模块前缀),所以 SPA 必须挂在后端根路径;同时保留 /shell/fusion-security/
# 前缀挂载供直连访问。SPA 页面/静态资源无租户数据,对 TenantMiddleware 做
# 前缀豁免 —— API (/api/v1/*) 的 fail-closed 租户语义完全不变。
_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

_SPA_EXACT_PATHS = frozenset({"/", "/dashboard", "/scans", "/vulnerabilities", "/projects", "/favicon.ico"})
_SPA_PREFIXES = ("/assets/", "/shell/fusion-security")


class _SpaExemptPaths(frozenset):
    # TenantMiddleware 只做 `path in exempt` 精确匹配;frozenset 子类改写
    # __contains__ 支持前缀匹配,不动 fusion-core(上游包,见改造边界)。
    def __new__(cls, exact: frozenset, prefixes: tuple[str, ...]):
        obj = super().__new__(cls, exact)
        obj._prefixes = prefixes
        return obj

    def __contains__(self, path: object) -> bool:
        return super().__contains__(path) or (isinstance(path, str) and path.startswith(self._prefixes))


class SPAStaticFiles(StaticFiles):
    # SPA 回退:客户端路由 (/dashboard 等) 未命中文件时回 index.html;
    # API/docs 命名空间不回退,保持裸 404。Starlette 1.x 的 404 以
    # starlette.exceptions.HTTPException 抛出(fastapi.HTTPException 是其
    # 子类,接父类才接得住)。
    async def get_response(self, path: str, scope):
        from starlette.exceptions import HTTPException as StarletteHTTPException

        if path.startswith(("api/", "docs", "openapi.json", "redoc")):
            return await super().get_response(path, scope)
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404:
                raise
            return await super().get_response("index.html", scope)


def _mount_spa(app: FastAPI, dist_dir: Path | None = None) -> bool:
    # dist/ 由 `cd frontend && npm run build` 产出(不入库);未构建时跳过并记日志。
    dist = dist_dir or _FRONTEND_DIST
    if not (dist / "index.html").exists():
        logger.info(f"[Startup] SPA 静态托管跳过(frontend/dist 未构建): {dist}")
        return False
    app.mount("/shell/fusion-security", SPAStaticFiles(directory=dist, html=True), name="spa-prefixed")
    app.mount("/", SPAStaticFiles(directory=dist, html=True), name="spa")
    logger.info(f"[Startup] SPA 已挂载: {dist} (/, /shell/fusion-security/)")
    return True


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

    # Issue #35: union-web shell 模块注册 + 心跳(环境变量门控,未配置则跳过)。
    registry_task = None
    from ..shell_registry import run_shell_registry, shell_registration_enabled

    if shell_registration_enabled():
        registry_task = asyncio.create_task(run_shell_registry())
        logger.info("[Startup] shell registry 任务已启动(manifest 注册/心跳)")
    else:
        logger.info("[Startup] shell registry 未启用(缺 FUSION_SHELL_GATEWAY_URL/FUSION_GATEWAY_ADMIN_KEY)")

    yield

    # 优雅停机:停注册心跳,停调度器,停工作池,在途任务带 timeout drain。
    if registry_task is not None:
        registry_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await registry_task
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
        exempt_paths=_SpaExemptPaths(
            frozenset({"/api/v1/system/health", "/docs", "/openapi.json", "/redoc"}) | _SPA_EXACT_PATHS,
            _SPA_PREFIXES,
        ),
        verify_jwt=make_verify_jwt(),
        require_jwt=False,
    )
    logger.info("[Startup] TenantMiddleware 已接入 fusion-identity(SPA 静态路径豁免,API 不豁免)")

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

    # Issue #40: SPA 挂载必须在所有路由之后 —— Mount "/" 会按注册顺序吞掉后续路径,
    # 放前面会把 API 路由全部遮蔽。dist 未构建时静默跳过。
    _mount_spa(app)

    return app


app = create_app()
