from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fusion_core.config import service_port

from .auth import ROLES, APIKey, auth_manager, get_current_key, require_permission
from .routes import console, integrations, patches, projects, reports, scans, schedules, system, vulnerabilities

try:
    from .. import __version__ as _PKG_VERSION
except Exception:
    _PKG_VERSION = "0.0.0"

logger = logging.getLogger(__name__)

_AUTH = [Depends(get_current_key)]

# Issue #40: the gateway /shell proxy forwards /shell/fusion-security/<rest> to backend /<rest>
# (stripping the module prefix), so the SPA must be mounted at the backend root path; the
# /shell/fusion-security/ prefix mount is kept for direct access. SPA pages/static assets carry no
# tenant data, so TenantMiddleware gets a prefix exemption —— the fail-closed tenant semantics of
# the API (/api/v1/*) are completely unchanged.
_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

_SPA_EXACT_PATHS = frozenset({"/", "/dashboard", "/scans", "/vulnerabilities", "/projects", "/favicon.ico"})
_SPA_PREFIXES = ("/assets/", "/shell/fusion-security")


class _SpaExemptPaths(frozenset):
    # TenantMiddleware only does exact `path in exempt` matching; a frozenset subclass overrides
    # __contains__ to support prefix matching, without touching fusion-core (upstream package).
    def __new__(cls, exact: frozenset, prefixes: tuple[str, ...]):
        obj = super().__new__(cls, exact)
        obj._prefixes = prefixes
        return obj

    def __contains__(self, path: object) -> bool:
        return super().__contains__(path) or (isinstance(path, str) and path.startswith(self._prefixes))


class SPAStaticFiles(StaticFiles):
    # SPA fallback: client routes (/dashboard etc.) fall back to index.html when no file matches;
    # API/docs namespaces do not fall back, keeping a bare 404. In Starlette 1.x the 404 is raised
    # as starlette.exceptions.HTTPException (fastapi.HTTPException is a
    # subclass; catching the parent class catches both).
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
    # dist/ is produced by `cd frontend && npm run build` (not committed); skip and log when not built.
    dist = dist_dir or _FRONTEND_DIST
    if not (dist / "index.html").exists():
        logger.info(f"[Startup] SPA static hosting skipped (frontend/dist not built): {dist}")
        return False
    app.mount("/shell/fusion-security", SPAStaticFiles(directory=dist, html=True), name="spa-prefixed")
    app.mount("/", SPAStaticFiles(directory=dist, html=True), name="spa")
    logger.info(f"[Startup] SPA mounted: {dist} (/, /shell/fusion-security/)")
    return True


async def _dispatch_scheduled_scan(schedule) -> None:
    # Feature 4 tick callback: enqueue the scheduled scan (reusing the scans queue path).
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
        logger.info(f"[Scheduler] schedule {schedule.id} enqueued scan={orm.id}")
    finally:
        db.close()


def set_process_title() -> None:
    # Issue #49: process title carries the product name (start.sh launches the uvicorn binary
    # directly; on macOS homebrew Python the Python.app argv overrides exec -a, so setproctitle
    # is the only reliable means). Degrades silently when the dependency is missing.
    try:
        import setproctitle

        # Issue #52: port resolution goes through fusion_core.config.service_port(FUSION_SECURITY_PORT);
        # a non-integer env raises ValueError, caught by the except below to log a warning
        # instead of silently setting a broken title.
        port = service_port("security", default=11454)
        setproctitle.setproctitle(f"fusion-security serve :{port}")
        logger.info(f"[Startup] process title set: fusion-security serve :{port}")
    except Exception as e:
        logger.warning(f"[Startup] setproctitle failed (non-fatal): {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from ..db import init_db

    set_process_title()
    init_db()
    # S-P0-3: never log the master key plaintext, only its readiness.
    auth_manager.ensure_master_key()
    logger.info("Fusion-Security API started, master key ready")

    # Issue #53: the module service key injected by the gateway /shell proxy is persisted at
    # startup as admin. Previously there was no persistence path: manually inserted viewer keys
    # made dashboard /system/health/detailed (system:manage) 403 on every load via the shell
    # proxy. The tenant aligns with the frontend-passed X-Tenant-Id (VITE_TENANT_ID defaults to
    # default), overridable via FUSION_SECURITY_SHELL_TENANT. The key is never logged. Idempotent
    # upsert, safe on repeated startups.
    from ..shell_registry import MODULE_KEY_ENV

    module_key = os.environ.get(MODULE_KEY_ENV, "").strip()
    if module_key:
        tenant = os.environ.get("FUSION_SECURITY_SHELL_TENANT", "default").strip() or "default"
        auth_manager.ensure_module_key(module_key, tenant)
        logger.info(f"[Startup] shell module service key persisted (role=admin, tenant={tenant})")
    else:
        logger.info(f"[Startup] {MODULE_KEY_ENV} not set, skipping module key persistence")

    # Issue #32: the local TenantManager is retired; tenant registration belongs to fusion-identity. Check identity readiness.
    import os as _os

    if _os.environ.get("FUSION_IDENTITY_SERVICE_TOKEN", "").strip():
        logger.info("[Startup] fusion-identity service token configured, JWT verification enabled")
    else:
        logger.warning(
            "[Startup] FUSION_IDENTITY_SERVICE_TOKEN not set, JWT verification unavailable (API Key mode only)"
        )

    # Auto-start the WorkerPool, otherwise enqueued scans stay PENDING forever; reclaim orphan scans left by a previous crash.
    try:
        from .routes import scans as _scans

        await _scans.startup_reconcile_scans()
        await _scans._get_pool().start()
        logger.info("[Startup] WorkerPool auto-started")
    except Exception as e:
        logger.error(f"[Startup] WorkerPool auto-start failed: {e}")

    # Feature 4: start the scheduled-scan scheduler (never started before). The singleton lives in routes/schedules for CRUD.
    scheduler = None
    try:
        from ..engine.scheduler import ScanScheduler
        from .routes import schedules as _schedules

        scheduler = ScanScheduler()
        _schedules.set_scheduler(scheduler)
        await scheduler.start(_dispatch_scheduled_scan)
        logger.info("[Startup] ScanScheduler started")
    except Exception as e:
        logger.warning(f"[Startup] ScanScheduler failed to start (non-fatal): {e}")

    # Issue #35: union-web shell module registration + heartbeat (env-gated, skipped when unconfigured).
    registry_task = None
    from ..shell_registry import run_shell_registry, shell_registration_enabled

    if shell_registration_enabled():
        registry_task = asyncio.create_task(run_shell_registry())
        logger.info("[Startup] shell registry task started (manifest registration/heartbeat)")
    else:
        logger.info("[Startup] shell registry not enabled (missing FUSION_SHELL_GATEWAY_URL/FUSION_ADMIN_KEY)")

    yield

    # Graceful shutdown: stop registry heartbeat, scheduler, and worker pool; drain in-flight tasks with timeout.
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
        description="Local AI code security audit tool API — 100% offline",
        version=_PKG_VERSION,
        lifespan=lifespan,
    )

    cors_origins = [
        o.strip()
        for o in os.environ.get("FUSION_CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
        if o.strip()
    ]
    # P1-3: wildcard origin is invalid and dangerous with allow_credentials=True (any origin can carry cookies), reject explicitly.
    if "*" in cors_origins:
        raise RuntimeError("FUSION_CORS_ORIGINS=* not allowed with allow_credentials=True")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["X-API-Key", "X-Tenant-Id", "Content-Type"],
    )

    # P0-6: rate-limit middleware registration (outermost, runs before routes). Registered after add_middleware, executes first.
    from .middleware import rate_limit_middleware

    app.middleware("http")(rate_limit_middleware)

    # Issue #53: error responses like 401/403 get a top-level message field —— the web-shell host
    # client only reads the top-level message; without it the real RBAC reason (e.g. insufficient
    # permission: system:manage required) gets generalized into "no permission to access this
    # module". Keep detail for compatibility with existing clients; catching the parent class also
    # catches fastapi.HTTPException (same convention as the SPAStaticFiles 404 fallback).
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_envelope(request, exc: StarletteHTTPException):
        message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail, "message": message})

    # Issue #32: integrate fusion-identity. TenantMiddleware enforces the presence of X-Tenant-Id
    # and verifies the Bearer JWT (tid↔header match), fail-closed. require_jwt=False = dual mode:
    # pure API Key requests pass through (get_principal then does the fail-closed tenant check),
    # JWT requests go through verify_jwt.
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
    logger.info("[Startup] TenantMiddleware integrated with fusion-identity (SPA static paths exempt, API not exempt)")

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
    # Issue #60: Admin Console aggregate surface —— system:manage gating lives inside the routes
    # (require_permission); mounting with _AUTH only resolves the principal to avoid double 403 semantics.
    app.include_router(console.router, prefix="/api/v1/console", tags=["Console"])
    # Evolution plan P1.1: agent-security routes (injection detection).
    from .routes import agent as agent_routes

    app.include_router(agent_routes.router, prefix="/api/v1/agent", tags=["Agent Security"])

    # Evolution plan P2.3: guardrails routes (LLM input/output filtering).
    from .routes import guardrails as guardrails_routes

    app.include_router(guardrails_routes.router, prefix="/api/v1/guardrails", tags=["Guardrails"])

    @app.post("/api/v1/keys", tags=["Auth"])
    async def create_api_key(
        name: str = "default", roles: str = "viewer", principal: APIKey = Depends(require_permission("api_key:manage"))
    ):
        role_list = [r.strip() for r in roles.split(",") if r.strip()]
        invalid = [r for r in role_list if r not in ROLES]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Unknown roles: {invalid}")
        key = auth_manager.create_api_key(name, role_list)
        # Issue #60: key management operations enter the audit stream (medium risk, visible in the workbench).
        try:
            from ..engine.tenant.audit import get_audit_logger

            get_audit_logger(principal.tenant_id or "system").log(
                action="key.create",
                actor=principal.name,
                resource_type="api_key",
                resource_id=name,
                details={"roles": role_list},
                risk_level="medium",
            )
        except Exception as e:
            logger.warning(f"[Startup] key.create audit failed: {e}")
        return {"api_key": key, "name": name, "roles": role_list}

    @app.get("/api/v1/keys", tags=["Auth"], dependencies=[Depends(require_permission("api_key:manage"))])
    async def list_api_keys():
        return {"keys": auth_manager.list_keys()}

    # Issue #40: SPA mounting must come after all routes —— Mount "/" swallows subsequent paths in
    # registration order; mounting it first would shadow every API route. Skipped silently when dist is not built.
    _mount_spa(app)

    return app


app = create_app()
