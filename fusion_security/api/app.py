from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .auth import ROLES, auth_manager, get_current_key, require_permission
from .routes import integrations, patches, projects, reports, scans, system, vulnerabilities

logger = logging.getLogger(__name__)

_AUTH = [Depends(get_current_key)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    from ..db import init_db

    init_db()
    master_key = os.environ.get("FUSION_SECURITY_MASTER_KEY", "")
    if master_key:
        auth_manager.create_api_key_from_raw("master", master_key, ["admin"])
    else:
        master_key = auth_manager.create_api_key("master", ["admin"])
        logger.warning(f"[Auth] 未设 FUSION_SECURITY_MASTER_KEY，已生成临时 master key: {master_key}")
    logger.info("Fusion-Security API 已启动, master key 已就绪")
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Fusion-Security API",
        description="本地 AI 代码安全审计工具 API — 100% 离线",
        version="0.5.0",
        lifespan=lifespan,
    )

    cors_origins = os.environ.get("FUSION_CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cors_origins if o.strip()],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
