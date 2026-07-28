from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import auth_manager
from .routes import integrations, patches, projects, reports, scans, system, vulnerabilities

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from ..db import init_db

    init_db()
    auth_manager.create_api_key("master", ["admin"])
    logger.info("Fusion-Security API 已启动, master key 已生成")
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

    app.include_router(projects.router, prefix="/api/v1/projects", tags=["Projects"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
    app.include_router(system.router, prefix="/api/v1/system", tags=["System"])
    app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["Integrations"])
    app.include_router(patches.router, prefix="/api/v1/patches", tags=["Patches"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])

    @app.post("/api/v1/keys", tags=["Auth"])
    async def create_api_key(name: str = "default", roles: str = "viewer"):
        key = auth_manager.create_api_key(name, roles.split(","))
        return {"api_key": key, "name": name, "roles": roles.split(",")}

    @app.get("/api/v1/keys", tags=["Auth"])
    async def list_api_keys():
        return {"keys": auth_manager.list_keys()}

    return app


app = create_app()
