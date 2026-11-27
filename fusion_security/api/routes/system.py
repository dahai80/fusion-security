from __future__ import annotations

import logging
import os
import platform

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ... import __version__
from ..auth import require_permission


def _resolve_mlx_url() -> str:
    # Same source as analyzer.py: MLX_BASE_URL first, falling back to FUSION_AI_URL / FUSION_MLX_URL.
    for var in ("MLX_BASE_URL", "FUSION_AI_URL", "FUSION_MLX_URL"):
        val = os.environ.get(var, "").strip()
        if val:
            return val.rstrip("/")
    return "http://localhost:11432/v1"


_MLX_BASE_URL = _resolve_mlx_url()

logger = logging.getLogger(__name__)
router = APIRouter()

public_router = APIRouter()


@router.get("/info")
def system_info(_=Depends(require_permission("scan:read"))):
    return {
        "name": "Fusion-Security",
        "version": __version__,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
    }


@public_router.get("/health")
def health_check():
    return {"status": "ok"}


@router.get("/health/detailed")
def health_detailed(_=Depends(require_permission("system:manage"))):
    # S-P1: previously mounted on public_router (no auth), leaking DB/AI/CPU/disk status. Moved to the authenticated router.
    # Also fixes next(get_session()) misuse + s.execute("SELECT 1") breaking on SA 2.x (requires text()).
    import httpx
    from sqlalchemy import text

    db_ok = True
    try:
        from ...db import get_session

        s = get_session()
        try:
            s.execute(text("SELECT 1"))
        finally:
            s.close()
    except Exception as e:
        db_ok = False
        logger.warning(f"DB health check failed: {e}")
    ai_ok = False
    try:
        r = httpx.get(f"{_MLX_BASE_URL}/models", timeout=3)
        ai_ok = r.status_code == 200
    except Exception:
        pass
    try:
        import psutil

        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.5)
        disk = psutil.disk_usage("/").percent
    except ImportError:
        mem = None
        cpu = None
        disk = None
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else "error",
        "ai_backend": "ok" if ai_ok else "unavailable",
        "memory_percent": getattr(mem, "percent", None),
        "cpu_percent": cpu,
        "disk_percent": disk,
    }


@router.get("/model/config")
def model_config(_=Depends(require_permission("system:manage"))):
    import httpx

    try:
        r = httpx.get(f"{_MLX_BASE_URL}/models", timeout=5)
        if r.status_code == 200:
            data = r.json()
            models = data.get("data", [])
            return {"available": True, "models": models, "default": models[0]["id"] if models else ""}
        return {"available": False, "models": [], "default": ""}
    except Exception as e:
        # P1-4: exception text may leak intranet topology/paths; keep details in logs, return a generic message in the response.
        logger.warning(f"failed to get model config: {e}")
        return {"available": False, "models": [], "default": "", "error": "model backend unavailable"}


@router.get("/rules")
def list_rules(_=Depends(require_permission("scan:read"))):
    from ...engine.rules.engine import RuleEngine

    engine = RuleEngine()
    rules = []
    for r in engine.get_rules():
        rules.append(
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "cwe_id": r.cwe_id,
                "category": r.category,
                "language": r.language,
                "prdid": r.prdid,
            }
        )
    return {"total": len(rules), "rules": rules}


@router.get("/rulesets")
def list_rulesets(_=Depends(require_permission("scan:read"))):
    from ...engine.rules.engine import RuleEngine

    engine = RuleEngine()
    rules = engine.get_rules()
    categories = {}
    for r in rules:
        cat = r.category or "other"
        categories.setdefault(cat, []).append(r.id)
    return {"total_categories": len(categories), "categories": categories}


class ModelConfigUpdate(BaseModel):
    default_model: str = ""


@router.put("/models")
def update_model_config(body: ModelConfigUpdate, _=Depends(require_permission("system:manage"))):
    if not body.default_model:
        raise HTTPException(status_code=400, detail="default_model must not be empty")
    import httpx

    try:
        r = httpx.get(f"{_MLX_BASE_URL}/models", timeout=5)
        if r.status_code == 200:
            models = r.json().get("data", [])
            model_ids = [m.get("id", m.get("model", "")) for m in models]
            if body.default_model not in model_ids:
                raise HTTPException(
                    status_code=400,
                    detail=f"Model {body.default_model} unavailable, valid options: {', '.join(model_ids)}",
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"model verification failed: {e}")
    logger.info(f"model config updated: default_model={body.default_model}")
    return {"status": "ok", "default_model": body.default_model}
