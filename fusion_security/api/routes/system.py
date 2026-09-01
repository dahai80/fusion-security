from __future__ import annotations

import logging
import os
import platform

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ... import __version__


def _resolve_mlx_url() -> str:
    # 与 analyzer.py 同一来源:MLX_BASE_URL 优先,回退 FUSION_AI_URL / FUSION_MLX_URL。
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
def system_info():
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
def health_detailed():
    # S-P1: 此前挂在 public_router(无鉴权),泄露 DB/AI/CPU/磁盘状态。移到鉴权 router。
    # 修复 next(get_session()) 误用 + s.execute("SELECT 1") 在 SA 2.x 报错(需 text())。
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
        logger.warning(f"DB健康检查失败: {e}")
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
def model_config():
    import httpx

    try:
        r = httpx.get(f"{_MLX_BASE_URL}/models", timeout=5)
        if r.status_code == 200:
            data = r.json()
            models = data.get("data", [])
            return {"available": True, "models": models, "default": models[0]["id"] if models else ""}
        return {"available": False, "models": [], "default": ""}
    except Exception as e:
        # P1-4: 异常文本可能泄露内网拓扑/路径,日志保留明细,响应只回通用文案。
        logger.warning(f"获取模型配置失败: {e}")
        return {"available": False, "models": [], "default": "", "error": "model backend unavailable"}


@router.get("/rules")
def list_rules():
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
def list_rulesets():
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
def update_model_config(body: ModelConfigUpdate):
    if not body.default_model:
        raise HTTPException(status_code=400, detail="default_model 不能为空")
    import httpx

    try:
        r = httpx.get(f"{_MLX_BASE_URL}/models", timeout=5)
        if r.status_code == 200:
            models = r.json().get("data", [])
            model_ids = [m.get("id", m.get("model", "")) for m in models]
            if body.default_model not in model_ids:
                raise HTTPException(
                    status_code=400, detail=f"模型 {body.default_model} 不可用，可选: {', '.join(model_ids)}"
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"验证模型失败: {e}")
    logger.info(f"模型配置更新: default_model={body.default_model}")
    return {"status": "ok", "default_model": body.default_model}
