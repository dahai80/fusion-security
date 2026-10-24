"""Union Web shell 模块注册 + 心跳(PRD §5.2 / Issue #35)。

启动时把 frontend/manifest.json 注册到 fusion-gateway shell 注册中心
(POST /api/v1/shell/manifests,Bearer admin key),之后按固定间隔心跳保活,
超时未心跳的模块在 shell 菜单被标记 unreachable(置灰,不删除)。

环境变量开关 —— 需同时设置:
- FUSION_SHELL_GATEWAY_URL: gateway 基址,如 http://127.0.0.1:11432
- FUSION_GATEWAY_ADMIN_KEY: 有 /api/v1/shell/manifests 权限的 gateway key

可选:
- FUSION_SHELL_MANIFEST: manifest 路径覆盖(默认仓内 frontend/manifest.json)

/shell/fusion-security/ 反向代理本身是 gateway 静态配置
(web_shell.modules.fusion-security.upstream/api_key),动态 manifest 只驱动
菜单/entry。gateway 侧接线见 fusion-gateway 仓 issue。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

GATEWAY_URL_ENV = "FUSION_SHELL_GATEWAY_URL"
ADMIN_KEY_ENV = "FUSION_GATEWAY_ADMIN_KEY"
MANIFEST_PATH_ENV = "FUSION_SHELL_MANIFEST"
REGISTER_INTERVAL_SECONDS = 15.0
HTTP_TIMEOUT_SECONDS = 5.0
# 心跳每 15s 一次 —— gateway 掉线/拒绝时不能每个 tick 刷一条告警(告警限频)。
FAILURE_LOG_INTERVAL_SECONDS = 300.0


def _default_manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / "frontend" / "manifest.json"


def shell_registration_enabled() -> bool:
    gateway = os.environ.get(GATEWAY_URL_ENV, "").strip()
    admin_key = os.environ.get(ADMIN_KEY_ENV, "").strip()
    return bool(gateway and admin_key)


def _load_manifest() -> dict[str, Any]:
    path = Path(os.environ.get(MANIFEST_PATH_ENV, "").strip() or _default_manifest_path())
    if not path.exists():
        raise FileNotFoundError(f"shell manifest 不存在: {path}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not manifest.get("id"):
        raise ValueError(f"shell manifest 缺少 id: {path}")
    return manifest


async def register_once() -> tuple[bool, str]:
    # 单次注册/心跳往返。gateway 接受返回 (True, ""),否则 (False, 原因)。
    gateway = os.environ.get(GATEWAY_URL_ENV, "").strip().rstrip("/")
    admin_key = os.environ.get(ADMIN_KEY_ENV, "").strip()
    manifest = _load_manifest()
    url = f"{gateway}/api/v1/shell/manifests"
    headers = {"Authorization": f"Bearer {admin_key}"}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.post(url, json=manifest, headers=headers)
    if resp.status_code in (200, 201, 204):
        return True, ""
    return False, f"注册失败 {url} -> {resp.status_code} {resp.text[:200]}"


async def run_shell_registry() -> None:
    # lifespan 常驻任务:注册 + 心跳直到被取消。永不抛异常 —— gateway 挂掉
    # 不能拖垮安全服务,每次失败记日志后下个间隔重试。
    logger.info(
        "shell registry: 已启用 gateway=%s manifest=%s",
        os.environ.get(GATEWAY_URL_ENV, ""),
        os.environ.get(MANIFEST_PATH_ENV, "") or _default_manifest_path(),
    )
    last_failure_log = 0.0
    consecutive_failures = 0
    while True:
        exc: Exception | None = None
        try:
            ok, reason = await register_once()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            ok = False
            exc = e
            reason = f"往返失败: {type(e).__name__}: {e}"
        if ok:
            if consecutive_failures:
                logger.info("shell registry: 在 %d 次失败后恢复", consecutive_failures)
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            now = time.monotonic()
            if now - last_failure_log >= FAILURE_LOG_INTERVAL_SECONDS:
                last_failure_log = now
                logger.warning("shell registry: %s", reason, exc_info=exc is not None)
        await asyncio.sleep(REGISTER_INTERVAL_SECONDS)
