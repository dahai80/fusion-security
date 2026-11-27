"""Union Web shell module registration + heartbeat (PRD §5.2 / Issue #35).

On startup, registers frontend/manifest.json into the fusion-gateway shell registry
(POST /api/v1/shell/manifests, Bearer admin key), then keeps it alive with heartbeats
at a fixed interval; modules whose heartbeat times out are marked unreachable (grayed
out, not deleted) in the shell menu.

Environment switches — both must be set:
- FUSION_SHELL_GATEWAY_URL: gateway base URL, e.g. http://127.0.0.1:11432
- FUSION_ADMIN_KEY: gateway key with /api/v1/shell/manifests permission (resolved via fusion_core.config.admin_key)

Optional:
- FUSION_SHELL_MANIFEST: manifest path override (defaults to in-repo frontend/manifest.json)

The /shell/fusion-security/ reverse proxy itself is static gateway configuration
(web_shell.modules.fusion-security.upstream/api_key); the dynamic manifest only drives
the menu/entry. Gateway-side wiring is tracked in a fusion-gateway repo issue.
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
ADMIN_KEY_ENV = "FUSION_ADMIN_KEY"
MANIFEST_PATH_ENV = "FUSION_SHELL_MANIFEST"
# Issue #40: module api_key — when set, the api_key field is carried in the registration body. When unset, the
# gateway issues an fm- key and the proxy prefers the dynamically registered credential, and fusion-security gets
# 401; self-registration must be disabled.
MODULE_KEY_ENV = "FUSION_SECURITY_SHELL_API_KEY"
REGISTER_INTERVAL_SECONDS = 15.0
HTTP_TIMEOUT_SECONDS = 5.0
# Heartbeat every 15s — when the gateway is down/rejecting, do not log an alert on every tick (alert rate limiting).
FAILURE_LOG_INTERVAL_SECONDS = 300.0


def _default_manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / "frontend" / "manifest.json"


def _gateway_admin_key() -> str:
    # Issue #57: admin key resolution is centralized in fusion_core.config.admin_key (canonical name
    # FUSION_ADMIN_KEY; the prod missing-key RuntimeError is contained inside fusion-core). In bare installs
    # without fusion-core, the fallback only accepts the canonical name; no alias chain duplicated in this
    # repo (pattern: fusion-cowork #204).
    try:
        from fusion_core.config import admin_key

        return admin_key()
    except ImportError:
        key = os.environ.get(ADMIN_KEY_ENV, "")
        if not key:
            logger.warning(
                f"{ADMIN_KEY_ENV} not set: shell gateway registration unavailable (request a key from the fusion-gateway admin API)"
            )
        return key


def shell_registration_enabled() -> bool:
    # Short-circuit when the URL is not configured, without triggering admin key resolution (the prod
    # missing-key RuntimeError is only a configuration error when registration is explicitly requested).
    if not os.environ.get(GATEWAY_URL_ENV, "").strip():
        return False
    return bool(_gateway_admin_key().strip())


def _load_manifest() -> dict[str, Any]:
    path = Path(os.environ.get(MANIFEST_PATH_ENV, "").strip() or _default_manifest_path())
    if not path.exists():
        raise FileNotFoundError(f"shell manifest not found: {path}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not manifest.get("id"):
        raise ValueError(f"shell manifest missing id: {path}")
    return manifest


async def register_once() -> tuple[bool, str]:
    # Single registration/heartbeat round trip. Returns (True, "") if the gateway accepts, otherwise (False, reason).
    # Issue #40: when FUSION_SECURITY_SHELL_API_KEY is set, the api_key field is included in the registration
    # body (the api_key_env in manifest.json points to this variable); the gateway proxy prefers this
    # credential when injecting upstream; the key is never logged.
    gateway = os.environ.get(GATEWAY_URL_ENV, "").strip().rstrip("/")
    gw_key = _gateway_admin_key().strip()
    manifest = _load_manifest()
    body: dict[str, Any] = dict(manifest)
    module_key = os.environ.get(MODULE_KEY_ENV, "").strip()
    if module_key:
        body["api_key"] = module_key
    else:
        logger.warning(
            "[ShellRegistry] %s not set: registration body carries no api_key; the gateway will issue an fm- key;"
            " the issued result (raw_key) is persisted automatically after the registration response (issue #97)",
            MODULE_KEY_ENV,
        )
    url = f"{gateway}/api/v1/shell/manifests"
    headers = {"Authorization": f"Bearer {gw_key}"}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.post(url, json=body, headers=headers)
    if resp.status_code in (200, 201, 204):
        _persist_issued_key(resp)
        return True, ""
    return False, f"registration failed {url} -> {resp.status_code} {resp.text[:200]}"


def _persist_issued_key(resp: httpx.Response) -> None:
    # Issue #97: when issuing/rotating the fm- key, the gateway returns raw_key in the 2xx response body,
    # and only once. It must be persisted to this module's key store, otherwise the proxy-injected Bearer
    # always gets 401. Idempotent upsert (same hash updates role/tenant); the key plaintext is never logged.
    try:
        payload = resp.json() if hasattr(resp, "json") else {}
    except ValueError:
        payload = {}
    raw_key = str((payload or {}).get("raw_key") or "").strip()
    if not raw_key:
        return
    from .api.auth import auth_manager

    tenant = os.environ.get("FUSION_SECURITY_SHELL_TENANT", "default").strip() or "default"
    try:
        auth_manager.create_api_key_from_raw("shell-module", raw_key, ["admin"], tenant_id=tenant)
        logger.info("[ShellRegistry] gateway-issued service key persisted to module key store")
    except Exception as e:
        # A persist failure must not take down the registration heartbeat: the gateway resends next
        # interval (or a static key is configured manually).
        logger.error("[ShellRegistry] failed to persist gateway-issued key: %s", e)


async def run_shell_registry() -> None:
    # Long-lived lifespan task: register + heartbeat until cancelled. Never raises — the gateway being
    # down must not take down the security service; log each failure and retry next interval.
    logger.info(
        "shell registry: enabled gateway=%s manifest=%s",
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
            reason = f"round trip failed: {type(e).__name__}: {e}"
        if ok:
            if consecutive_failures:
                logger.info("shell registry: recovered after %d failures", consecutive_failures)
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            now = time.monotonic()
            if now - last_failure_log >= FAILURE_LOG_INTERVAL_SECONDS:
                last_failure_log = now
                logger.warning("shell registry: %s", reason, exc_info=exc is not None)
        await asyncio.sleep(REGISTER_INTERVAL_SECONDS)
