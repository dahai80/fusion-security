"""P0-6: rate limiting middleware + per-tenant concurrent scan quota.

Rate limit: sliding-window counter, bucket key=(client_ip, api_key digest). Over-limit returns 429.
Quota: before creating a scan, count active scans (running/queued/pending) by tenant_id; over
MAX_CONCURRENT_SCANS_PER_TENANT returns 409. Keys without a tenant_id share one "" bucket.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

_WINDOW_SECONDS = 60
_DEFAULT_MAX_PER_MINUTE = 120
MAX_CONCURRENT_SCANS_PER_TENANT = int(os.environ.get("FUSION_MAX_CONCURRENT_SCANS", "4"))

# (ip, key_hash) -> [timestamp,...] sliding window.
_buckets: dict[tuple[str, str], list[float]] = defaultdict(list)


def _max_per_minute() -> int:
    return int(os.environ.get("FUSION_RATE_LIMIT_PER_MINUTE", str(_DEFAULT_MAX_PER_MINUTE)))


def _client_ip(request: Request) -> str:
    # When trusting proxies, prefer the first segment of X-Forwarded-For; otherwise use the direct client host.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _key_hash(request: Request) -> str:
    raw = request.headers.get("x-api-key", "")
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


async def rate_limit_middleware(request: Request, call_next):
    # FUSION_RATE_LIMIT=0 disables rate limiting (tests / single-machine offline scenarios).
    if os.environ.get("FUSION_RATE_LIMIT", "1") == "0":
        return await call_next(request)
    path = request.url.path
    # Only rate-limit protected APIs; the public /health passes through.
    if not path.startswith("/api/v1/") or path.endswith("/system/health"):
        return await call_next(request)
    bucket = (_client_ip(request), _key_hash(request))
    now = time.monotonic()
    window = _buckets[bucket]
    # Drop expired timestamps.
    cutoff = now - _WINDOW_SECONDS
    fresh = [t for t in window if t > cutoff]
    _buckets[bucket] = fresh
    if len(fresh) >= _max_per_minute():
        logger.warning(f"[RateLimit] rejected ip={bucket[0]} key={bucket[1] or '-'} count={len(fresh)}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests, please retry later"},
            headers={"Retry-After": str(_WINDOW_SECONDS)},
        )
    fresh.append(now)
    return await call_next(request)


def count_active_scans(tenant_id: str) -> int:
    # Issue #32: fail-closed. Always filter by tenant_id (an empty tenant never reaches here, already blocked by get_principal).
    from ..db import get_session
    from ..db.models import ScanORM

    db = get_session()
    try:
        q = db.query(ScanORM).filter(ScanORM.status.in_(("running", "queued", "pending")))
        q = q.filter(ScanORM.tenant_id == tenant_id)
        return q.count()
    finally:
        db.close()


def _tenant_quota_cap(tenant_id: str) -> int:
    # Issue #32: on the JWT path the verify_jwt callback caches the quota issued by fusion-identity; the API-key path falls back to the environment variable.
    cap = MAX_CONCURRENT_SCANS_PER_TENANT
    try:
        from ..identity.client import get_tenant_quota

        quota = get_tenant_quota(tenant_id)
        if quota:
            val = quota.get("max_concurrent_scans")
            if isinstance(val, (int, float)) and val > 0:
                return int(val)
    except Exception as e:
        logger.debug(f"[Quota] failed to read identity quota, falling back to default: tid={tenant_id} err={e}")
    return cap


def enforce_scan_quota(tenant_id: str) -> None:
    cap = _tenant_quota_cap(tenant_id)
    active = count_active_scans(tenant_id)
    if active >= cap:
        logger.warning(f"[Quota] tenant {tenant_id or '-'} active scans {active} >= {cap}, rejected")
        raise _QuotaExceeded()


class _QuotaExceeded(Exception):
    pass
