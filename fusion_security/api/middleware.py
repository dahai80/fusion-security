"""P0-6: 限流中间件 + 每租户并发扫描配额。

限流:滑动窗口计数,桶 key=(client_ip, api_key 摘要)。超限返回 429。
配额:创建扫描前按 tenant_id 统计活跃扫描(running/queued/pending),超
MAX_CONCURRENT_SCANS_PER_TENANT 返回 409。无 tenant_id 的 key 共用一个 "" 桶。
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

# (ip, key_hash) -> [timestamp,...] 滑动窗口。
_buckets: dict[tuple[str, str], list[float]] = defaultdict(list)


def _max_per_minute() -> int:
    return int(os.environ.get("FUSION_RATE_LIMIT_PER_MINUTE", str(_DEFAULT_MAX_PER_MINUTE)))


def _client_ip(request: Request) -> str:
    # 信任代理时优先 X-Forwarded-For 首段;否则用直连 client host。
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
    # FUSION_RATE_LIMIT=0 关闭限流(测试/单机离线场景)。
    if os.environ.get("FUSION_RATE_LIMIT", "1") == "0":
        return await call_next(request)
    path = request.url.path
    # 只对受保护 API 限流;公开 /health 放行。
    if not path.startswith("/api/v1/") or path.endswith("/system/health"):
        return await call_next(request)
    bucket = (_client_ip(request), _key_hash(request))
    now = time.monotonic()
    window = _buckets[bucket]
    # 清理过期戳。
    cutoff = now - _WINDOW_SECONDS
    fresh = [t for t in window if t > cutoff]
    _buckets[bucket] = fresh
    if len(fresh) >= _max_per_minute():
        logger.warning(f"[RateLimit] 拒绝 ip={bucket[0]} key={bucket[1] or '-'} count={len(fresh)}")
        return JSONResponse(
            status_code=429,
            content={"detail": "请求过于频繁,请稍后重试"},
            headers={"Retry-After": str(_WINDOW_SECONDS)},
        )
    fresh.append(now)
    return await call_next(request)


def count_active_scans(tenant_id: str) -> int:
    # 统计指定租户的活跃扫描数(running/queued/pending)。
    from ..db import get_session
    from ..db.models import ScanORM

    db = get_session()
    try:
        q = db.query(ScanORM).filter(ScanORM.status.in_(("running", "queued", "pending")))
        if tenant_id:
            q = q.filter(ScanORM.tenant_id == tenant_id)
        return q.count()
    finally:
        db.close()


def enforce_scan_quota(tenant_id: str) -> None:
    active = count_active_scans(tenant_id)
    if active >= MAX_CONCURRENT_SCANS_PER_TENANT:
        logger.warning(f"[Quota] 租户 {tenant_id or '-'} 活跃扫描 {active} >= {MAX_CONCURRENT_SCANS_PER_TENANT},拒绝")
        raise _QuotaExceeded()


class _QuotaExceeded(Exception):
    pass
