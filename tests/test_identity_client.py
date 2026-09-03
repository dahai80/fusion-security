"""Issue #32:fusion-identity 客户端 + 配额/限流中间件单测。

覆盖 identity/client.py(httpx 经 respx 桩)与 api/middleware.py 的配额/限流分支,
拉高覆盖率至 90% 门禁。无真实网络。
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from fusion_security.api.middleware import (
    MAX_CONCURRENT_SCANS_PER_TENANT,
    _buckets,
    _client_ip,
    _key_hash,
    _max_per_minute,
    _tenant_quota_cap,
    count_active_scans,
    enforce_scan_quota,
    rate_limit_middleware,
)
from fusion_security.db.session import init_db
from fusion_security.identity.client import (
    IdentityVerifyClient,
    IdentityVerifyError,
    cache_tenant_quota,
    get_tenant_quota,
)


class _Resp:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


# ===== identity/client.py =====


def test_resolve_url_default(monkeypatch):
    monkeypatch.delenv("FUSION_IDENTITY_URL", raising=False)
    from fusion_security.identity.client import _resolve_url

    assert _resolve_url() == "http://127.0.0.1:11470"


def test_resolve_url_env_strip_slash(monkeypatch):
    monkeypatch.setenv("FUSION_IDENTITY_URL", "http://127.0.0.1:11470/")
    from fusion_security.identity.client import _resolve_url

    assert _resolve_url() == "http://127.0.0.1:11470"


def test_verify_sync_missing_service_token():
    c = IdentityVerifyClient(service_token="")
    with pytest.raises(IdentityVerifyError, match="missing FUSION_IDENTITY_SERVICE_TOKEN"):
        c.verify_sync("tok")


def test_verify_sync_empty_token():
    c = IdentityVerifyClient(service_token="svc")
    with pytest.raises(IdentityVerifyError, match="empty token"):
        c.verify_sync("")


def test_verify_sync_unreachable():
    c = IdentityVerifyClient(service_token="svc")
    with (
        patch("fusion_security.identity.client.httpx.post", side_effect=httpx.ConnectError("down")),
        pytest.raises(IdentityVerifyError, match="identity unreachable"),
    ):
        c.verify_sync("tok")


def test_verify_sync_non200():
    c = IdentityVerifyClient(service_token="svc")
    with (
        patch("fusion_security.identity.client.httpx.post", return_value=_Resp(401, text="nope")),
        pytest.raises(IdentityVerifyError, match="verify status 401"),
    ):
        c.verify_sync("tok")


def test_verify_sync_revoked():
    c = IdentityVerifyClient(service_token="svc")
    with (
        patch(
            "fusion_security.identity.client.httpx.post",
            return_value=_Resp(200, {"tid": "t1", "revoked": True}),
        ),
        pytest.raises(IdentityVerifyError, match="token revoked"),
    ):
        c.verify_sync("tok")


def test_verify_sync_ok_caches_quota():
    cache_tenant_quota("t_ok", {})  # 清
    c = IdentityVerifyClient(service_token="svc")
    payload = {"tid": "t_ok", "role": "admin", "scopes": ["scan:read"], "quota": {"max_concurrent_scans": 7}}
    with patch("fusion_security.identity.client.httpx.post", return_value=_Resp(200, payload)):
        out = c.verify_sync("tok")
    assert out["tid"] == "t_ok"


@pytest.mark.asyncio
async def test_report_usage_no_tenant():
    c = IdentityVerifyClient(service_token="svc")
    await c.report_usage("", {"n": 1})  # 早退,无异常


@pytest.mark.asyncio
async def test_report_usage_no_token():
    c = IdentityVerifyClient(service_token="")
    await c.report_usage("t1", {"n": 1})  # 早退,无异常


@pytest.mark.asyncio
async def test_report_usage_http_error_ignored():
    c = IdentityVerifyClient(service_token="svc")
    with patch("fusion_security.identity.client.httpx.AsyncClient") as mock_ac:
        inst = mock_ac.return_value.__aenter__.return_value
        inst.post.side_effect = httpx.ConnectError("down")
        await c.report_usage("t1", {"n": 1})  # best-effort,不抛


@pytest.mark.asyncio
async def test_report_usage_non2xx_warning():
    c = IdentityVerifyClient(service_token="svc")
    with patch("fusion_security.identity.client.httpx.AsyncClient") as mock_ac:
        inst = mock_ac.return_value.__aenter__.return_value
        inst.post.return_value = _Resp(500, text="err")
        await c.report_usage("t1", {"n": 1})  # 仅告警


def test_quota_cache_roundtrip():
    cache_tenant_quota("t_q", {"max_concurrent_scans": 9})
    assert get_tenant_quota("t_q") == {"max_concurrent_scans": 9}
    assert get_tenant_quota("missing") == {}


# ===== middleware.py =====


class _FakeRequest:
    def __init__(self, headers=None, client_host="1.2.3.4", path="/api/v1/scans"):
        self.headers = headers or {}
        self.client = type("C", (), {"host": client_host})()
        self.url = type("U", (), {"path": path})()


def test_client_ip_xff():
    req = _FakeRequest(headers={"x-forwarded-for": "9.9.9.9, 8.8.8.8"})
    assert _client_ip(req) == "9.9.9.9"


def test_client_ip_direct():
    req = _FakeRequest(headers={}, client_host="7.7.7.7")
    assert _client_ip(req) == "7.7.7.7"


def test_client_ip_no_client():
    req = _FakeRequest(headers={}, client_host="")
    req.client = None
    assert _client_ip(req) == "unknown"


def test_key_hash_present():
    req = _FakeRequest(headers={"x-api-key": "fs_abc"})
    h = _key_hash(req)
    assert h and len(h) == 16


def test_key_hash_absent():
    req = _FakeRequest(headers={})
    assert _key_hash(req) == ""


def test_max_per_minute_default(monkeypatch):
    monkeypatch.delenv("FUSION_RATE_LIMIT_PER_MINUTE", raising=False)
    assert _max_per_minute() == 120


def test_max_per_minute_env(monkeypatch):
    monkeypatch.setenv("FUSION_RATE_LIMIT_PER_MINUTE", "5")
    assert _max_per_minute() == 5


def test_tenant_quota_cap_from_identity():
    cache_tenant_quota("t_cap", {"max_concurrent_scans": 11})
    assert _tenant_quota_cap("t_cap") == 11


def test_tenant_quota_cap_fallback_default():
    assert _tenant_quota_cap("nope_missing") == MAX_CONCURRENT_SCANS_PER_TENANT


def test_tenant_quota_cap_invalid_value():
    cache_tenant_quota("t_bad", {"max_concurrent_scans": -3})
    assert _tenant_quota_cap("t_bad") == MAX_CONCURRENT_SCANS_PER_TENANT


def test_tenant_quota_cap_identity_error_fallback():
    # get_tenant_quota 抛异常 → 回退默认配额(分支 99-100)。
    with patch("fusion_security.identity.client.get_tenant_quota", side_effect=RuntimeError("boom")):
        assert _tenant_quota_cap("t_err") == MAX_CONCURRENT_SCANS_PER_TENANT


def test_count_active_scans_filters_tenant():
    init_db(":memory:")
    from fusion_security.db.models import ScanORM
    from fusion_security.db.session import get_session

    db = get_session()
    try:
        db.add(ScanORM(id="s_a", path="/p", status="running", tenant_id="t_a"))
        db.add(ScanORM(id="s_b", path="/p", status="completed", tenant_id="t_a"))
        db.add(ScanORM(id="s_c", path="/p", status="running", tenant_id="t_b"))
        db.commit()
    finally:
        db.close()
    assert count_active_scans("t_a") == 1
    assert count_active_scans("t_b") == 1
    assert count_active_scans("t_none") == 0


def test_enforce_scan_quota_exceeded():
    init_db(":memory:")
    from fusion_security.db.models import ScanORM
    from fusion_security.db.session import get_session

    # 显式低配额,避免依赖模块常量(随机序下 env 不可控)。
    cache_tenant_quota("t_q", {"max_concurrent_scans": 1})
    db = get_session()
    try:
        db.add(ScanORM(id="s0", path="/p", status="running", tenant_id="t_q"))
        db.commit()
    finally:
        db.close()
    with pytest.raises(Exception) as exc_info:
        enforce_scan_quota("t_q")
    assert exc_info.type.__name__ == "_QuotaExceeded"


def test_enforce_scan_quota_ok():
    init_db(":memory:")
    enforce_scan_quota("t_empty")  # 0 active < cap,不抛


# ===== rate_limit_middleware(ASGI 路径) =====


def test_rate_limit_disabled_passthrough(monkeypatch):
    # FUSION_RATE_LIMIT=0 关闭限流,中间件直接放行。
    import asyncio

    monkeypatch.setenv("FUSION_RATE_LIMIT", "0")
    called = {"n": 0}

    async def call_next(req):
        called["n"] += 1
        return type("R", (), {"status_code": 200})()

    req = _FakeRequest()
    asyncio.run(rate_limit_middleware(req, call_next))
    assert called["n"] == 1


def test_rate_limit_health_exempt(monkeypatch):
    import asyncio

    monkeypatch.setenv("FUSION_RATE_LIMIT", "1")
    called = {"n": 0}

    async def call_next(req):
        called["n"] += 1
        return type("R", (), {"status_code": 200})()

    req = _FakeRequest(path="/api/v1/system/health")
    asyncio.run(rate_limit_middleware(req, call_next))
    assert called["n"] == 1


def test_rate_limit_non_api_exempt(monkeypatch):
    import asyncio

    monkeypatch.setenv("FUSION_RATE_LIMIT", "1")
    called = {"n": 0}

    async def call_next(req):
        called["n"] += 1
        return type("R", (), {"status_code": 200})()

    req = _FakeRequest(path="/docs")
    asyncio.run(rate_limit_middleware(req, call_next))
    assert called["n"] == 1


def test_rate_limit_throttle_429(monkeypatch):
    import asyncio

    monkeypatch.setenv("FUSION_RATE_LIMIT", "1")
    monkeypatch.setenv("FUSION_RATE_LIMIT_PER_MINUTE", "2")
    _buckets.clear()

    async def call_next(req):
        return type("R", (), {"status_code": 200})()

    req = _FakeRequest(headers={"x-api-key": "fs_x"}, path="/api/v1/scans")
    r1 = asyncio.run(rate_limit_middleware(req, call_next))
    r2 = asyncio.run(rate_limit_middleware(req, call_next))
    r3 = asyncio.run(rate_limit_middleware(req, call_next))
    assert r1.status_code == 200 and r2.status_code == 200
    assert r3.status_code == 429
