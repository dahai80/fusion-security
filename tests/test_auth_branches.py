"""Issue #32:auth.py 异常分支 + ensure_master_key 覆盖补齐。

覆盖 validate_key/revoke_key 异常回退、_tenant_context 异常、ensure_master_key 临时 key 路径,
拉高 auth.py 覆盖率至门禁。
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from fusion_security.api.auth import AuthManager, _tenant_context


def _isolated_auth():
    import os
    import tempfile

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from fusion_security.db.session import Base

    d = tempfile.mkdtemp()
    engine = create_engine(
        f"sqlite:///{os.path.join(d, 'auth.db')}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return AuthManager(session_factory=sessionmaker(bind=engine, expire_on_commit=False))


def _raising_session(exc=RuntimeError("db down")):
    # 返回一个 query/commit/rollback/close 均抛异常的伪 session。
    class _Bad:
        def query(self, *a, **k):
            raise exc

        def add(self, *a, **k):
            raise exc

        def commit(self):
            raise exc

        def rollback(self):
            pass

        def close(self):
            pass

    return _Bad()


def test_validate_key_db_exception_returns_none():
    mgr = _isolated_auth()
    mgr._get_session = lambda: _raising_session()
    assert mgr.validate_key("fs_anything") is None


def test_revoke_key_db_exception_returns_false():
    mgr = _isolated_auth()
    mgr._get_session = lambda: _raising_session()
    assert mgr.revoke_key("k") is False


def test_create_api_key_db_exception_reraises():
    mgr = _isolated_auth()
    mgr._get_session = lambda: _raising_session()
    with pytest.raises(RuntimeError):
        mgr.create_api_key("k", ["admin"])


def test_tenant_context_exception_returns_none():
    # fusion_core.tenant.current 抛异常 → 返回 None(230-231)。
    with patch("fusion_core.tenant.current", side_effect=RuntimeError("no ctx")):
        assert _tenant_context() is None


def test_ensure_master_key_temp_path(monkeypatch):
    # 未设 FUSION_SECURITY_MASTER_KEY → 生成临时 key(216-218)。
    monkeypatch.delenv("FUSION_SECURITY_MASTER_KEY", raising=False)
    mgr = _isolated_auth()
    key = mgr.ensure_master_key()
    assert key.startswith("fs_")
