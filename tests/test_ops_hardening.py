# Issue #49 / #50 回归:进程标题 + webhook 密钥无默认字面量。

import logging
import sys

import pytest

from fusion_security.api.app import set_process_title
from fusion_security.engine.ci import _crypto


@pytest.fixture
def clean_key_env(monkeypatch):
    monkeypatch.delenv(_crypto._MASTER_ENV, raising=False)
    monkeypatch.delenv("FUSION_PROFILE", raising=False)
    monkeypatch.setattr(_crypto, "_DEV_SEED", None)
    yield


class TestWebhookCryptoKey:
    def test_prod_missing_key_raises(self, clean_key_env, monkeypatch):
        monkeypatch.setenv("FUSION_PROFILE", "prod")
        with pytest.raises(RuntimeError, match=_crypto._MASTER_ENV):
            _crypto.encrypt_secret("s")
        with pytest.raises(RuntimeError, match="config-conventions"):
            _crypto.decrypt_secret("tok")

    def test_prod_with_key_roundtrip(self, clean_key_env, monkeypatch):
        monkeypatch.setenv("FUSION_PROFILE", "prod")
        monkeypatch.setenv(_crypto._MASTER_ENV, "unit-test-master-key")
        token = _crypto.encrypt_secret("webhook-secret")
        assert token and token != "webhook-secret"
        assert _crypto.decrypt_secret(token) == "webhook-secret"

    def test_dev_missing_key_warns_and_uses_random_seed(self, clean_key_env, caplog):
        with caplog.at_level(logging.WARNING):
            token = _crypto.encrypt_secret("webhook-secret")
        assert any(_crypto._MASTER_ENV in r.message for r in caplog.records)
        # 进程级随机 seed:同进程内可解密,但密文不再对应任何已知常量派生的 key。
        assert _crypto._DEV_SEED is not None
        assert _crypto._DEV_SEED != "fusion-security-webhook-default-key"
        assert _crypto.decrypt_secret(token) == "webhook-secret"

    def test_dev_seed_stable_within_process(self, clean_key_env):
        first = _crypto._dev_seed()
        assert _crypto._dev_seed() == first

    def test_no_fallback_literal_in_source(self):
        # 守卫:默认字面量不得回潮(check-env.py 的镜像断言)。
        import inspect

        src = inspect.getsource(_crypto)
        assert "fusion-security-webhook-default-key" not in src


class TestProcessTitle:
    def test_sets_title_with_port(self, monkeypatch):
        setproctitle = pytest.importorskip("setproctitle")
        calls = []
        monkeypatch.setattr(setproctitle, "setproctitle", lambda t: calls.append(t))
        monkeypatch.setenv("FUSION_SECURITY_PORT", "12345")
        set_process_title()
        assert calls == ["fusion-security serve :12345"]

    def test_default_port_11454(self, monkeypatch):
        setproctitle = pytest.importorskip("setproctitle")
        calls = []
        monkeypatch.setattr(setproctitle, "setproctitle", lambda t: calls.append(t))
        monkeypatch.delenv("FUSION_SECURITY_PORT", raising=False)
        set_process_title()
        assert calls == ["fusion-security serve :11454"]

    def test_missing_setproctitle_no_raise(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "setproctitle", None)
        monkeypatch.delenv("FUSION_SECURITY_PORT", raising=False)
        set_process_title()  # 静默降级,不抛异常
