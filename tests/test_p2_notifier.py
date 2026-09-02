import json
from unittest.mock import MagicMock, patch

from fusion_security.engine.ci.notifier import (
    DingTalkConfig,
    DingTalkNotifier,
    FeishuConfig,
    FeishuNotifier,
    NotificationDispatcher,
    _urllib_post,
)


class TestFeishuNotifier:
    def test_sign_url_without_secret(self):
        cfg = FeishuConfig(webhook_url="https://hook.example.com/abc")
        n = FeishuNotifier(cfg)
        assert n._sign_url() == "https://hook.example.com/abc"

    def test_sign_url_with_secret(self):
        cfg = FeishuConfig(webhook_url="https://hook.example.com/abc", secret="test_secret")
        n = FeishuNotifier(cfg)
        url = n._sign_url()
        assert "timestamp=" in url
        assert "sign=" in url

    def test_send_skips_non_matching_event(self):
        cfg = FeishuConfig(webhook_url="https://example.com", events=["gate.failed"])
        n = FeishuNotifier(cfg)
        assert n.send("scan.completed", "s1", 1, 0, 0, 0, 0) is True

    @patch("fusion_security.engine.ci.notifier._urllib_post", return_value=True)
    def test_send_success(self, mock_post):
        cfg = FeishuConfig(webhook_url="https://hook.example.com/abc", events=["scan.completed"])
        n = FeishuNotifier(cfg)
        result = n.send("scan.completed", "s1", 5, 1, 2, 1, 1, gate_passed=True)
        assert result is True
        body = json.loads(mock_post.call_args[0][1].decode("utf-8"))
        assert body["msg_type"] == "interactive"
        assert body["card"]["header"]["template"] == "green"

    @patch("fusion_security.engine.ci.notifier._urllib_post", return_value=True)
    def test_send_gate_failed_red(self, mock_post):
        cfg = FeishuConfig(webhook_url="https://hook.example.com/abc", events=["gate.failed"])
        n = FeishuNotifier(cfg)
        n.send("gate.failed", "s2", 3, 2, 1, 0, 0, gate_passed=False)
        body = json.loads(mock_post.call_args[0][1].decode("utf-8"))
        assert body["card"]["header"]["template"] == "red"


class TestDingTalkNotifier:
    def test_sign_url_without_secret(self):
        cfg = DingTalkConfig(webhook_url="https://oapi.dingtalk.com/robot/send?access_token=abc")
        n = DingTalkNotifier(cfg)
        assert n._sign_url() == cfg.webhook_url

    def test_sign_url_with_secret(self):
        cfg = DingTalkConfig(webhook_url="https://oapi.dingtalk.com/robot/send?access_token=abc", secret="sec")
        n = DingTalkNotifier(cfg)
        url = n._sign_url()
        assert "timestamp=" in url
        assert "sign=" in url

    def test_send_skips_non_matching_event(self):
        cfg = DingTalkConfig(webhook_url="https://example.com", events=["gate.failed"])
        n = DingTalkNotifier(cfg)
        assert n.send("scan.completed", "s1", 1, 0, 0, 0, 0) is True

    @patch("fusion_security.engine.ci.notifier._urllib_post", return_value=True)
    def test_send_markdown_format(self, mock_post):
        cfg = DingTalkConfig(
            webhook_url="https://oapi.dingtalk.com/robot/send?access_token=x", events=["scan.completed"]
        )
        n = DingTalkNotifier(cfg)
        result = n.send("scan.completed", "s1", 4, 1, 1, 1, 1, gate_passed=True)
        assert result is True
        body = json.loads(mock_post.call_args[0][1].decode("utf-8"))
        assert body["msgtype"] == "markdown"
        assert "Critical" in body["markdown"]["text"]

    @patch("fusion_security.engine.ci.notifier._urllib_post", return_value=True)
    def test_send_mention_all(self, mock_post):
        cfg = DingTalkConfig(webhook_url="https://example.com", mention_all=True)
        n = DingTalkNotifier(cfg)
        n.send("scan.completed", "s1", 0, 0, 0, 0, 0)
        body = json.loads(mock_post.call_args[0][1].decode("utf-8"))
        assert body["at"]["isAtAll"] is True


class TestNotificationDispatcher:
    @patch("fusion_security.engine.ci.notifier._urllib_post", return_value=True)
    def test_dispatch_feishu_and_dingtalk(self, mock_post):
        d = NotificationDispatcher()
        d.add_feishu(FeishuConfig(webhook_url="https://hook.feishu.cn/x"))
        d.add_dingtalk(DingTalkConfig(webhook_url="https://oapi.dingtalk.com/robot/send?access_token=y"))
        results = d.notify("scan.completed", "s1", 2, 1, 1, 0, 0)
        assert results["feishu"] == [True]
        assert results["dingtalk"] == [True]
        assert mock_post.call_count == 2

    def test_dispatch_empty(self):
        d = NotificationDispatcher()
        results = d.notify("scan.completed", "s1", 0, 0, 0, 0, 0)
        assert results == {}


class TestUrllibPost:
    @patch("fusion_security.engine.ci.notifier.build_opener")
    @patch("fusion_security.engine.ci.notifier.pin_url")
    def test_success_response(self, mock_pin, mock_build):
        from fusion_security.engine.ci._url_guard import URLGuardResult

        mock_pin.return_value = (URLGuardResult(ok=True, safe_url="https://example.com"), None)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"code":0}'
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build.return_value = mock_opener
        assert _urllib_post("https://example.com", b"{}", {"Content-Type": "application/json"}) is True

    @patch("fusion_security.engine.ci.notifier.build_opener")
    @patch("fusion_security.engine.ci.notifier.pin_url")
    def test_error_response_code(self, mock_pin, mock_build):
        from fusion_security.engine.ci._url_guard import URLGuardResult

        mock_pin.return_value = (URLGuardResult(ok=True, safe_url="https://example.com"), None)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"errcode":40001}'
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build.return_value = mock_opener
        assert _urllib_post("https://example.com", b"{}", {"Content-Type": "application/json"}) is False

    @patch("fusion_security.engine.ci.notifier.pin_url")
    def test_ssrf_rejected(self, mock_pin):
        from fusion_security.engine.ci._url_guard import URLGuardResult

        mock_pin.return_value = (URLGuardResult(ok=False, reason="目标地址禁止外发"), None)
        assert _urllib_post("http://169.254.169.254/", b"{}", {"Content-Type": "application/json"}) is False
