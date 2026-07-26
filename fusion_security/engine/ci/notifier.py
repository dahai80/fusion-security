from __future__ import annotations

import hashlib
import hmac
import base64
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


@dataclass
class FeishuConfig:
    webhook_url: str = ""
    secret: str = ""
    mention_all: bool = False
    events: List[str] = field(default_factory=lambda: ["scan.completed", "gate.failed"])


@dataclass
class DingTalkConfig:
    webhook_url: str = ""
    secret: str = ""
    mention_all: bool = False
    at_mobiles: List[str] = field(default_factory=list)
    events: List[str] = field(default_factory=lambda: ["scan.completed", "gate.failed"])


def _urllib_post(url: str, data: bytes, headers: Dict[str, str], timeout: int = 10) -> bool:
    try:
        req = Request(url, data=data, headers=headers, method="POST")
        with urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if body.get("code", body.get("errcode", 0)) != 0:
                logger.warning(f"[Notifier] 响应错误: {body}")
                return False
            logger.info(f"[Notifier] 发送成功 status={resp.status}")
            return True
    except URLError as e:
        logger.warning(f"[Notifier] URL错误: {e}")
        return False
    except Exception as e:
        logger.warning(f"[Notifier] 发送异常: {e}")
        return False


class FeishuNotifier:
    def __init__(self, config: FeishuConfig):
        self.config = config

    def _sign_url(self) -> str:
        if not self.config.secret:
            return self.config.webhook_url
        ts = str(int(time.time()))
        string_to_sign = f"{ts}\n{self.config.secret}"
        hmac_code = hmac.new(
            self.config.secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        sep = "&" if "?" in self.config.webhook_url else "?"
        return f"{self.config.webhook_url}{sep}timestamp={ts}&sign={sign}"

    def send(self, event: str, scan_id: str, total: int,
             critical: int, high: int, medium: int, low: int,
             gate_passed: bool = True) -> bool:
        if event not in self.config.events:
            return True

        color = "green" if gate_passed else "red"
        status_text = "通过" if gate_passed else "未通过"
        mention = "<at user_id='all'></at>" if self.config.mention_all else ""

        elements = [
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"**扫描ID:** {scan_id}\n**安全门禁:** {status_text}\n**漏洞总数:** {total}"
                }
            },
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"🔴 Critical: **{critical}**  🟠 High: **{high}**  🟡 Medium: **{medium}**  🟢 Low: **{low}**"
                }
            },
        ]
        if mention:
            elements.append({"tag": "div", "text": {"tag": "lark_md", "content": mention}})

        card = {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text", "content": f"Fusion-Security 扫描报告 - {status_text}"},
                    "template": color,
                },
                "elements": elements,
            },
        }

        url = self._sign_url()
        data = json.dumps(card, ensure_ascii=False).encode("utf-8")
        return _urllib_post(url, data, {"Content-Type": "application/json"})


class DingTalkNotifier:
    def __init__(self, config: DingTalkConfig):
        self.config = config

    def _sign_url(self) -> str:
        if not self.config.secret:
            return self.config.webhook_url
        ts = str(round(time.time() * 1000))
        string_to_sign = f"{ts}\n{self.config.secret}"
        hmac_code = hmac.new(
            self.config.secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        sep = "&" if "?" in self.config.webhook_url else "?"
        return f"{self.config.webhook_url}{sep}timestamp={ts}&sign={sign}"

    def send(self, event: str, scan_id: str, total: int,
             critical: int, high: int, medium: int, low: int,
             gate_passed: bool = True) -> bool:
        if event not in self.config.events:
            return True

        status_text = "通过 ✅" if gate_passed else "未通过 ❌"

        at_dict: Dict[str, Any] = {"isAtAll": self.config.mention_all}
        if self.config.at_mobiles:
            at_dict["atMobiles"] = self.config.at_mobiles

        markdown_body = {
            "msgtype": "markdown",
            "markdown": {
                "title": f"Fusion-Security 扫描报告 - {status_text}",
                "text": (
                    f"### Fusion-Security 扫描报告 - {status_text}\n\n"
                    f"- 扫描ID: {scan_id}\n"
                    f"- 安全门禁: {status_text}\n"
                    f"- 漏洞总数: {total}\n\n"
                    f"#### 严重级别分布\n"
                    f"| 级别 | 数量 |\n|------|------|\n"
                    f"| Critical | {critical} |\n| High | {high} |\n| Medium | {medium} |\n| Low | {low} |\n"
                ),
            },
            "at": at_dict,
        }

        url = self._sign_url()
        data = json.dumps(markdown_body, ensure_ascii=False).encode("utf-8")
        return _urllib_post(url, data, {"Content-Type": "application/json"})


class NotificationDispatcher:
    def __init__(self):
        self.feishu_notifiers: List[FeishuNotifier] = []
        self.dingtalk_notifiers: List[DingTalkNotifier] = []

    def add_feishu(self, config: FeishuConfig) -> None:
        self.feishu_notifiers.append(FeishuNotifier(config))
        logger.info(f"[Notifier] 添加飞书通知: {config.webhook_url[:40]}")

    def add_dingtalk(self, config: DingTalkConfig) -> None:
        self.dingtalk_notifiers.append(DingTalkNotifier(config))
        logger.info(f"[Notifier] 添加钉钉通知: {config.webhook_url[:40]}")

    def notify(self, event: str, scan_id: str, total: int,
               critical: int, high: int, medium: int, low: int,
               gate_passed: bool = True) -> Dict[str, List[bool]]:
        results: Dict[str, List[bool]] = {}
        for n in self.feishu_notifiers:
            ok = n.send(event, scan_id, total, critical, high, medium, low, gate_passed)
            results.setdefault("feishu", []).append(ok)
        for n in self.dingtalk_notifiers:
            ok = n.send(event, scan_id, total, critical, high, medium, low, gate_passed)
            results.setdefault("dingtalk", []).append(ok)
        return results
