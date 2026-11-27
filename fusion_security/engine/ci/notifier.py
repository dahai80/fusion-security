from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import BaseHandler, Request, build_opener

from ._url_guard import pin_url

logger = logging.getLogger(__name__)


class _NullResolver:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class _NoRedirectHandler(BaseHandler):
    # P0-2: block automatic 3xx following, validate Location hop-by-hop to prevent redirect-based SSRF bypass.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_301(self, req, fp, code, msg, headers):
        return None

    def http_error_302(self, req, fp, code, msg, headers):
        return None

    def http_error_307(self, req, fp, code, msg, headers):
        return None

    def http_error_308(self, req, fp, code, msg, headers):
        return None


def _host_of(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or "unknown"
    except Exception:
        return "unknown"


@dataclass
class FeishuConfig:
    webhook_url: str = ""
    secret: str = ""
    mention_all: bool = False
    events: list[str] = field(default_factory=lambda: ["scan.completed", "gate.failed"])


@dataclass
class DingTalkConfig:
    webhook_url: str = ""
    secret: str = ""
    mention_all: bool = False
    at_mobiles: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=lambda: ["scan.completed", "gate.failed"])


def _urllib_post(url: str, data: bytes, headers: dict[str, str], timeout: int = 10) -> bool:
    guard, resolver = pin_url(url)
    if not guard.ok:
        logger.warning(f"[Notifier] SSRF check rejected host={_host_of(url)}: {guard.reason}")
        return False
    opener = build_opener(_NoRedirectHandler())
    target_url = guard.safe_url
    active_resolver = resolver
    max_redirects = 3
    for hop in range(max_redirects + 1):
        with active_resolver or _NullResolver():
            try:
                req = Request(target_url, data=data, headers=headers, method="POST")
                with opener.open(req, timeout=timeout) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    if body.get("code", body.get("errcode", 0)) != 0:
                        logger.warning(f"[Notifier] response error host={_host_of(target_url)}: {body}")
                        return False
                    logger.info(f"[Notifier] send succeeded host={_host_of(target_url)} status={resp.status}")
                    return True
            except HTTPError as e:
                if e.code in (301, 302, 307, 308) and hop < max_redirects:
                    loc = e.headers.get("Location") or ""
                    if not loc:
                        logger.warning(f"[Notifier] {e.code} has no Location, giving up host={_host_of(target_url)}")
                        return False
                    loc = urllib.parse.urljoin(target_url, loc)
                    guard2, resolver2 = pin_url(loc)
                    if not guard2.ok:
                        logger.warning(f"[Notifier] redirect target rejected by SSRF check: {loc} ({guard2.reason})")
                        return False
                    logger.info(f"[Notifier] following redirect {e.code} -> {loc} (validated)")
                    target_url = guard2.safe_url
                    active_resolver = resolver2
                    continue
                logger.warning(f"[Notifier] HTTP error host={_host_of(target_url)}: {e.code} {e.reason}")
                return False
            except URLError as e:
                logger.warning(f"[Notifier] URL error host={_host_of(target_url)}: {e}")
                return False
            except Exception as e:
                logger.warning(f"[Notifier] send exception host={_host_of(target_url)}: {e}")
                return False
    logger.warning(f"[Notifier] exceeded max redirects {max_redirects} host={_host_of(url)}")
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

    def send(
        self,
        event: str,
        scan_id: str,
        total: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        gate_passed: bool = True,
    ) -> bool:
        if event not in self.config.events:
            return True

        color = "green" if gate_passed else "red"
        # i18n: user-facing
        status_text = "通过" if gate_passed else "未通过"
        mention = "<at user_id='all'></at>" if self.config.mention_all else ""

        elements = [
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    # i18n: user-facing
                    "content": f"**扫描ID:** {scan_id}\n**安全门禁:** {status_text}\n**漏洞总数:** {total}",
                },
            },
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"🔴 Critical: **{critical}**  🟠 High: **{high}**  🟡 Medium: **{medium}**  🟢 Low: **{low}**",
                },
            },
        ]
        if mention:
            elements.append({"tag": "div", "text": {"tag": "lark_md", "content": mention}})

        card = {
            "msg_type": "interactive",
            "card": {
                "header": {
                    # i18n: user-facing
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

    def send(
        self,
        event: str,
        scan_id: str,
        total: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        gate_passed: bool = True,
    ) -> bool:
        if event not in self.config.events:
            return True

        # i18n: user-facing
        status_text = "通过 ✅" if gate_passed else "未通过 ❌"

        at_dict: dict[str, Any] = {"isAtAll": self.config.mention_all}
        if self.config.at_mobiles:
            at_dict["atMobiles"] = self.config.at_mobiles

        markdown_body = {
            "msgtype": "markdown",
            "markdown": {
                # i18n: user-facing
                "title": f"Fusion-Security 扫描报告 - {status_text}",
                # i18n: user-facing
                "text": (
                    f"### Fusion-Security 扫描报告 - {status_text}\n\n"  # i18n: user-facing
                    f"- 扫描ID: {scan_id}\n"  # i18n: user-facing
                    f"- 安全门禁: {status_text}\n"  # i18n: user-facing
                    f"- 漏洞总数: {total}\n\n"  # i18n: user-facing
                    f"#### 严重级别分布\n"  # i18n: user-facing
                    f"| 级别 | 数量 |\n|------|------|\n"  # i18n: user-facing
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
        self.feishu_notifiers: list[FeishuNotifier] = []
        self.dingtalk_notifiers: list[DingTalkNotifier] = []

    def add_feishu(self, config: FeishuConfig) -> None:
        self.feishu_notifiers.append(FeishuNotifier(config))
        logger.info(f"[Notifier] added Feishu notifier host={_host_of(config.webhook_url)}")

    def add_dingtalk(self, config: DingTalkConfig) -> None:
        self.dingtalk_notifiers.append(DingTalkNotifier(config))
        logger.info(f"[Notifier] added DingTalk notifier host={_host_of(config.webhook_url)}")

    def notify(
        self,
        event: str,
        scan_id: str,
        total: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        gate_passed: bool = True,
    ) -> dict[str, list[bool]]:
        results: dict[str, list[bool]] = {}
        for n in self.feishu_notifiers:
            ok = n.send(event, scan_id, total, critical, high, medium, low, gate_passed)
            results.setdefault("feishu", []).append(ok)
        for n in self.dingtalk_notifiers:
            ok = n.send(event, scan_id, total, critical, high, medium, low, gate_passed)
            results.setdefault("dingtalk", []).append(ok)
        return results
