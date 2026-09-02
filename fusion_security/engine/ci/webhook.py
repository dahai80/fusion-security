"""Webhook notifier — send scan results to external services."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import BaseHandler, Request, build_opener

from ._url_guard import pin_url

logger = logging.getLogger(__name__)


class _NullResolver:
    # resolver 为 None(校验未提供 pinned_ips)时的占位上下文,什么都不做。
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class _NoRedirectHandler(BaseHandler):
    # P0-2: urllib 默认跟随 3xx 重定向,绕过 SSRF 校验(攻击者用 302 指向内网)。
    # 该 handler 把 3xx 当作终态返回,不自动跟随;调用方再逐条校验 Location。
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


@dataclass
class WebhookConfig:
    url: str = ""
    secret: str = ""
    events: list[str] = field(default_factory=lambda: ["scan.completed", "gate.failed"])
    headers: dict[str, str] = field(default_factory=dict)


def _host_of(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or "unknown"
    except Exception:
        return "unknown"


class WebhookNotifier:
    def __init__(self, configs: list[WebhookConfig] | None = None):
        self.configs = configs or []
        logger.info(f"[Webhook] 初始化 {len(self.configs)} 个 webhook")

    def add_config(self, config: WebhookConfig) -> None:
        self.configs.append(config)
        logger.info(f"[Webhook] 添加 webhook host={_host_of(config.url)}")

    def notify(self, event: str, payload: dict[str, Any]) -> list[bool]:
        results = []
        for config in self.configs:
            if event not in config.events:
                results.append(True)
                continue
            try:
                success = self._send(config, event, payload)
                results.append(success)
            except Exception as e:
                logger.warning(f"[Webhook] 发送失败 host={_host_of(config.url)}: {e}")
                results.append(False)
        return results

    def _send(self, config: WebhookConfig, event: str, payload: dict[str, Any]) -> bool:
        guard, resolver = pin_url(config.url)
        if not guard.ok:
            logger.warning(f"[Webhook] SSRF 校验拒绝 host={_host_of(config.url)}: {guard.reason}")
            return False

        body = json.dumps(
            {
                "event": event,
                "payload": payload,
            },
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "X-Fusion-Security-Event": event,
        }
        if config.secret:
            signature = hmac.new(config.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Fusion-Security-Signature"] = f"sha256={signature}"
        headers.update(config.headers)

        # P0-2: 不自动跟随重定向,逐跳校验 Location,防止 302 指向内网绕过 SSRF。
        opener = build_opener(_NoRedirectHandler())
        target_url = guard.safe_url
        active_resolver = resolver
        max_redirects = 3
        for hop in range(max_redirects + 1):
            # DNS pinning:urlopen 期间固定为校验通过的 IP,关闭 DNS-rebinding TOCTOU 窗口。
            with active_resolver or _NullResolver():
                try:
                    req = Request(target_url, data=body, headers=headers, method="POST")
                    with opener.open(req, timeout=10) as resp:
                        logger.info(f"[Webhook] 发送成功 host={_host_of(target_url)} status={resp.status}")
                        return 200 <= resp.status < 300
                except HTTPError as e:
                    if e.code in (301, 302, 307, 308) and hop < max_redirects:
                        loc = e.headers.get("Location") or ""
                        if not loc:
                            logger.warning(f"[Webhook] {e.code} 无 Location,放弃 host={_host_of(target_url)}")
                            return False
                        # 解析相对/绝对 Location,重新做 SSRF + DNS pin 校验。
                        loc = urllib.parse.urljoin(target_url, loc)
                        guard2, resolver2 = pin_url(loc)
                        if not guard2.ok:
                            logger.warning(f"[Webhook] 重定向目标被 SSRF 拒绝: {loc} ({guard2.reason})")
                            return False
                        logger.info(f"[Webhook] 跟随重定向 {e.code} -> {loc} (已校验)")
                        target_url = guard2.safe_url
                        active_resolver = resolver2
                        continue
                    logger.warning(f"[Webhook] HTTP错误 host={_host_of(target_url)}: {e.code} {e.reason}")
                    return False
                except URLError as e:
                    logger.warning(f"[Webhook] URL错误 host={_host_of(target_url)}: {e}")
                    return False
                except Exception as e:
                    logger.warning(f"[Webhook] 发送异常 host={_host_of(target_url)}: {e}")
                    return False
        logger.warning(f"[Webhook] 超过最大重定向次数 {max_redirects} host={_host_of(config.url)}")
        return False

    def notify_scan_complete(
        self, scan_id: str, total: int, critical: int, high: int, medium: int, low: int, gate_passed: bool = True
    ) -> list[bool]:
        event = "scan.completed" if gate_passed else "gate.failed"
        return self.notify(
            event,
            {
                "scan_id": scan_id,
                "total_vulnerabilities": total,
                "severity_counts": {"critical": critical, "high": high, "medium": medium, "low": low},
                "gate_passed": gate_passed,
            },
        )
