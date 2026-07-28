"""Webhook notifier — send scan results to external services."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


@dataclass
class WebhookConfig:
    url: str = ""
    secret: str = ""
    events: list[str] = field(default_factory=lambda: ["scan.completed", "gate.failed"])
    headers: dict[str, str] = field(default_factory=dict)


class WebhookNotifier:
    def __init__(self, configs: list[WebhookConfig] | None = None):
        self.configs = configs or []
        logger.info(f"[Webhook] 初始化 {len(self.configs)} 个 webhook")

    def add_config(self, config: WebhookConfig) -> None:
        self.configs.append(config)
        logger.info(f"[Webhook] 添加 webhook: {config.url[:50]}")

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
                logger.warning(f"[Webhook] 发送失败 {config.url[:30]}: {e}")
                results.append(False)
        return results

    def _send(self, config: WebhookConfig, event: str, payload: dict[str, Any]) -> bool:
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

        try:
            req = Request(config.url, data=body, headers=headers, method="POST")
            with urlopen(req, timeout=10) as resp:
                logger.info(f"[Webhook] 发送成功 {config.url[:30]} status={resp.status}")
                return 200 <= resp.status < 300
        except URLError as e:
            logger.warning(f"[Webhook] URL错误: {e}")
            return False
        except Exception as e:
            logger.warning(f"[Webhook] 发送异常: {e}")
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
