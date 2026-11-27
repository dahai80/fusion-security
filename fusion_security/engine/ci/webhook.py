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
    # Placeholder context for when resolver is None (validation found no pinned_ips); does nothing.
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class _NoRedirectHandler(BaseHandler):
    # P0-2: urllib follows 3xx redirects by default, which bypasses the SSRF check
    # (an attacker can point at the intranet via 302). This handler treats 3xx as
    # terminal and does not follow; the caller validates each Location itself.
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
        logger.info(f"[Webhook] initialized {len(self.configs)} webhooks")

    def add_config(self, config: WebhookConfig) -> None:
        self.configs.append(config)
        logger.info(f"[Webhook] added webhook host={_host_of(config.url)}")

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
                logger.warning(f"[Webhook] send failed host={_host_of(config.url)}: {e}")
                results.append(False)
        return results

    def _send(self, config: WebhookConfig, event: str, payload: dict[str, Any]) -> bool:
        guard, resolver = pin_url(config.url)
        if not guard.ok:
            logger.warning(f"[Webhook] SSRF check rejected host={_host_of(config.url)}: {guard.reason}")
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

        # P0-2: do not follow redirects automatically; validate Location hop-by-hop
        # to prevent a 302 pointing at the intranet from bypassing the SSRF check.
        opener = build_opener(_NoRedirectHandler())
        target_url = guard.safe_url
        active_resolver = resolver
        max_redirects = 3
        for hop in range(max_redirects + 1):
            # DNS pinning: pin resolution to the validated IP for the duration of urlopen,
            # closing the DNS-rebinding TOCTOU window.
            with active_resolver or _NullResolver():
                try:
                    req = Request(target_url, data=body, headers=headers, method="POST")
                    with opener.open(req, timeout=10) as resp:
                        logger.info(f"[Webhook] send succeeded host={_host_of(target_url)} status={resp.status}")
                        return 200 <= resp.status < 300
                except HTTPError as e:
                    if e.code in (301, 302, 307, 308) and hop < max_redirects:
                        loc = e.headers.get("Location") or ""
                        if not loc:
                            logger.warning(f"[Webhook] {e.code} has no Location, giving up host={_host_of(target_url)}")
                            return False
                        # Resolve relative/absolute Location and re-run SSRF + DNS pin validation.
                        loc = urllib.parse.urljoin(target_url, loc)
                        guard2, resolver2 = pin_url(loc)
                        if not guard2.ok:
                            logger.warning(f"[Webhook] redirect target rejected by SSRF check: {loc} ({guard2.reason})")
                            return False
                        logger.info(f"[Webhook] following redirect {e.code} -> {loc} (validated)")
                        target_url = guard2.safe_url
                        active_resolver = resolver2
                        continue
                    logger.warning(f"[Webhook] HTTP error host={_host_of(target_url)}: {e.code} {e.reason}")
                    return False
                except URLError as e:
                    logger.warning(f"[Webhook] URL error host={_host_of(target_url)}: {e}")
                    return False
                except Exception as e:
                    logger.warning(f"[Webhook] send exception host={_host_of(target_url)}: {e}")
                    return False
        logger.warning(f"[Webhook] exceeded max redirects {max_redirects} host={_host_of(config.url)}")
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
