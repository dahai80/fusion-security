"""SSRF 防护 — webhook / notifier 外发 URL 校验。拒绝非 http(s) 协议、私网/环回/链路本地地址。"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.parse
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = {"http", "https"}


@dataclass
class URLGuardResult:
    ok: bool
    reason: str = ""
    safe_url: str = ""


def _is_forbidden_ip(addr: ipaddress._BaseAddress) -> bool:
    # is_global == False 涵盖私网/环回/链路本地/组播/保留段；公网单播 is_global == True。
    # 额外显式拒绝 0.0.0.0 与 metadata 地址 169.254.169.254（后者本属链路本地，双保险）。
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return True
    if addr.is_unspecified:
        return True
    # is_global == False 涵盖其余私网/保留/链路本地等未显式命中的非公网段。
    return not addr.is_global


def validate_outbound_url(raw_url: str) -> URLGuardResult:
    if not raw_url or not isinstance(raw_url, str):
        return URLGuardResult(ok=False, reason="URL 为空")

    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return URLGuardResult(ok=False, reason=f"非法协议: {parsed.scheme} (仅允许 http/https)")

    if not parsed.hostname:
        return URLGuardResult(ok=False, reason="URL 缺少 hostname")

    hostname = parsed.hostname
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return URLGuardResult(ok=False, reason=f"DNS 解析失败: {e}")

    resolved_ips: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_forbidden_ip(addr):
            return URLGuardResult(ok=False, reason=f"目标地址禁止外发: {ip_str} ({hostname})")
        resolved_ips.append(ip_str)

    if not resolved_ips:
        return URLGuardResult(ok=False, reason=f"无可用公网 IP: {hostname}")

    logger.debug(f"[URLGuard] 放行 {hostname} -> {resolved_ips[0]}")
    return URLGuardResult(ok=True, safe_url=raw_url, reason="ok")
