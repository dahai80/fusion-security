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
    # DNS-rebinding TOCTOU: validate 时解析的公网 IP 与 urlopen 实际连接的 IP 可能不同
    # (攻击者在两次 getaddrinfo 之间切换到内网地址)。pinned_ips 保存校验通过的 IP,
    # 调用方据此在请求期间 pin 住解析结果,杜绝重绑定窗口。
    pinned_ips: list[str] = None


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
    return URLGuardResult(ok=True, safe_url=raw_url, reason="ok", pinned_ips=resolved_ips)


class _PinnedResolver:
    # DNS pinning:请求期间把 hostname 解析固定为校验时通过的 IP,关闭重绑定窗口。
    # 通过 monkeypatch socket.getaddrinfo,仅命中目标 host 时返回 pinned 结果,
    # 其余 host 走原解析(避免影响同进程其他请求)。

    def __init__(self, hostname: str, pinned_ips: list[str]):
        self._hostname = hostname
        self._pinned = pinned_ips or []
        self._orig = socket.getaddrinfo

    def __enter__(self):
        if not self._pinned:
            return self
        host = self._hostname
        pinned = self._pinned

        def _patched(host_arg, port, *args, **kwargs):
            if host_arg == host:
                results = []
                for ip in pinned:
                    try:
                        results.append(
                            (
                                socket.AF_INET if ":" not in ip else socket.AF_INET6,
                                socket.SOCK_STREAM,
                                0,
                                "",
                                (ip, port or 0),
                            )
                        )
                    except OSError:
                        continue
                if results:
                    return results
            return self._orig(host_arg, port, *args, **kwargs)

        socket.getaddrinfo = _patched
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        socket.getaddrinfo = self._orig
        return False


def pin_url(raw_url: str) -> tuple[URLGuardResult, _PinnedResolver | None]:
    # 一步校验 + 返回 pin 上下文管理器:with pin_url(url)[1]: urlopen(...)。
    result = validate_outbound_url(raw_url)
    if not result.ok:
        return result, None
    parsed = urllib.parse.urlsplit(raw_url)
    hostname = parsed.hostname or ""
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    return result, _PinnedResolver(hostname, result.pinned_ips or [])
