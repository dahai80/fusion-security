"""SSRF protection — outbound URL validation for webhooks / notifiers. Rejects non-http(s) schemes and private/loopback/link-local addresses."""

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
    # DNS-rebinding TOCTOU: the public IP resolved during validate may differ from the
    # IP urlopen actually connects to (an attacker can switch to an intranet address
    # between the two getaddrinfo calls). pinned_ips holds the IPs that passed
    # validation; the caller pins resolution to them for the request duration,
    # eliminating the rebinding window.
    pinned_ips: list[str] = None


def _is_forbidden_ip(addr: ipaddress._BaseAddress) -> bool:
    # is_global == False covers private/loopback/link-local/multicast/reserved ranges;
    # public unicast has is_global == True. Additionally reject 0.0.0.0 and the
    # metadata address 169.254.169.254 explicitly (the latter is link-local anyway; belt and braces).
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return True
    if addr.is_unspecified:
        return True
    # is_global == False covers the remaining non-public ranges (private/reserved/link-local, etc.).
    return not addr.is_global


def validate_outbound_url(raw_url: str) -> URLGuardResult:
    if not raw_url or not isinstance(raw_url, str):
        return URLGuardResult(ok=False, reason="URL is empty")

    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return URLGuardResult(ok=False, reason=f"illegal scheme: {parsed.scheme} (only http/https allowed)")

    if not parsed.hostname:
        return URLGuardResult(ok=False, reason="URL is missing a hostname")

    hostname = parsed.hostname
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return URLGuardResult(ok=False, reason=f"DNS resolution failed: {e}")

    resolved_ips: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_forbidden_ip(addr):
            return URLGuardResult(ok=False, reason=f"outbound to target address forbidden: {ip_str} ({hostname})")
        resolved_ips.append(ip_str)

    if not resolved_ips:
        return URLGuardResult(ok=False, reason=f"no usable public IP: {hostname}")

    logger.debug(f"[URLGuard] allowed {hostname} -> {resolved_ips[0]}")
    return URLGuardResult(ok=True, safe_url=raw_url, reason="ok", pinned_ips=resolved_ips)


class _PinnedResolver:
    # DNS pinning: pin hostname resolution to the IPs that passed validation for the
    # request duration, closing the rebinding window. Monkeypatches socket.getaddrinfo
    # so only the target host returns the pinned result; all other hosts use the
    # original resolution (avoiding impact on other requests in the same process).

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
    # Validate in one step and return the pin context manager: with pin_url(url)[1]: urlopen(...).
    result = validate_outbound_url(raw_url)
    if not result.ok:
        return result, None
    parsed = urllib.parse.urlsplit(raw_url)
    hostname = parsed.hostname or ""
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    return result, _PinnedResolver(hostname, result.pinned_ips or [])
