"""Secrets detection module (evolution plan P1.2).

Standalone upgrade over the SAST secret regexes: Shannon-entropy analysis,
offline provider validators, allowlist (path + content hash) and git history
scan. Kept backward compatible with SEC001/SEC002 in engine/rules/engine.py,
which are now flagged deprecated but still emitted for existing consumers.
"""

from .history import scan_history
from .integration import get_shared_scanner, secrets_vulnerabilities
from .scanner import ALLOWLIST_ENV, DEFAULT_ALLOWLIST_PATH, SecretFinding, SecretScanner

__all__ = [
    "ALLOWLIST_ENV",
    "DEFAULT_ALLOWLIST_PATH",
    "SecretFinding",
    "SecretScanner",
    "get_shared_scanner",
    "scan_history",
    "secrets_vulnerabilities",
]
