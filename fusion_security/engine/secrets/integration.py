"""Scan-pipeline / gate wiring for the secrets module (evolution plan P1.2).

Shared entry point used by both scan paths so gate severity counts secrets
findings identically: legacy Scanner (check/gate/sarif) and ScanPipeline
Discover. Findings map onto the shared Vulnerability model with CWE-798.
"""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import uuid4

from ...models import Vulnerability
from .scanner import SecretScanner, finding_to_vulnerability_dict

logger = logging.getLogger(__name__)

_shared_scanner: SecretScanner | None = None


def get_shared_scanner() -> SecretScanner:
    global _shared_scanner
    if _shared_scanner is None:
        _shared_scanner = SecretScanner()
        logger.info("[Secrets] shared SecretScanner initialized (allowlist entries resolved)")
    return _shared_scanner


def secrets_vulnerabilities(file_path: Path, content: str, root: Path) -> list[Vulnerability]:
    try:
        rel = str(file_path.relative_to(root)) if file_path.is_relative_to(root) else str(file_path)
        findings = get_shared_scanner().scan_text(content, rel_path=rel)
        if not findings:
            return []
        logger.info(f"[Secrets] {len(findings)} finding(s) in {rel}")
        return [
            Vulnerability(id=f"V-{uuid4().hex[:8]}", **finding_to_vulnerability_dict(f, str(file_path)))
            for f in findings
        ]
    except Exception as e:
        logger.warning(f"[Secrets] secrets scan failed for {file_path}: {e}")
        return []
