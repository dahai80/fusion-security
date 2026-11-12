"""Git history secrets scan: walk added lines across commits via `git log -p`.

Reuses the working-tree SecretScanner on each added hunk line; findings carry
the introducing commit. Incremental mode limits the walk to commits touching
files changed between a base ref and HEAD (same diff source as incremental
scans).
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import SecretFinding, SecretScanner

logger = logging.getLogger(__name__)

_MAX_HISTORY_COMMITS = 2000


@dataclass
class HistoryScanResult:
    commits_scanned: int = 0
    findings: list[SecretFinding] = field(default_factory=list)


def _run_git(repo: str, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def scan_history(
    repo_path: str, base: str = "", head: str = "HEAD", max_commits: int = _MAX_HISTORY_COMMITS
) -> HistoryScanResult:
    root = Path(repo_path).resolve()
    if not (root / ".git").exists():
        raise ValueError(f"not a git repository: {root}")

    rev_range = f"{base}..{head}" if base else head
    log_text = _run_git(str(root), "log", "-p", "-U0", "--no-color", f"-{max_commits}", rev_range)

    scanner = SecretScanner()
    result = HistoryScanResult()
    current_commit = ""
    current_file = ""

    for line in log_text.split("\n"):
        if line.startswith("commit "):
            current_commit = line.split(" ", 1)[1].strip()
            result.commits_scanned += 1
            current_file = ""
        elif line.startswith("+++ b/"):
            current_file = line[len("+++ b/") :].strip()
        elif line.startswith("+") and not line.startswith("+++"):
            added = line[1:]
            if len(added) < 20:
                continue
            for finding in scanner.scan_text(added, rel_path=current_file, commit=current_commit):
                finding.line_number = 0  # per-hunk line numbers not tracked across -U0 output
                result.findings.append(finding)

    logger.info(f"[Secrets] history scan done: commits={result.commits_scanned} findings={len(result.findings)}")
    return result
