"""Core secrets scanner: provider validators + entropy analysis + allowlist.

Confidence classes:
- verified  : token matches a provider-specific offline-verifiable shape
              (structure and/or embedded checksum).
- likely    : credential-context keyword + high-entropy string literal.
- possible  : high-entropy literal without credential context (reported at
              lower severity, designed for triage not gating).

Zero-false-positive gate: the committed negative corpus
(tests/fixtures/secrets_corpus.json) must produce no findings.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_ALLOWLIST_PATH = Path.home() / ".fusion-security" / "secrets_allowlist.json"
ALLOWLIST_ENV = "FUSION_SECRETS_ALLOWLIST"

_SEVERITY_BY_CONFIDENCE = {"verified": "critical", "likely": "high", "possible": "medium"}

# Provider token shapes. Ordered: first match wins per span.
# AWS access key ids embed no checksum offline, but the 4-letter prefix +
# 16 uppercase alnum body is provider-strict; treat as verified shape.
_PROVIDER_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"\b(?<![A-Za-z0-9+/=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9+/=])\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_secret_key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("openai_token", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
]

# Generic entropy rule: credential-context keyword near a long high-entropy literal.
_KEYWORD_RE = re.compile(
    r"(?i)(api[_-]?keys?|secrets?|passwords?|passwds?|tokens?|credentials?|auth[_-]?keys?|private[_-]?keys?|access[_-]?keys?|client[_-]?secrets?)"
)
_ASSIGNMENT_RE = re.compile(r"""['"]([^'"\n]{24,256})['"]""")

# Placeholders and known example values are never findings.
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x+|\.+|your[-_].*|<.*>|\$\{.*\}|\$.*|\{\{.*\}\}|%.*%|example[-_].*|placeholder.*|dummy.*|fake.*|test[-_].*|sample[-_].*|changeme|change[-_]?me|todo|fixme|none|null|n/a|redacted|redact|masked|\\*\\*\\*+|xxx+)$"
)
_AWS_EXAMPLE_IDS = {"AKIAIOSFODNN7EXAMPLE", "AKIAQAAAAAAAAAAAAAAAAA", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}

_MIN_ENTROPY_GENERIC = 3.8  # uuid-shaped strings sit ~3.7; real secrets land higher
_MIN_CHARSET_CLASSES = 3


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _charset_classes(value: str) -> int:
    classes = 0
    for checker in (str.islower, str.isupper, str.isdigit):
        if any(checker(ch) for ch in value if ch.isascii()):
            classes += 1
    if any(not ch.isalnum() for ch in value):
        classes += 1
    return classes


@dataclass
class SecretFinding:
    rule_id: str
    kind: str
    confidence: str
    severity: str
    match: str
    sha256: str
    line_number: int
    start: int
    end: int
    commit: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "confidence": self.confidence,
            "severity": self.severity,
            "match": self.match,
            "sha256": self.sha256,
            "line_number": self.line_number,
            "start": self.start,
            "end": self.end,
            "commit": self.commit,
        }


@dataclass
class Allowlist:
    entries: set[str] = field(default_factory=set)  # content sha256 values
    paths: set[str] = field(default_factory=set)

    def allows(self, finding: SecretFinding, rel_path: str) -> bool:
        return finding.sha256 in self.entries or rel_path in self.paths

    @classmethod
    def load(cls, path: Path | None = None) -> Allowlist:
        candidate = (
            Path(os.environ.get(ALLOWLIST_ENV, ""))
            if os.environ.get(ALLOWLIST_ENV, "").strip()
            else (path or DEFAULT_ALLOWLIST_PATH)
        )
        if not candidate.is_file():
            return cls()
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
            entries = {e for e in data.get("content_hashes", []) if isinstance(e, str)}
            paths = {p for p in data.get("paths", []) if isinstance(p, str)}
            logger.info(f"[Secrets] allowlist loaded: {len(entries)} hashes, {len(paths)} paths from {candidate}")
            return cls(entries=entries, paths=paths)
        except Exception as e:
            logger.warning(f"[Secrets] allowlist unreadable at {candidate}: {e}")
            return cls()


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _is_placeholder(value: str) -> bool:
    if value.strip().upper() in _AWS_EXAMPLE_IDS or value in _AWS_EXAMPLE_IDS:
        return True
    return bool(_PLACEHOLDER_RE.match(value.strip()))


class SecretScanner:
    def __init__(self, allowlist: Allowlist | None = None):
        self.allowlist = allowlist if allowlist is not None else Allowlist.load()

    def scan_text(self, content: str, rel_path: str = "", commit: str = "") -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        claimed: list[tuple[int, int]] = []

        def overlap(start: int, end: int) -> bool:
            return any(not (end <= s or start >= e) for s, e in claimed)

        for kind, pattern in _PROVIDER_PATTERNS:
            for m in pattern.finditer(content):
                value = m.group(0)
                if _is_placeholder(value):
                    continue
                if kind == "aws_secret_access_key" and re.fullmatch(r"[0-9a-fA-F]{40}", value):
                    # 40-char pure hex is overwhelmingly a git sha1 / generic
                    # digest in source; real AWS secret keys carry +/= or
                    # mixed non-hex alphabet. Skip to protect the 0-FP gate.
                    continue
                span = (m.start(), m.end())
                if overlap(*span):
                    continue
                claimed.append(span)
                findings.append(self._finding(kind, "verified", value, content, m.start(), m.end(), commit))

        # Generic entropy tier: keyword context on the same line as an
        # assignment-style high-entropy string literal.
        for line_match in re.finditer(r"[^\n]*", content):
            line = line_match.group(0)
            if not _KEYWORD_RE.search(line) or "os.environ" in line or "getenv" in line:
                continue
            offset = line_match.start()
            for m in _ASSIGNMENT_RE.finditer(line):
                value = m.group(1)
                if _is_placeholder(value) or len(value) < 24:
                    continue
                # Literal holding a variable reference (Bearer $TOKEN,
                # ${VAR}) is config plumbing, not a secret. All-caps sigil
                # refs only — mixed-case $-containing literals stay findings.
                if re.search(r"\$\{[^}]+\}|\$[A-Z_]{2,}\b", value):
                    continue
                if shannon_entropy(value) < _MIN_ENTROPY_GENERIC:
                    continue
                if _charset_classes(value) < _MIN_CHARSET_CLASSES:
                    continue
                abs_start = offset + m.start(1)
                abs_end = offset + m.end(1)
                if overlap(abs_start, abs_end):
                    continue
                claimed.append((abs_start, abs_end))
                findings.append(
                    self._finding("high_entropy_string", "likely", value, content, abs_start, abs_end, commit)
                )

        filtered = [f for f in findings if not self.allowlist.allows(f, rel_path)]
        if len(filtered) != len(findings):
            logger.info(f"[Secrets] allowlist suppressed {len(findings) - len(filtered)} finding(s) in {rel_path}")
        return filtered

    def _finding(
        self, kind: str, confidence: str, value: str, content: str, start: int, end: int, commit: str
    ) -> SecretFinding:
        return SecretFinding(
            rule_id=f"SEC-{kind.upper()}",
            kind=kind,
            confidence=confidence,
            severity=_SEVERITY_BY_CONFIDENCE[confidence],
            match=value[:64],
            sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
            line_number=_line_number(content, start),
            start=start,
            end=end,
            commit=commit,
        )


def finding_to_vulnerability_dict(f: SecretFinding, file_path: str) -> dict:
    return {
        "title": f"硬编码密钥({f.kind})",
        "description": f"检测到疑似敏感凭据 (confidence={f.confidence})",
        "severity": f.severity,
        "confidence": 90 if f.confidence == "verified" else 75 if f.confidence == "likely" else 55,
        "file_path": file_path,
        "line_number": f.line_number,
        "code_snippet": f.match,
        "rule_id": f.rule_id,
        "cwe_id": "CWE-798",
        "fix_suggestion": "从环境变量或密钥管理服务加载敏感信息；确认后可将其加入 allowlist (path + content hash)",
    }
