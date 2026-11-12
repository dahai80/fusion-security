"""Local signature library for known-malicious agent-asset patterns.

Offline update path (no default egress): point FUSION_AGENT_SIGNATURES at a
bundle file or pass --signatures on the CLI; the bundle replaces (not
merges) the shipped defaults so revocation is explicit and auditable.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

BUNDLED_SIGNATURES = Path(__file__).parent / "signatures.json"
SIGNATURES_ENV = "FUSION_AGENT_SIGNATURES"


@dataclass
class SignatureLibrary:
    version: int = 1
    updated: str = ""
    package_indicators: list[str] = field(default_factory=list)
    domain_indicators: list[str] = field(default_factory=list)
    command_indicators: list[str] = field(default_factory=list)
    source: str = "bundled"

    def match_package(self, text: str) -> list[str]:
        return [p for p in self.package_indicators if p and p in text]

    def match_domain(self, url: str) -> list[str]:
        return [d for d in self.domain_indicators if d and d in url]

    def match_command(self, text: str) -> list[str]:
        return [c for c in self.command_indicators if c and c in text]

    @classmethod
    def load(cls, override_path: str | Path | None = None) -> SignatureLibrary:
        candidate: Path | None = None
        if override_path:
            candidate = Path(override_path)
        elif os.environ.get(SIGNATURES_ENV, "").strip():
            candidate = Path(os.environ[SIGNATURES_ENV].strip())
        source = candidate if candidate else BUNDLED_SIGNATURES
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            lib = cls(
                version=int(data.get("version", 1)),
                updated=str(data.get("updated", "")),
                package_indicators=[str(p) for p in data.get("package_indicators", [])],
                domain_indicators=[str(d) for d in data.get("domain_indicators", [])],
                command_indicators=[str(c) for c in data.get("command_indicators", [])],
                source=str(source),
            )
            logger.info(
                f"[Assets] signature library loaded: v{lib.version} "
                f"({len(lib.package_indicators)} pkg / {len(lib.domain_indicators)} domain / "
                f"{len(lib.command_indicators)} cmd) from {lib.source}"
            )
            return lib
        except Exception as e:
            logger.warning(f"[Assets] signature library unreadable at {source}: {e}; using empty library")
            return cls(source=str(source))
