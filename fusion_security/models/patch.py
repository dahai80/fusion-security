from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any


@dataclass
class Patch:
    id: str = ""
    vuln_id: str = ""
    scan_id: str = ""
    diff_content: str = ""
    original_code: str = ""
    patched_code: str = ""
    description: str = ""
    status: str = "draft"  # draft | applied | verified | rejected
    strategy: str = "template"  # template | ai_generated | hybrid
    verified: bool = False
    created_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"patch_{uuid.uuid4().hex[:12]}"
        if not self.created_at:
            from datetime import datetime

            self.created_at = datetime.now().isoformat()

    def to_diff(self) -> str:
        lines = [
            f"--- a/{self.vuln_id}",
            f"+++ b/{self.vuln_id}",
        ]
        for line in self.original_code.split("\n"):
            lines.append(f"-{line}")
        for line in self.patched_code.split("\n"):
            lines.append(f"+{line}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vuln_id": self.vuln_id,
            "scan_id": self.scan_id,
            "diff_content": self.diff_content,
            "description": self.description,
            "status": self.status,
            "strategy": self.strategy,
            "verified": self.verified,
            "created_at": self.created_at,
        }
