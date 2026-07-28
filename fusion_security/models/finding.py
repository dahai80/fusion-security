from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any


@dataclass
class Finding:
    id: str = ""
    vuln_id: str = ""
    scan_id: str = ""
    file_path: str = ""
    line_number: int = 0
    line_end: int = 0
    code_snippet: str = ""
    context_before: str = ""
    context_after: str = ""
    data_flow_path: str = ""
    confidence: float = 0.0
    created_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"find_{uuid.uuid4().hex[:12]}"
        if not self.created_at:
            from datetime import datetime

            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vuln_id": self.vuln_id,
            "scan_id": self.scan_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet[:500],
            "context_before": self.context_before[:200],
            "context_after": self.context_after[:200],
            "data_flow_path": self.data_flow_path,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }
