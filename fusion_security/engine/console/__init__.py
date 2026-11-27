"""Console engine — Admin Console aggregation layer (Issue #60/#61/#62).

audit_store: audit jsonl query; identity_admin: identity service-plane
aggregation (degradable); posture: posture checklist; summary: four-zone
home aggregation.
"""

from .audit_store import AuditStore
from .identity_admin import get_identity_admin_client
from .posture import build_posture_checklist
from .summary import build_console_summary

__all__ = [
    "AuditStore",
    "get_identity_admin_client",
    "build_posture_checklist",
    "build_console_summary",
]
