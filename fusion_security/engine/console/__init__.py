"""Console engine —— Admin Console 聚合层(Issue #60/#61/#62)。

audit_store:审计 jsonl 查询;identity_admin:identity 服务面聚合(可降级);
posture:姿态 checklist;summary:四分区首页聚合。
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
