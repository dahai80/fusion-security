# Issue #32: local tenant registry retired, auth owned by fusion-identity.
# TenantManager/Tenant are kept as error stubs; instantiating raises RuntimeError so the old local implementation is never silently used.
# AuditLogger/AuditEntry are kept (the audit path is independent and does not rely on TenantManager).
from .audit import AuditEntry, AuditLogger
from .manager import Tenant, TenantManager

__all__ = ["TenantManager", "Tenant", "AuditLogger", "AuditEntry"]
