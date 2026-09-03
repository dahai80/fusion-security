# Issue #32: 本地租户注册已退役,鉴权归 fusion-identity。
# TenantManager/Tenant 保留为报错桩,实例化即 RuntimeError,避免静默回退旧实现。
# AuditLogger/AuditEntry 仍保留(审计路径独立,不依赖 TenantManager)。
from .audit import AuditEntry, AuditLogger
from .manager import Tenant, TenantManager

__all__ = ["TenantManager", "Tenant", "AuditLogger", "AuditEntry"]
