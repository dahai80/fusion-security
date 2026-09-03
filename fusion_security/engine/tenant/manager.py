"""本地租户注册已退役 —— 租户/JWT 鉴权归 fusion-identity(Issue #32)。

保留空壳仅为向后兼容导入;实例化或调用一律显式报错,避免静默回退到旧本地实现。
真实租户数据由 fusion-identity 统一管理,本服务通过 TenantMiddleware + get_principal
做 fail-closed 租户隔离,不再本地 mint tenant key 或持久化 tenants.json。
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class TenantManager:
    # Issue #32: 已退役。租户注册/鉴权/配额归 fusion-identity。
    def __init__(self, *args, **kwargs):
        raise RuntimeError(
            "TenantManager 已退役(Issue #32),租户鉴权由 fusion-identity 提供。"
            " API 鉴权走 X-API-Key + X-Tenant-Id(经 get_principal / TenantMiddleware fail-closed)。"
        )


class Tenant:
    # Issue #32: 已退役。仅保留名字兼容旧导入,实例化即报错。
    def __init__(self, *args, **kwargs):
        raise RuntimeError("Tenant 已退役(Issue #32),租户模型由 fusion-identity 管理。")
