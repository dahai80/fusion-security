"""Local tenant registry retired - tenant/JWT auth is owned by fusion-identity (Issue #32).

Empty shells are kept only for backward-compatible imports; instantiation or calls always raise
explicitly instead of silently falling back to the old local implementation. Real tenant data is
managed centrally by fusion-identity; this service enforces fail-closed tenant isolation through
TenantMiddleware + get_principal, and no longer mints tenant keys or persists tenants.json locally.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class TenantManager:
    # Issue #32: retired. Tenant registration/auth/quota owned by fusion-identity.
    def __init__(self, *args, **kwargs):
        raise RuntimeError(
            "TenantManager is retired (Issue #32); tenant auth is provided by fusion-identity."
            " API auth uses X-API-Key + X-Tenant-Id (via get_principal / TenantMiddleware fail-closed)."
        )


class Tenant:
    # Issue #32: retired. Kept only for name compatibility with old imports; instantiation raises.
    def __init__(self, *args, **kwargs):
        raise RuntimeError("Tenant is retired (Issue #32); the tenant model is managed by fusion-identity.")
