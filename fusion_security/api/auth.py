"""API authentication — API key + RBAC, DB-backed hashed key store."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field, replace
from datetime import datetime

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

MASTER_KEY_ENV = "FUSION_SECURITY_MASTER_KEY"


@dataclass
class APIKey:
    key_hash: str
    name: str = ""
    roles: list[str] = field(default_factory=lambda: ["viewer"])
    tenant_id: str = ""
    created_at: float = 0.0
    expires_at: float = 0.0
    key_id: str = ""

    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at


@dataclass
class Role:
    name: str
    permissions: set[str] = field(default_factory=set)


ROLES: dict[str, Role] = {
    "admin": Role(
        "admin",
        {
            "scan:run",
            "scan:read",
            "project:manage",
            "vuln:read",
            "vuln:manage",
            "rule:manage",
            "system:manage",
            "api_key:manage",
        },
    ),
    "operator": Role("operator", {"scan:run", "scan:read", "project:manage", "vuln:read", "vuln:manage"}),
    "viewer": Role("viewer", {"scan:read", "vuln:read"}),
}


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


class AuthManager:
    # P0-4/S-P0-3: keys are persisted to the DB, only sha256 hashes stored; the master key is stable via FUSION_SECURITY_MASTER_KEY, never logged in plaintext.
    def __init__(self, session_factory=None):
        self._master_key = ""
        # Tests can inject an isolated session factory; production uses the global get_session.
        self._session_factory = session_factory

    def _get_session(self):
        if self._session_factory is not None:
            return self._session_factory()
        from ..db.session import get_session

        return get_session()

    def create_api_key(self, name: str, roles: list[str] = None, expires_in: int = 0, tenant_id: str = "") -> str:
        raw_key = f"fs_{secrets.token_hex(24)}"
        self.create_api_key_from_raw(name, raw_key, roles, expires_in, tenant_id)
        return raw_key

    def create_api_key_from_raw(
        self, name: str, raw_key: str, roles: list[str] = None, expires_in: int = 0, tenant_id: str = ""
    ) -> None:
        from datetime import timedelta

        from ..db.models import ApiKeyORM

        role_list = roles or ["viewer"]
        key_hash = _hash_key(raw_key)
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in) if expires_in > 0 else None
        db = self._get_session()
        try:
            existing = db.query(ApiKeyORM).filter(ApiKeyORM.key_hash == key_hash).first()
            if existing:
                existing.name = name
                existing.role = role_list[0]
                existing.tenant_id = tenant_id
                existing.enabled = True
                existing.expires_at = expires_at
            else:
                row = ApiKeyORM(
                    key_hash=key_hash,
                    name=name,
                    role=role_list[0],
                    tenant_id=tenant_id,
                    enabled=True,
                    expires_at=expires_at,
                )
                db.add(row)
            db.commit()
            logger.info(f"[Auth] API Key created: name={name} role={role_list[0]} tenant={tenant_id}")
        except Exception as e:
            db.rollback()
            logger.error(f"[Auth] API Key creation failed: {e}")
            raise
        finally:
            db.close()

    def validate_key(self, raw_key: str) -> APIKey | None:
        if not raw_key:
            return None
        from ..db.models import ApiKeyORM

        key_hash = _hash_key(raw_key)
        db = self._get_session()
        try:
            row = db.query(ApiKeyORM).filter(ApiKeyORM.key_hash == key_hash, ApiKeyORM.enabled.is_(True)).first()
            if not row:
                return None
            # P2-1: a compare_digest after the DB equality filter already matched would be dead code
            # (filter match implies equality). Cross-DB equality filtering cannot do constant-time
            # comparison; security here relies on the key_hash unique index + enabled filter.
            expires_ts = row.expires_at.timestamp() if row.expires_at else 0.0
            # row.expires_at is naive UTC (written via utcnow); compare with utcnow to avoid timezone-offset misjudgment of expiry.
            now_ts = datetime.utcnow().timestamp()
            if expires_ts > 0 and now_ts > expires_ts:
                logger.warning(f"[Auth] API Key expired: {row.name}")
                return None
            row.last_used_at = datetime.utcnow()
            db.commit()
            # Restore the DB single role into a roles list (RBAC uses a list).
            return APIKey(
                key_hash=row.key_hash,
                name=row.name,
                roles=[row.role] if row.role else ["viewer"],
                tenant_id=row.tenant_id or "",
                created_at=row.created_at.timestamp() if row.created_at else 0.0,
                expires_at=expires_ts,
                key_id=row.id,
            )
        except Exception as e:
            db.rollback()
            logger.warning(f"[Auth] API Key validation error: {e}")
            return None
        finally:
            db.close()

    def has_permission(self, api_key: APIKey, permission: str) -> bool:
        for role_name in api_key.roles:
            role = ROLES.get(role_name)
            if role and permission in role.permissions:
                return True
        return False

    def revoke_key(self, name: str) -> bool:
        from ..db.models import ApiKeyORM

        db = self._get_session()
        try:
            rows = db.query(ApiKeyORM).filter(ApiKeyORM.name == name).all()
            for r in rows:
                r.enabled = False
            db.commit()
            logger.info(f"[Auth] API Key revoked: name={name} count={len(rows)}")
            return len(rows) > 0
        except Exception as e:
            db.rollback()
            logger.error(f"[Auth] API Key revocation failed: {e}")
            return False
        finally:
            db.close()

    def list_keys(self, include_disabled: bool = False) -> list[dict]:
        from ..db.models import ApiKeyORM

        db = self._get_session()
        try:
            q = db.query(ApiKeyORM)
            if not include_disabled:
                q = q.filter(ApiKeyORM.enabled.is_(True))
            return [
                {
                    "id": r.id,
                    "name": r.name,
                    "role": r.role,
                    "tenant_id": r.tenant_id,
                    "enabled": r.enabled,
                    "created_at": r.created_at,
                    "last_used_at": r.last_used_at,
                }
                for r in q.all()
            ]
        finally:
            db.close()

    def ensure_master_key(self) -> str:
        # Called at startup: use env when set (stable); otherwise generate a temporary key, only the id/name is recorded, never the plaintext.
        master_key = os.environ.get(MASTER_KEY_ENV, "").strip()
        if master_key:
            self.create_api_key_from_raw("master", master_key, ["admin"])
            logger.info("[Auth] master key loaded from FUSION_SECURITY_MASTER_KEY")
            return master_key
        master_key = self.create_api_key("master", ["admin"])
        logger.warning(
            "[Auth] FUSION_SECURITY_MASTER_KEY not set, generated a temporary master key (shown in this response, never displayed again)"
        )
        return master_key

    def ensure_module_key(self, raw_key: str, tenant_id: str = "default") -> None:
        # Issue #53: persist the shell module service key at startup. The gateway /shell proxy
        # injects this key as Bearer to call dashboard endpoints, but there was previously no
        # persistence path; manually inserted viewer keys made system:manage endpoints 403 on every
        # load. Idempotent upsert (updates role/tenant when a row with the same hash exists), never logs the plaintext.
        self.create_api_key_from_raw("shell-module", raw_key, ["admin"], tenant_id=tenant_id)


auth_manager = AuthManager()


def _tenant_context():
    # Lazy import: fusion_core.tenant gets its context set by TenantMiddleware during the request lifecycle.
    try:
        from fusion_core.tenant import current

        return current()
    except Exception:
        return None


def _audit_deny(request: Request, tenant_id: str, action: str, detail: str) -> None:
    # Issue #60: auth denial events enter the audit stream (high risk) —— data source for the
    # dashboard high-risk overview / audit workbench. Audit failure never affects the denial path
    # (fail-closed first), only logs a warning.
    try:
        from ..engine.tenant.audit import get_audit_logger

        get_audit_logger(tenant_id or "system").log(
            action=action,
            actor="anonymous",
            resource_type="auth",
            resource_id=request.url.path if request is not None else "",
            details={"detail": detail, "method": request.method if request is not None else ""},
            ip_address=request.client.host if request is not None and request.client else "",
            risk_level="high",
        )
    except Exception as e:
        logger.warning(f"[Auth] audit logging failed (does not affect denial): {e}")


async def get_principal(request: Request, api_key: str = Security(API_KEY_HEADER)) -> APIKey:
    # Issue #32: dual-mode auth. TenantMiddleware already enforces the presence of X-Tenant-Id +
    # (when Bearer is present) JWT↔header matching. The fail-closed tenant checks happen here:
    # empty-tenant key → 401 (red line 1); key tenant ≠ header → 401 (red line 2).
    ctx = _tenant_context()
    header_tid = ctx.tenant_id if ctx else ""
    if api_key:
        key_obj = auth_manager.validate_key(api_key)
        if not key_obj:
            _audit_deny(request, header_tid, "auth.invalid_key", "API Key invalid or expired")
            raise HTTPException(status_code=401, detail="Invalid or expired API Key")
        if not key_obj.tenant_id:
            logger.warning(f"[Auth] API Key has no tenant assigned (name={key_obj.name}), fail-closed 401")
            _audit_deny(request, header_tid, "auth.key_no_tenant", f"key={key_obj.name} has no tenant assigned")
            raise HTTPException(status_code=401, detail="API Key has no tenant assigned, access denied")
        if header_tid and key_obj.tenant_id != header_tid:
            logger.warning(f"[Auth] tenant mismatch key={key_obj.tenant_id} header={header_tid}, fail-closed 401")
            _audit_deny(
                request,
                header_tid,
                "auth.tenant_mismatch",
                f"key_tenant={key_obj.tenant_id} header_tenant={header_tid}",
            )
            raise HTTPException(status_code=401, detail="Tenant mismatch")
        # When Bearer is present, JWT role takes priority (identity layer is authoritative).
        if ctx and ctx.role:
            key_obj = replace(key_obj, roles=[ctx.role])
        return key_obj
    # Issue #35: no X-API-Key but a non-JWT-shaped Bearer —— the gateway shell module proxy
    # (web_shell.modules) injects Bearer <module API Key> upstream; validate as a key with the
    # same fail-closed tenant checks as X-API-Key.
    bearer = request.headers.get("authorization", "") if request is not None else ""
    if bearer.lower().startswith("bearer "):
        token = bearer[7:].strip()
        from ..identity import looks_like_jwt

        if token and not looks_like_jwt(token):
            key_obj = auth_manager.validate_key(token)
            if not key_obj:
                _audit_deny(request, header_tid, "auth.invalid_key", "Bearer module key invalid or expired")
                raise HTTPException(status_code=401, detail="Invalid or expired API Key")
            if not key_obj.tenant_id:
                logger.warning(f"[Auth] Bearer Key has no tenant assigned (name={key_obj.name}), fail-closed 401")
                _audit_deny(request, header_tid, "auth.key_no_tenant", f"key={key_obj.name} has no tenant assigned")
                raise HTTPException(status_code=401, detail="API Key has no tenant assigned, access denied")
            if header_tid and key_obj.tenant_id != header_tid:
                logger.warning(f"[Auth] tenant mismatch key={key_obj.tenant_id} header={header_tid}, fail-closed 401")
                _audit_deny(
                    request,
                    header_tid,
                    "auth.tenant_mismatch",
                    f"key_tenant={key_obj.tenant_id} header_tenant={header_tid}",
                )
                raise HTTPException(status_code=401, detail="Tenant mismatch")
            return key_obj
    # No API Key —— pure JWT path: construct the principal from TenantContext.
    # Evidence of "JWT verified" is required (role/jti/scopes are only populated when verify_jwt
    # returns claims): under TenantMiddleware require_jwt=False, an anonymous request carrying
    # only X-Tenant-Id also gets TenantContext(role=None); without checking the evidence an
    # anonymous request would get viewer directly —— fail-open.
    if ctx and ctx.tenant_id and (ctx.role or ctx.jti or ctx.scopes):
        role = ctx.role or "viewer"
        return APIKey(key_hash="", name="jwt", roles=[role], tenant_id=ctx.tenant_id)
    if ctx and ctx.tenant_id:
        logger.warning(f"[Auth] no credential and no verified JWT (tenant={ctx.tenant_id}), fail-closed 401")
        _audit_deny(request, header_tid, "auth.no_credential", "no credential and no verified JWT")
    raise HTTPException(status_code=401, detail="Missing credentials (X-API-Key or Bearer token)")


# Keep get_current_key as an alias, compatible with existing dependency_overrides test fixtures.
get_current_key = get_principal


def require_permission(permission: str):
    async def _check(key: APIKey = Depends(get_principal)) -> APIKey:
        if not auth_manager.has_permission(key, permission):
            # Issue #60: privilege escalation attempts enter the audit stream (high risk) —— dashboard high-risk overview data source.
            try:
                from ..engine.tenant.audit import get_audit_logger

                get_audit_logger(key.tenant_id or "system").log(
                    action="auth.permission_denied",
                    actor=key.name,
                    resource_type="permission",
                    resource_id=permission,
                    details={"roles": list(key.roles)},
                    risk_level="high",
                )
            except Exception as e:
                logger.warning(f"[Auth] audit logging failed (does not affect denial): {e}")
            raise HTTPException(status_code=403, detail=f"Insufficient permission: {permission} required")
        return key

    return _check
