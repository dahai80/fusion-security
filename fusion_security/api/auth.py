"""API authentication — API key + RBAC, DB-backed hashed key store."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
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
    # P0-4/S-P0-3: key 持久化到 DB,只存 sha256 哈希;主密钥经 FUSION_SECURITY_MASTER_KEY 稳定,绝不记录明文。
    def __init__(self, session_factory=None):
        self._master_key = ""
        # 测试可注入独立 session factory 做隔离;生产用全局 get_session。
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
            logger.info(f"[Auth] 创建 API Key: name={name} role={role_list[0]} tenant={tenant_id}")
        except Exception as e:
            db.rollback()
            logger.error(f"[Auth] 创建 API Key 失败: {e}")
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
            if not hmac.compare_digest(row.key_hash, key_hash):
                return None
            expires_ts = row.expires_at.timestamp() if row.expires_at else 0.0
            # row.expires_at 是 naive UTC(utcnow 写入),用 utcnow 比较避免本地时区偏移导致的误判过期。
            now_ts = datetime.utcnow().timestamp()
            if expires_ts > 0 and now_ts > expires_ts:
                logger.warning(f"[Auth] API Key 已过期: {row.name}")
                return None
            row.last_used_at = datetime.utcnow()
            db.commit()
            # 把 DB 单角色还原成 roles 列表(RBAC 用 list)。
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
            logger.warning(f"[Auth] 校验 API Key 异常: {e}")
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
            logger.info(f"[Auth] 撤销 API Key: name={name} count={len(rows)}")
            return len(rows) > 0
        except Exception as e:
            db.rollback()
            logger.error(f"[Auth] 撤销 API Key 失败: {e}")
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
        # 启动时调用:env 设了就用 env(稳定);没设就生成临时 key,只记录 id/name,绝不记明文。
        master_key = os.environ.get(MASTER_KEY_ENV, "").strip()
        if master_key:
            self.create_api_key_from_raw("master", master_key, ["admin"])
            logger.info("[Auth] master key 已从 FUSION_SECURITY_MASTER_KEY 载入")
            return master_key
        master_key = self.create_api_key("master", ["admin"])
        logger.warning("[Auth] 未设 FUSION_SECURITY_MASTER_KEY,已生成临时 master key(见本条响应,后续不再显示)")
        return master_key


auth_manager = AuthManager()


async def get_current_key(request: Request, api_key: str = Security(API_KEY_HEADER)) -> APIKey:
    if not api_key:
        raise HTTPException(status_code=401, detail="缺少 API Key (X-API-Key header)")
    key_obj = auth_manager.validate_key(api_key)
    if not key_obj:
        raise HTTPException(status_code=401, detail="无效或过期的 API Key")
    return key_obj


def require_permission(permission: str):
    async def _check(key: APIKey = Depends(get_current_key)) -> APIKey:
        if not auth_manager.has_permission(key, permission):
            raise HTTPException(status_code=403, detail=f"权限不足: 需要 {permission}")
        return key

    return _check
