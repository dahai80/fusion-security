"""API authentication — API key + RBAC."""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass
class APIKey:
    key_hash: str
    name: str = ""
    roles: List[str] = field(default_factory=lambda: ["viewer"])
    created_at: float = 0.0
    expires_at: float = 0.0

    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at


@dataclass
class Role:
    name: str
    permissions: Set[str] = field(default_factory=set)


ROLES: Dict[str, Role] = {
    "admin": Role("admin", {"scan:run", "scan:read", "project:manage", "vuln:read", "vuln:manage", "rule:manage", "system:manage", "api_key:manage"}),
    "operator": Role("operator", {"scan:run", "scan:read", "project:manage", "vuln:read", "vuln:manage"}),
    "viewer": Role("viewer", {"scan:read", "vuln:read"}),
}


class AuthManager:
    def __init__(self):
        self.api_keys: Dict[str, APIKey] = {}
        self._master_key = ""

    def create_api_key(self, name: str, roles: List[str] = None, expires_in: int = 0) -> str:
        raw_key = f"fs_{secrets.token_hex(24)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = APIKey(
            key_hash=key_hash, name=name,
            roles=roles or ["viewer"],
            created_at=time.time(),
            expires_at=time.time() + expires_in if expires_in > 0 else 0,
        )
        self.api_keys[key_hash] = api_key
        logger.info(f"[Auth] 创建 API Key: name={name} roles={api_key.roles}")
        return raw_key

    def validate_key(self, raw_key: str) -> Optional[APIKey]:
        if not raw_key:
            return None
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = self.api_keys.get(key_hash)
        if not api_key:
            return None
        if api_key.is_expired():
            logger.warning(f"[Auth] API Key 已过期: {api_key.name}")
            return None
        return api_key

    def has_permission(self, api_key: APIKey, permission: str) -> bool:
        for role_name in api_key.roles:
            role = ROLES.get(role_name)
            if role and permission in role.permissions:
                return True
        return False

    def revoke_key(self, name: str) -> bool:
        to_remove = [h for h, k in self.api_keys.items() if k.name == name]
        for h in to_remove:
            del self.api_keys[h]
        logger.info(f"[Auth] 撤销 API Key: name={name}")
        return len(to_remove) > 0

    def list_keys(self) -> List[Dict]:
        return [
            {"name": k.name, "roles": k.roles, "created_at": k.created_at, "expired": k.is_expired()}
            for k in self.api_keys.values()
        ]


auth_manager = AuthManager()


async def get_current_key(request: Request, api_key: str = Security(API_KEY_HEADER)) -> APIKey:
    if not api_key:
        raise HTTPException(status_code=401, detail="缺少 API Key (X-API-Key header)")
    key_obj = auth_manager.validate_key(api_key)
    if not key_obj:
        raise HTTPException(status_code=401, detail="无效或过期的 API Key")
    return key_obj


async def require_permission(permission: str):
    async def _check(key: APIKey = Depends(get_current_key)) -> APIKey:
        if not auth_manager.has_permission(key, permission):
            raise HTTPException(status_code=403, detail=f"权限不足: 需要 {permission}")
        return key
    return _check
