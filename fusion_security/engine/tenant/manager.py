"""Multi-tenant isolation manager."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Tenant:
    id: str = ""
    name: str = ""
    api_key_hash: str = ""
    data_dir: str = ""
    settings: dict[str, Any] = field(default_factory=dict)
    is_active: bool = True

    def __post_init__(self):
        if not self.id:
            self.id = f"tenant_{secrets.token_hex(6)}"


class TenantManager:
    def __init__(self, base_dir: str = ""):
        self.base_dir = base_dir or os.path.expanduser("~/.fusion_security/tenants")
        self.tenants: dict[str, Tenant] = {}
        self._load()

    def create_tenant(self, name: str, settings: dict[str, Any] | None = None) -> tuple:
        raw_key = f"fs_tenant_{secrets.token_hex(24)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        tenant_id = f"tenant_{secrets.token_hex(6)}"
        data_dir = str(Path(self.base_dir) / tenant_id / "data")
        Path(data_dir).mkdir(parents=True, exist_ok=True)

        tenant = Tenant(
            id=tenant_id,
            name=name,
            api_key_hash=key_hash,
            data_dir=data_dir,
            settings=settings or {},
        )
        self.tenants[tenant_id] = tenant
        self._save()
        logger.info(f"[Tenant] 创建租户: {name} id={tenant_id}")
        return tenant_id, raw_key

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self.tenants.get(tenant_id)

    def authenticate(self, raw_key: str) -> Tenant | None:
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        for t in self.tenants.values():
            if t.api_key_hash == key_hash and t.is_active:
                return t
        return None

    def list_tenants(self) -> list[dict[str, Any]]:
        return [
            {"id": t.id, "name": t.name, "active": t.is_active, "data_dir": t.data_dir} for t in self.tenants.values()
        ]

    def deactivate(self, tenant_id: str) -> bool:
        t = self.tenants.get(tenant_id)
        if t:
            t.is_active = False
            self._save()
            logger.info(f"[Tenant] 停用租户: {t.name}")
            return True
        return False

    def _save(self) -> None:
        import json

        try:
            Path(self.base_dir).mkdir(parents=True, exist_ok=True)
            data = {}
            for tid, t in self.tenants.items():
                data[tid] = {
                    "id": t.id,
                    "name": t.name,
                    "api_key_hash": t.api_key_hash,
                    "data_dir": t.data_dir,
                    "settings": t.settings,
                    "is_active": t.is_active,
                }
            with open(Path(self.base_dir) / "tenants.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"[Tenant] 保存失败: {e}")

    def _load(self) -> None:
        import json

        try:
            p = Path(self.base_dir) / "tenants.json"
            if not p.exists():
                return
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            for tid, d in data.items():
                self.tenants[tid] = Tenant(**d)
            logger.info(f"[Tenant] 加载 {len(self.tenants)} 个租户")
        except Exception as e:
            logger.warning(f"[Tenant] 加载失败: {e}")
