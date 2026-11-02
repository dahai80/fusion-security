"""Console audit store — query layer over per-tenant audit jsonl files.

Issue #60/#61: AuditLogger 落盘 audit_{tenant}.jsonl(append-only);本模块只读该
文件做聚合/检索(重启不丢)。旧行缺 risk_level/trace_id 字段时按 info/""兜底。
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from ..tenant.audit import _safe_tenant_slug

logger = logging.getLogger(__name__)

RISK_LEVELS = ("info", "low", "medium", "high", "critical")
HIGH_RISK_LEVELS = ("high", "critical")


def event_key(rec: dict[str, Any]) -> str:
    # Issue #65: 事件无落盘 ID,用 ts:action:actor 组合键定位(jsonl append-only,
    # 标记复核存独立表引用该键;同秒同action同actor视为同一事件,工作台场景够用)。
    return f"{rec['timestamp']:.3f}:{rec['action']}:{rec['actor']}"


def _entry_from_line(line: str) -> dict[str, Any] | None:
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict) or not rec.get("action"):
        return None
    rec.setdefault("risk_level", "info")
    rec.setdefault("trace_id", "")
    rec.setdefault("details", {})
    rec.setdefault("actor", "")
    rec.setdefault("resource_type", "")
    rec.setdefault("resource_id", "")
    rec.setdefault("ip_address", "")
    try:
        rec["timestamp"] = float(rec.get("timestamp") or 0.0)
    except (TypeError, ValueError):
        rec["timestamp"] = 0.0
    return rec


class AuditStore:
    # 只读查询层:不持锁、不缓存(文件量级 = 审计条数,逐行读可接受;
    # max_entries 环形驱逐只影响内存,文件是完整历史)。
    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)

    def _tenant_file(self, tenant_id: str) -> Path:
        return self.log_dir / f"audit_{_safe_tenant_slug(tenant_id)}.jsonl"

    def _load(self, tenant_id: str) -> list[dict[str, Any]]:
        path = self._tenant_file(tenant_id)
        if not path.exists():
            return []
        entries: list[dict[str, Any]] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    rec = _entry_from_line(line)
                    if rec is not None:
                        entries.append(rec)
        except OSError as e:
            logger.warning(f"[AuditStore] 读取失败 {path}: {e}")
            return []
        return entries

    @staticmethod
    def _match(
        rec: dict[str, Any],
        search: str,
        action: str,
        risk_levels: tuple[str, ...],
        start_ts: float,
        end_ts: float,
        trace_id: str = "",
        resource_id: str = "",
        marked_keys: frozenset[str] | None = None,
        marked_only: bool = False,
    ) -> bool:
        if start_ts and rec["timestamp"] < start_ts:
            return False
        if end_ts and rec["timestamp"] > end_ts:
            return False
        if action and not rec["action"].startswith(action):
            return False
        if risk_levels and rec["risk_level"] not in risk_levels:
            return False
        if trace_id and rec["trace_id"] != trace_id:
            return False
        if resource_id and rec["resource_id"] != resource_id:
            return False
        if marked_only and (marked_keys is None or event_key(rec) not in marked_keys):
            return False
        if search:
            haystack = f"{rec['action']} {rec['actor']} {rec['resource_type']} {rec['resource_id']}"
            if search.lower() not in haystack.lower():
                return False
        return True

    def query(
        self,
        tenant_id: str,
        search: str = "",
        action: str = "",
        risk_levels: tuple[str, ...] = (),
        start_ts: float = 0.0,
        end_ts: float = 0.0,
        limit: int = 100,
        offset: int = 0,
        trace_id: str = "",
        resource_id: str = "",
        marked_keys: frozenset[str] | None = None,
        marked_only: bool = False,
    ) -> tuple[list[dict[str, Any]], int]:
        # 返回 (entries, total):total 为过滤后总数(分页用),entries 为当前页。
        # Issue #65: trace_id/resource_id 精确匹配(关联事件跳转);marked_keys +
        # marked_only 支撑"仅看已标记"(total 含标记过滤,分页数一致)。
        entries = self._load(tenant_id)
        matched = [
            r
            for r in entries
            if self._match(
                r,
                search.strip(),
                action.strip(),
                risk_levels,
                start_ts,
                end_ts,
                trace_id.strip(),
                resource_id.strip(),
                marked_keys,
                marked_only,
            )
        ]
        matched.sort(key=lambda r: r["timestamp"], reverse=True)
        total = len(matched)
        return matched[offset : offset + limit], total

    def today_counts(self, tenant_id: str) -> dict[str, int]:
        # 首页审计分区:今日事件数 + 高风险数 + 最近高风险条目。
        now = time.time()
        day_start = now - (now % 86400)
        entries = self._load(tenant_id)
        today = [r for r in entries if r["timestamp"] >= day_start]
        high = [r for r in today if r["risk_level"] in HIGH_RISK_LEVELS]
        return {"total": len(today), "high_risk": len(high)}

    def latest_high_risk(self, tenant_id: str, limit: int = 3) -> list[dict[str, Any]]:
        entries = self._load(tenant_id)
        high = [r for r in entries if r["risk_level"] in HIGH_RISK_LEVELS]
        high.sort(key=lambda r: r["timestamp"], reverse=True)
        return high[:limit]
