"""Console audit store — query layer over per-tenant audit jsonl files.

Issue #60/#61: AuditLogger persists audit_{tenant}.jsonl (append-only); this module only
reads that file for aggregation/search (nothing lost on restart). Old rows missing
risk_level/trace_id fall back to info/"".
"""

from __future__ import annotations

import hashlib
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
    # Issue #68 R1: events carry no persisted ID, so the key = sha256 digest of the full
    # payload. On-disk timestamps are already microsecond precision; the legacy
    # ts:action:actor three-digit truncation collides when same-millisecond + same actor
    # + same action (concurrent bursts are exactly that shape) → markers cross-pollute.
    # The digest covers the full payload, so in practice no collisions.
    # Migration compatibility: legacy_event_key still participates in matching, so
    # existing markers stay valid.
    payload = json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)
    return "mk_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def legacy_event_key(rec: dict[str, Any]) -> str:
    # Key shape used up to v0.2.0rc9 (three-digit millisecond truncation), kept only for
    # matching existing markers.
    return f"{rec['timestamp']:.3f}:{rec['action']}:{rec['actor']}"


def event_key_candidates(rec: dict[str, Any]) -> tuple[str, str]:
    # Marker resolution candidates: new digest key first, legacy key as fallback (used on
    # both the event rows and the marker table sides).
    return (event_key(rec), legacy_event_key(rec))


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
    # Read-only query layer: no locks, no cache (file size = audit entry count, so
    # line-by-line reads are acceptable; max_entries ring eviction only affects memory,
    # the file is the complete history).
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
            logger.warning(f"[AuditStore] failed to read {path}: {e}")
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
        if marked_only and (marked_keys is None or not (set(event_key_candidates(rec)) & marked_keys)):
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
        # Returns (entries, total): total is the post-filter count (for pagination),
        # entries is the current page.
        # Issue #65: trace_id/resource_id exact match (related-event jumps); marked_keys +
        # marked_only support "marked only" (total includes the marker filter, page counts stay consistent).
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

    def known_mark_keys(self, tenant_id: str) -> frozenset[str]:
        # Issue #68 R2: every marker key actually present in the current audit stream
        # (new digest + legacy fallback); the marks write path uses it to reject
        # dangling event_keys.
        keys: set[str] = set()
        for rec in self._load(tenant_id):
            keys.update(event_key_candidates(rec))
        return frozenset(keys)

    def today_counts(self, tenant_id: str) -> dict[str, int]:
        # Home audit zone: today's event count + high-risk count + latest high-risk entries.
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
