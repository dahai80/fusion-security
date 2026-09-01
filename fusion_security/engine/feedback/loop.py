"""False-positive feedback loop — learn from user feedback to suppress FP."""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    vuln_id: str = ""
    rule_id: str = ""
    file_path: str = ""
    line_number: int = 0
    is_false_positive: bool = False
    reason: str = ""
    timestamp: float = 0.0
    user: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


class FeedbackStore:
    def __init__(self, store_path: str = "", max_entries: int = 10000):
        self.store_path = store_path
        self.max_entries = max_entries
        # deque.popleft 为 O(1)；list.pop(0) 在万级条目下每次平移整表，改用有界 deque。
        self.entries: deque[FeedbackEntry] = deque(maxlen=max_entries)
        self._fp_signatures: set[str] = set()
        if store_path:
            self._load()

    def add_feedback(self, entry: FeedbackEntry) -> None:
        # 达到上限时先取出最旧条目并清除其误报签名，再 append，保证签名集与队列一致。
        if len(self.entries) == self.max_entries:
            removed = self.entries.popleft()
            self._fp_signatures.discard(self._signature(removed))
        self.entries.append(entry)
        if entry.is_false_positive:
            sig = self._signature(entry)
            self._fp_signatures.add(sig)
            logger.info(f"[Feedback] 标记误报: {entry.vuln_id} rule={entry.rule_id}")
        else:
            logger.info(f"[Feedback] 确认漏洞: {entry.vuln_id}")
        if self.store_path:
            self._save()

    def is_false_positive(self, rule_id: str, file_path: str, line_number: int) -> bool:
        sig = f"{rule_id}:{file_path}:{line_number}"
        return sig in self._fp_signatures

    def filter_vulnerabilities(self, vulns: list) -> list:
        before = len(vulns)
        filtered = [
            v
            for v in vulns
            if not self.is_false_positive(
                getattr(v, "rule_id", ""), getattr(v, "file_path", ""), getattr(v, "line_number", 0)
            )
        ]
        removed = before - len(filtered)
        if removed:
            logger.info(f"[Feedback] 过滤 {removed} 个误报")
        return filtered

    def get_stats(self) -> dict[str, Any]:
        fp = sum(1 for e in self.entries if e.is_false_positive)
        tp = sum(1 for e in self.entries if not e.is_false_positive)
        rule_fp: dict[str, int] = {}
        for e in self.entries:
            if e.is_false_positive:
                rule_fp[e.rule_id] = rule_fp.get(e.rule_id, 0) + 1
        return {
            "total_feedback": len(self.entries),
            "false_positives": fp,
            "true_positives": tp,
            "rules_with_fp": rule_fp,
        }

    def _signature(self, entry: FeedbackEntry) -> str:
        return f"{entry.rule_id}:{entry.file_path}:{entry.line_number}"

    def _save(self) -> None:
        if not self.store_path:
            return
        try:
            Path(self.store_path).parent.mkdir(parents=True, exist_ok=True)
            data = []
            for e in self.entries:
                data.append(
                    {
                        "vuln_id": e.vuln_id,
                        "rule_id": e.rule_id,
                        "file_path": e.file_path,
                        "line_number": e.line_number,
                        "is_false_positive": e.is_false_positive,
                        "reason": e.reason,
                        "timestamp": e.timestamp,
                        "user": e.user,
                    }
                )
            with open(self.store_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"[Feedback] 保存失败: {e}")

    def _load(self) -> None:
        if not self.store_path:
            return
        try:
            p = Path(self.store_path)
            if not p.exists():
                return
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                entry = FeedbackEntry(
                    vuln_id=item.get("vuln_id", ""),
                    rule_id=item.get("rule_id", ""),
                    file_path=item.get("file_path", ""),
                    line_number=item.get("line_number", 0),
                    is_false_positive=item.get("is_false_positive", False),
                    reason=item.get("reason", ""),
                    timestamp=item.get("timestamp", 0),
                    user=item.get("user", ""),
                )
                self.entries.append(entry)
                if entry.is_false_positive:
                    self._fp_signatures.add(self._signature(entry))
            # 加载量超过 maxlen 时 deque 已静默驱逐最旧条目，需清掉残留的误报签名保持一致。
            live_sigs = {self._signature(e) for e in self.entries if e.is_false_positive}
            self._fp_signatures &= live_sigs
            logger.info(f"[Feedback] 加载 {len(self.entries)} 条反馈")
        except Exception as e:
            logger.warning(f"[Feedback] 加载失败: {e}")
