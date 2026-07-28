from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class StageCheckpoint:
    scan_id: str = ""
    project_path: str = ""
    completed_stage: str = ""
    stage_data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StageCheckpoint:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class CheckpointManager:
    def __init__(self, checkpoint_dir: str = ".fusion_checkpoints"):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def save(self, cp: StageCheckpoint) -> Path:
        cp.updated_at = time.time()
        safe_id = re.sub(r"[^\w.-]", "_", cp.scan_id)
        path = self.checkpoint_dir / f"{safe_id}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(cp.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        logger.info(f"[Checkpoint] 保存 scan_id={cp.scan_id} stage={cp.completed_stage}")
        return path

    def load(self, scan_id: str) -> StageCheckpoint | None:
        safe_id = re.sub(r"[^\w.-]", "_", scan_id)
        path = self.checkpoint_dir / f"{safe_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cp = StageCheckpoint.from_dict(data)
            logger.info(f"[Checkpoint] 加载 scan_id={scan_id} stage={cp.completed_stage}")
            return cp
        except Exception as e:
            logger.error(f"[Checkpoint] 加载失败: {e}")
            return None

    def remove(self, scan_id: str) -> bool:
        safe_id = re.sub(r"[^\w.-]", "_", scan_id)
        path = self.checkpoint_dir / f"{safe_id}.json"
        if path.exists():
            path.unlink()
            logger.info(f"[Checkpoint] 删除 scan_id={scan_id}")
            return True
        return False

    def list_checkpoints(self) -> list[StageCheckpoint]:
        results = []
        for path in self.checkpoint_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                results.append(StageCheckpoint.from_dict(data))
            except Exception:
                pass
        return results


@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 1

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _half_open_calls: int = field(default=0, init=False)

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN and time.time() - self._last_failure_time >= self.recovery_timeout:
            self._state = CircuitState.HALF_OPEN
            self._half_open_calls = 0
            logger.info("[CircuitBreaker] OPEN -> HALF_OPEN")
        return self._state

    def allow_request(self) -> bool:
        current = self.state
        if current == CircuitState.CLOSED:
            return True
        if current == CircuitState.HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False
        return False

    def record_success(self) -> None:
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
            logger.info("[CircuitBreaker] HALF_OPEN -> CLOSED")
        self._failure_count = 0
        self._half_open_calls = 0

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            logger.info("[CircuitBreaker] HALF_OPEN -> OPEN")
        elif self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.info(f"[CircuitBreaker] CLOSED -> OPEN (failures={self._failure_count})")

    def reset(self) -> None:
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_calls = 0
        logger.info("[CircuitBreaker] 重置")


@dataclass
class RetryPolicy:
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0

    def get_delay(self, attempt: int) -> float:
        delay = self.base_delay * (self.exponential_base**attempt)
        return min(delay, self.max_delay)
