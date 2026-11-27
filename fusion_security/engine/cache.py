from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from sqlalchemy import func

from ..db.models import ScanCacheORM
from ..models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _vulns_to_json(vulns: list[Vulnerability]) -> str:
    return json.dumps([v.to_dict() for v in vulns], ensure_ascii=False)


def _json_to_vulns(data: str) -> list[Vulnerability]:
    # Schema drift / corrupted JSON makes Vulnerability(**item) raise TypeError and
    # invalidates the whole cache entry. Per-item try/except plus field filtering:
    # skip and log bad items instead of crashing the whole batch.
    if not data:
        return []
    try:
        items = json.loads(data)
    except json.JSONDecodeError as e:
        logger.warning(f"[Cache] results_json parse failed, returning empty: {e}")
        return []
    if not isinstance(items, list):
        logger.warning("[Cache] results_json is not an array, returning empty")
        return []
    valid_fields = set(Vulnerability.__dataclass_fields__)
    vulns = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            vulns.append(Vulnerability(**{k: v for k, v in item.items() if k in valid_fields}))
        except Exception as e:
            logger.warning(f"[Cache] skipping corrupted cache item: {e}")
    return vulns


class ProjectScanCache:
    def __init__(self, db):
        self._db = db

    def get(self, project_id: str, file_path: str, content: str) -> list[Vulnerability] | None:
        ch = _content_hash(content)
        row = (
            self._db.query(ScanCacheORM)
            .filter(
                ScanCacheORM.project_id == project_id,
                ScanCacheORM.file_path == file_path,
                ScanCacheORM.content_hash == ch,
            )
            .first()
        )
        if row:
            logger.debug(f"cache hit: project={project_id} file={file_path}")
            return _json_to_vulns(row.results_json)
        logger.debug(f"cache miss: project={project_id} file={file_path}")
        return None

    def put(
        self, project_id: str, file_path: str, content: str, vulns: list[Vulnerability], commit: bool = True
    ) -> None:
        # A-P1-4: with the (project_id, file_path) unique constraint, concurrent scans of
        # the same file race between query-then-insert: both threads miss the query ->
        # both insert -> the second hits IntegrityError. Catch it and fall back to UPDATE.
        from sqlalchemy.exc import IntegrityError

        ch = _content_hash(content)
        row = (
            self._db.query(ScanCacheORM)
            .filter(
                ScanCacheORM.project_id == project_id,
                ScanCacheORM.file_path == file_path,
            )
            .first()
        )
        if row:
            row.content_hash = ch
            row.results_json = _vulns_to_json(vulns)
            logger.debug(f"cache updated: project={project_id} file={file_path}")
        else:
            row = ScanCacheORM(
                project_id=project_id,
                file_path=file_path,
                content_hash=ch,
                results_json=_vulns_to_json(vulns),
            )
            self._db.add(row)
            logger.debug(f"cache written: project={project_id} file={file_path}")
        if commit:
            try:
                self._db.commit()
            except IntegrityError:
                # Unique-constraint conflict: another concurrent write already inserted
                # the same (project_id, file_path). Fall back to updating that row.
                self._db.rollback()
                existing = (
                    self._db.query(ScanCacheORM)
                    .filter(
                        ScanCacheORM.project_id == project_id,
                        ScanCacheORM.file_path == file_path,
                    )
                    .first()
                )
                if existing:
                    existing.content_hash = ch
                    existing.results_json = _vulns_to_json(vulns)
                    self._db.commit()
                    logger.debug(f"cache race fallback update: project={project_id} file={file_path}")

    def flush(self) -> None:
        # Commit once after batch writes instead of per-file commits in put, avoiding
        # N fsyncs. Committing an empty transaction has no side effects.
        try:
            self._db.commit()
        except Exception as e:
            logger.warning(f"[Cache] flush commit failed: {e}")
            self._db.rollback()

    def get_multi(
        self, project_id: str, file_paths: list[str], contents: dict[str, str]
    ) -> dict[str, list[Vulnerability]]:
        results = {}
        for fp in file_paths:
            content = contents.get(fp, "")
            if content:
                cached = self.get(project_id, fp, content)
                if cached is not None:
                    results[fp] = cached
        return results

    def put_multi(self, project_id: str, results_map: dict[str, tuple]) -> None:
        # Batch write: put each item without commit, then commit once, avoiding N fsyncs.
        for fp, (content, vulns) in results_map.items():
            self.put(project_id, fp, content, vulns, commit=False)
        self._db.commit()

    def invalidate_project(self, project_id: str) -> int:
        count = (
            self._db.query(ScanCacheORM)
            .filter(
                ScanCacheORM.project_id == project_id,
            )
            .delete()
        )
        self._db.commit()
        logger.info(f"project cache cleared: project={project_id} deleted={count}")
        return count

    def invalidate_file(self, project_id: str, file_path: str) -> None:
        self._db.query(ScanCacheORM).filter(
            ScanCacheORM.project_id == project_id,
            ScanCacheORM.file_path == file_path,
        ).delete()
        self._db.commit()

    def cleanup_stale(self, project_id: str, current_files: list[str]) -> int:
        cached = (
            self._db.query(ScanCacheORM)
            .filter(
                ScanCacheORM.project_id == project_id,
            )
            .all()
        )
        current_set = set(current_files)
        stale = [r for r in cached if r.file_path not in current_set]
        for r in stale:
            self._db.delete(r)
        if stale:
            self._db.commit()
        logger.info(f"stale cache cleaned: project={project_id} deleted={len(stale)}")
        return len(stale)

    def stats(self, project_id: str) -> dict[str, Any]:
        total = (
            self._db.query(func.count(ScanCacheORM.id))
            .filter(
                ScanCacheORM.project_id == project_id,
            )
            .scalar()
        )
        return {
            "project_id": project_id,
            "cached_files": total,
        }
