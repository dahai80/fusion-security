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
    # schema 漂移/损坏 JSON 会让 Vulnerability(**item) 抛 TypeError,整条缓存不可用。
    # 逐项 try/except + 字段过滤,坏项跳过并记录,不再整批崩溃。
    if not data:
        return []
    try:
        items = json.loads(data)
    except json.JSONDecodeError as e:
        logger.warning(f"[Cache] results_json 解析失败,返回空: {e}")
        return []
    if not isinstance(items, list):
        logger.warning("[Cache] results_json 非数组,返回空")
        return []
    valid_fields = set(Vulnerability.__dataclass_fields__)
    vulns = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            vulns.append(Vulnerability(**{k: v for k, v in item.items() if k in valid_fields}))
        except Exception as e:
            logger.warning(f"[Cache] 跳过损坏缓存项: {e}")
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
            logger.debug(f"缓存命中: project={project_id} file={file_path}")
            return _json_to_vulns(row.results_json)
        logger.debug(f"缓存未命中: project={project_id} file={file_path}")
        return None

    def put(
        self, project_id: str, file_path: str, content: str, vulns: list[Vulnerability], commit: bool = True
    ) -> None:
        # A-P1-4: (project_id, file_path) 唯一约束下,并发扫描同文件先 query-后-insert 存在竞态:
        # 两线程都 query 未命中 -> 都 insert -> 第二个 IntegrityError。捕获后回退为 UPDATE。
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
            logger.debug(f"缓存更新: project={project_id} file={file_path}")
        else:
            row = ScanCacheORM(
                project_id=project_id,
                file_path=file_path,
                content_hash=ch,
                results_json=_vulns_to_json(vulns),
            )
            self._db.add(row)
            logger.debug(f"缓存写入: project={project_id} file={file_path}")
        if commit:
            try:
                self._db.commit()
            except IntegrityError:
                # 唯一约束冲突:另一并发写已插入同 (project_id, file_path)。回退为更新该行。
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
                    logger.debug(f"缓存竞态回退更新: project={project_id} file={file_path}")

    def flush(self) -> None:
        # 批量写后统一提交,避免 put 逐文件 commit 导致 N 次 fsync。空事务提交无副作用。
        try:
            self._db.commit()
        except Exception as e:
            logger.warning(f"[Cache] flush 提交失败: {e}")
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
        # 批量写:逐条 put 不 commit,最后一次 commit,避免 N 次 fsync。
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
        logger.info(f"清理项目缓存: project={project_id} 删除={count}")
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
        logger.info(f"清理过期缓存: project={project_id} 删除={len(stale)}")
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
