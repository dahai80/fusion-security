from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from ..models.project import Scan
from ..models.vulnerability import Vulnerability
from .ai.analyzer import AIAnalyzer
from .rules.engine import RuleEngine

logger = logging.getLogger(__name__)

DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
DEFAULT_MAX_FILES = 10000


class ScanCache:
    def __init__(self, max_entries: int = 5000, ttl_seconds: int = 3600):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[float, list[Vulnerability]]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _make_key(file_path: Path, content: str) -> str:
        h = hashlib.sha256(f"{file_path}:{content}".encode()).hexdigest()[:16]
        return h

    def get(self, file_path: Path, content: str) -> list[Vulnerability] | None:
        key = self._make_key(file_path, content)
        if key in self._cache:
            ts, vulns = self._cache[key]
            if time.time() - ts < self.ttl_seconds:
                self._cache.move_to_end(key)
                self._hits += 1
                return vulns
            del self._cache[key]
        self._misses += 1
        return None

    def put(self, file_path: Path, content: str, vulns: list[Vulnerability]) -> None:
        key = self._make_key(file_path, content)
        self._cache[key] = (time.time(), vulns)
        self._cache.move_to_end(key)
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def invalidate(self, file_path: Path) -> None:
        keys_to_remove = [k for k in self._cache if str(file_path) in k]
        for k in keys_to_remove:
            del self._cache[k]

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    @property
    def stats(self) -> dict[str, Any]:
        total = self._hits + self._misses
        return {
            "entries": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / total if total else 0.0,
        }


class ScanTarget:
    def __init__(
        self,
        path: str,
        recursive: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_files: int = DEFAULT_MAX_FILES,
        incremental_files: list[str] | None = None,
    ):
        self.path = Path(path).expanduser().resolve()
        self.recursive = recursive
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.files: list[Path] = []
        self._incremental_files: list[str] = incremental_files or []

    def discover(self, extensions: set[str] | None = None) -> list[Path]:
        if not extensions:
            extensions = {
                ".py",
                ".js",
                ".ts",
                ".jsx",
                ".tsx",
                ".java",
                ".go",
                ".rs",
                ".php",
                ".rb",
                ".swift",
                ".kt",
                ".scala",
                ".cs",
                ".c",
                ".cpp",
                ".h",
                ".hpp",
                ".yaml",
                ".yml",
                ".json",
                ".xml",
                ".sql",
                ".sh",
            }

        exclude_dirs = {
            ".git",
            "__pycache__",
            "node_modules",
            "venv",
            ".venv",
            ".egg-info",
            "dist",
            "build",
            ".build",
            ".svn",
            ".gitlab",
        }

        if self.path.is_file():
            if self.path.suffix in extensions and self._check_file_size(self.path):
                self.files = [self.path]
            else:
                self.files = []
        else:
            self.files = []
            for ext in extensions:
                if len(self.files) >= self.max_files:
                    break
                pattern = f"**/*{ext}" if self.recursive else f"*{ext}"
                for f in self.path.glob(pattern):
                    if len(self.files) >= self.max_files:
                        break
                    if any(p in f.parts for p in exclude_dirs):
                        continue
                    if self._check_file_size(f):
                        self.files.append(f)

        logger.info(f"发现 {len(self.files)} 个文件待扫描")
        return self.files

    def discover_incremental(self, changed_files: list[str], extensions: set[str] | None = None) -> list[Path]:
        if not extensions:
            extensions = {
                ".py",
                ".js",
                ".ts",
                ".jsx",
                ".tsx",
                ".java",
                ".go",
                ".rs",
                ".php",
                ".rb",
                ".swift",
                ".kt",
                ".scala",
                ".cs",
                ".c",
                ".cpp",
                ".h",
                ".hpp",
                ".yaml",
                ".yml",
                ".json",
                ".xml",
                ".sql",
                ".sh",
            }

        self.files = []
        for cf in changed_files:
            if not cf or ".." in Path(cf).parts:
                continue
            p = Path(cf)
            if not p.is_absolute():
                p = self.path / p
            if p.suffix in extensions and p.exists() and self._check_file_size(p):
                self.files.append(p)

        logger.info(f"增量扫描: {len(self.files)} 个变更文件")
        return self.files

    def _check_file_size(self, path: Path) -> bool:
        try:
            return path.stat().st_size <= self.max_file_size
        except OSError:
            return False


class ScanResult:
    def __init__(self, target: ScanTarget):
        self.target = target
        self.scan: Scan | None = None
        self.vulnerabilities: list[Vulnerability] = []
        self.files_scanned: int = 0
        self.files_skipped: int = 0
        self.duration_ms: float = 0.0
        self.summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": str(self.target.path),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "duration_ms": round(self.duration_ms, 1),
            "total_vulnerabilities": len(self.vulnerabilities),
            "critical": sum(1 for v in self.vulnerabilities if v.severity == "critical"),
            "high": sum(1 for v in self.vulnerabilities if v.severity == "high"),
            "medium": sum(1 for v in self.vulnerabilities if v.severity == "medium"),
            "low": sum(1 for v in self.vulnerabilities if v.severity == "low"),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "summary": self.summary,
        }

    def to_scan_model(self) -> Scan:
        s = Scan()
        s.files_scanned = self.files_scanned
        s.files_skipped = self.files_skipped
        s.duration_ms = self.duration_ms
        s.total_vulnerabilities = len(self.vulnerabilities)
        s.critical = sum(1 for v in self.vulnerabilities if v.severity == "critical")
        s.high = sum(1 for v in self.vulnerabilities if v.severity == "high")
        s.medium = sum(1 for v in self.vulnerabilities if v.severity == "medium")
        s.low = sum(1 for v in self.vulnerabilities if v.severity == "low")
        s.summary = self.summary
        s.status = "completed"
        return s


class Scanner:
    def __init__(self, use_ai: bool = True, model: str = "", enable_cache: bool = True, project_id: str = "", db=None):
        self.use_ai = use_ai
        self.model = model
        self.rule_engine = RuleEngine()
        self.ai_analyzer = AIAnalyzer(model=model) if use_ai else None
        self.cache = ScanCache() if enable_cache else None
        self.project_id = project_id
        self._project_cache = None
        if project_id and db:
            from .cache import ProjectScanCache

            self._project_cache = ProjectScanCache(db)

    async def scan(
        self,
        target: ScanTarget,
        severity_threshold: str = "low",
    ) -> ScanResult:
        start = time.time()
        result = ScanResult(target)
        files = target.discover()
        result.files_scanned = len(files)

        logger.info(f"开始扫描: {target.path} ({len(files)} 个文件)")

        async def scan_file(file_path: Path) -> list[Vulnerability]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if self._project_cache:
                    rel = (
                        str(file_path.relative_to(target.path))
                        if file_path.is_relative_to(target.path)
                        else str(file_path)
                    )
                    cached = self._project_cache.get(self.project_id, rel, content)
                    if cached is not None:
                        return cached
                if self.cache:
                    cached = self.cache.get(file_path, content)
                    if cached is not None:
                        return cached
                vulns = self.rule_engine.scan_file_full(file_path, content)
                if self._project_cache:
                    rel = (
                        str(file_path.relative_to(target.path))
                        if file_path.is_relative_to(target.path)
                        else str(file_path)
                    )
                    self._project_cache.put(self.project_id, rel, content, vulns)
                if self.cache:
                    self.cache.put(file_path, content, vulns)
                return vulns
            except Exception as e:
                logger.debug(f"扫描文件失败 {file_path}: {e}")
                result.files_skipped += 1
                return []

        batch_size = 50
        for i in range(0, len(files), batch_size):
            batch = files[i : i + batch_size]
            batch_results = await asyncio.gather(*[scan_file(f) for f in batch], return_exceptions=True)
            for findings in batch_results:
                if isinstance(findings, list):
                    result.vulnerabilities.extend(findings)

        if self.ai_analyzer and result.vulnerabilities:
            verified = await self.ai_analyzer.verify_findings(result.vulnerabilities, files)
            result.vulnerabilities = verified

        if self.ai_analyzer and result.vulnerabilities:
            semantic_findings = await self.ai_analyzer.semantic_scan(files)
            result.vulnerabilities.extend(semantic_findings)

        levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = levels.get(severity_threshold, 3)
        result.vulnerabilities = [v for v in result.vulnerabilities if levels.get(v.severity, 3) <= threshold]

        result.duration_ms = (time.time() - start) * 1000
        self._generate_summary(result)

        cache_info = f" cache={self.cache.stats}" if self.cache else ""
        logger.info(f"扫描完成: {len(result.vulnerabilities)} 个漏洞 ({result.duration_ms:.0f}ms){cache_info}")
        return result

    async def scan_incremental(
        self,
        target: ScanTarget,
        changed_files: list[str],
        severity_threshold: str = "low",
    ) -> ScanResult:
        start = time.time()
        result = ScanResult(target)
        files = target.discover_incremental(changed_files)
        result.files_scanned = len(files)

        logger.info(f"增量扫描: {target.path} ({len(files)} 个变更文件)")

        async def scan_file(file_path: Path) -> list[Vulnerability]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if self._project_cache:
                    rel = (
                        str(file_path.relative_to(target.path))
                        if file_path.is_relative_to(target.path)
                        else str(file_path)
                    )
                    cached = self._project_cache.get(self.project_id, rel, content)
                    if cached is not None:
                        return cached
                if self.cache:
                    cached = self.cache.get(file_path, content)
                    if cached is not None:
                        return cached
                vulns = self.rule_engine.scan_file_full(file_path, content)
                if self._project_cache:
                    rel = (
                        str(file_path.relative_to(target.path))
                        if file_path.is_relative_to(target.path)
                        else str(file_path)
                    )
                    self._project_cache.put(self.project_id, rel, content, vulns)
                if self.cache:
                    self.cache.put(file_path, content, vulns)
                return vulns
            except Exception as e:
                logger.debug(f"扫描文件失败 {file_path}: {e}")
                result.files_skipped += 1
                return []

        if files:
            batch_results = await asyncio.gather(*[scan_file(f) for f in files], return_exceptions=True)
            for findings in batch_results:
                if isinstance(findings, list):
                    result.vulnerabilities.extend(findings)

        if self.ai_analyzer and result.vulnerabilities:
            verified = await self.ai_analyzer.verify_findings(result.vulnerabilities, files)
            result.vulnerabilities = verified

        levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = levels.get(severity_threshold, 3)
        result.vulnerabilities = [v for v in result.vulnerabilities if levels.get(v.severity, 3) <= threshold]

        result.duration_ms = (time.time() - start) * 1000
        self._generate_summary(result)
        return result

    async def scan_directory(
        self,
        path: str,
        severity_threshold: str = "low",
        extensions: set[str] | None = None,
    ) -> ScanResult:
        target = ScanTarget(path)
        if extensions:
            target.discover(extensions)
        return await self.scan(target, severity_threshold)

    def _generate_summary(self, result: ScanResult) -> None:
        total = len(result.vulnerabilities)
        if total == 0:
            result.summary = "✅ 未发现安全漏洞"
            return

        by_severity = {}
        for v in result.vulnerabilities:
            by_severity.setdefault(v.severity, 0)
            by_severity[v.severity] += 1

        parts = [f"发现 {total} 个安全漏洞"]
        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_severity:
                parts.append(f"{sev}: {by_severity[sev]}")
        result.summary = " | ".join(parts)
