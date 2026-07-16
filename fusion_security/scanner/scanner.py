"""代码扫描引擎 — 多文件扫描、数据流追踪、漏洞检测。"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..rules.engine import RuleEngine
from ..models import Vulnerability
from ..ai.analyzer import AIAnalyzer

logger = logging.getLogger(__name__)

# 默认限制
DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
DEFAULT_MAX_FILES = 10000


class ScanTarget:
    """扫描目标定义。"""
    def __init__(
        self,
        path: str,
        recursive: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_files: int = DEFAULT_MAX_FILES,
    ):
        self.path = Path(path).expanduser().resolve()
        self.recursive = recursive
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.files: List[Path] = []

    def discover(self, extensions: Optional[Set[str]] = None) -> List[Path]:
        """发现待扫描文件（带大小和数量限制）。"""
        if not extensions:
            extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
                         '.php', '.rb', '.swift', '.kt', '.scala', '.cs', '.c', '.cpp',
                         '.h', '.hpp', '.yaml', '.yml', '.json', '.xml', '.sql', '.sh'}

        # 排除常见非源码目录
        exclude_dirs = {'.git', '__pycache__', 'node_modules', 'venv', '.venv',
                        '.egg-info', 'dist', 'build', '.build', '.svn', '.gitlab'}

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

        return self.files

    def _check_file_size(self, path: Path) -> bool:
        """检查文件是否在大小限制内。"""
        try:
            return path.stat().st_size <= self.max_file_size
        except (OSError, IOError):
            return False


class ScanResult:
    """扫描结果。"""
    def __init__(self, target: ScanTarget):
        self.target = target
        self.vulnerabilities: List[Vulnerability] = []
        self.files_scanned: int = 0
        self.files_skipped: int = 0
        self.duration_ms: float = 0.0
        self.summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
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


class Scanner:
    """代码安全扫描器 — 多文件并行扫描 + 规则匹配 + AI 验证。

    对标 Claude Security 的扫描能力：
    - 跨文件数据流追踪
    - AI 语义理解识别逻辑漏洞
    - 多层校验降低误报
    """

    def __init__(self, use_ai: bool = True, model: str = ""):
        self.use_ai = use_ai
        self.model = model
        self.rule_engine = RuleEngine()
        self.ai_analyzer = AIAnalyzer(model=model) if use_ai else None

    async def scan(
        self,
        target: ScanTarget,
        severity_threshold: str = "low",
    ) -> ScanResult:
        """执行扫描。"""
        import time
        start = time.time()

        result = ScanResult(target)
        files = target.discover()
        result.files_scanned = len(files)

        logger.info(f"开始扫描: {target.path} ({len(files)} 个文件)")

        # 1. 规则引擎扫描（并行）
        async def scan_file(file_path: Path) -> List[Vulnerability]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                return self.rule_engine.scan_file(file_path, content)
            except Exception as e:
                logger.debug(f"扫描文件失败 {file_path}: {e}")
                result.files_skipped += 1
                return []

        # 分批执行避免太多并发
        batch_size = 50
        for i in range(0, len(files), batch_size):
            batch = files[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[scan_file(f) for f in batch], return_exceptions=True
            )
            for findings in batch_results:
                if isinstance(findings, list):
                    result.vulnerabilities.extend(findings)

        # 2. AI 验证（降低误报）
        if self.ai_analyzer and result.vulnerabilities:
            verified = await self.ai_analyzer.verify_findings(
                result.vulnerabilities, files
            )
            result.vulnerabilities = verified

        # 3. AI 语义分析发现逻辑漏洞
        if self.ai_analyzer and result.vulnerabilities:
            semantic_findings = await self.ai_analyzer.semantic_scan(files)
            result.vulnerabilities.extend(semantic_findings)

        # 4. 按严重级别过滤
        levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = levels.get(severity_threshold, 3)
        result.vulnerabilities = [
            v for v in result.vulnerabilities
            if levels.get(v.severity, 3) <= threshold
        ]

        result.duration_ms = (time.time() - start) * 1000
        self._generate_summary(result)

        logger.info(f"扫描完成: {len(result.vulnerabilities)} 个漏洞 ({result.duration_ms:.0f}ms)")
        return result

    def _generate_summary(self, result: ScanResult) -> None:
        """生成扫描摘要。"""
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

    async def scan_directory(
        self,
        path: str,
        severity_threshold: str = "low",
        extensions: Optional[Set[str]] = None,
    ) -> ScanResult:
        """扫描目录的便捷方法。"""
        target = ScanTarget(path)
        if extensions:
            target.discover(extensions)
        return await self.scan(target, severity_threshold)