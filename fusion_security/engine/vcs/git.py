from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    base_commit: str = ""
    head_commit: str = ""
    changed_files: List[str] = field(default_factory=list)
    added_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    diff_content: str = ""


class GitHelper:
    def __init__(self, repo_path: str | Path):
        self.repo_path = Path(repo_path).resolve()
        if not (self.repo_path / ".git").exists():
            raise ValueError(f"不是git仓库: {self.repo_path}")

    def _run_git(self, *args: str) -> str:
        cmd = ["git", "-C", str(self.repo_path)] + list(args)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                logger.warning(f"git命令失败: {' '.join(cmd)}, stderr={result.stderr.strip()}")
                return ""
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"git命令超时: {' '.join(cmd)}")
            return ""
        except Exception as e:
            logger.error(f"git命令异常: {e}")
            return ""

    def get_current_branch(self) -> str:
        return self._run_git("rev-parse", "--abbrev-ref", "HEAD")

    def get_head_commit(self) -> str:
        return self._run_git("rev-parse", "HEAD")

    def get_merge_base(self, branch: str = "main") -> str:
        return self._run_git("merge-base", branch, "HEAD")

    def get_changed_files(
        self, base: str = "HEAD~1", head: str = "HEAD",
        extensions: Optional[List[str]] = None,
    ) -> DiffResult:
        result = DiffResult(base_commit=base, head_commit=head)

        name_status = self._run_git("diff", "--name-status", f"{base}...{head}")
        if not name_status:
            logger.info(f"无差异: {base}...{head}")
            return result

        source_exts = extensions or [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
            ".rb", ".php", ".c", ".cpp", ".h", ".rs", ".kt", ".swift",
        ]

        for line in name_status.split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            status, filepath = parts
            ext = Path(filepath).suffix.lower()
            if ext not in source_exts:
                continue

            result.changed_files.append(filepath)
            if status.startswith("A"):
                result.added_files.append(filepath)
            elif status.startswith("M"):
                result.modified_files.append(filepath)
            elif status.startswith("D"):
                result.deleted_files.append(filepath)

        result.diff_content = self._run_git("diff", f"{base}...{head}")
        logger.info(
            f"增量扫描: {base}...{head}, "
            f"changed={len(result.changed_files)}, "
            f"added={len(result.added_files)}, "
            f"modified={len(result.modified_files)}, "
            f"deleted={len(result.deleted_files)}"
        )
        return result

    def get_file_at_commit(self, filepath: str, commit: str = "HEAD") -> Optional[str]:
        content = self._run_git("show", f"{commit}:{filepath}")
        return content if content else None

    def get_blame(self, filepath: str) -> str:
        return self._run_git("blame", filepath)

    def list_commits(self, base: str = "HEAD~10", head: str = "HEAD") -> List[dict]:
        log = self._run_git(
            "log", "--oneline", "--format=%H|%s|%an|%ai", f"{base}..{head}"
        )
        if not log:
            return []
        commits = []
        for line in log.split("\n"):
            parts = line.split("|", 3)
            if len(parts) >= 4:
                commits.append({
                    "hash": parts[0], "subject": parts[1],
                    "author": parts[2], "date": parts[3],
                })
        return commits
