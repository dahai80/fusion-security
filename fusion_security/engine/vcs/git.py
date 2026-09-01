from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


class GitNotInstalledError(RuntimeError):
    pass


class GitArgError(ValueError):
    pass


def _validate_rev(rev: str) -> str:
    if not rev or rev.startswith("-"):
        raise GitArgError(f"非法 git rev: {rev!r}")
    return rev


def _validate_path_arg(path_arg: str) -> str:
    if not path_arg or path_arg.startswith("-"):
        raise GitArgError(f"非法 git path: {path_arg!r}")
    return path_arg


def _resolve_rev(helper, rev: str) -> str:
    rev = _validate_rev(rev)
    verified = helper._run_git("rev-parse", "--verify", f"{rev}^{{commit}}")
    if not verified:
        raise GitArgError(f"无法解析的 git rev: {rev!r}")
    return verified


@dataclass
class DiffResult:
    base_commit: str = ""
    head_commit: str = ""
    changed_files: list[str] = field(default_factory=list)
    added_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    diff_content: str = ""


class GitHelper:
    def __init__(self, repo_path: str | Path):
        self.repo_path = Path(repo_path).resolve()
        if not (self.repo_path / ".git").exists():
            raise ValueError(f"不是git仓库: {self.repo_path}")

    def _run_git(self, *args: str) -> str:
        if shutil.which("git") is None:
            # git 未安装时 subprocess.run 抛 FileNotFoundError,被下方 Exception 吞掉返回 "",
            # 调用方误判为"无法解析的 git rev"。显式检测并抛出明确错误。
            logger.error("git 未安装,无法执行 git 命令")
            raise GitNotInstalledError("git 未安装,请先安装 git CLI")
        cmd = ["git", "-C", str(self.repo_path)] + list(args)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning(f"git命令失败: {' '.join(cmd)}, stderr={result.stderr.strip()}")
                return ""
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"git命令超时: {' '.join(cmd)}")
            return ""
        except FileNotFoundError as e:
            logger.error(f"git 可执行文件不存在: {e}")
            raise GitNotInstalledError("git 未安装") from e
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
        self,
        base: str = "HEAD~1",
        head: str = "HEAD",
        extensions: list[str] | None = None,
    ) -> DiffResult:
        result = DiffResult(base_commit=base, head_commit=head)

        base_sha = _resolve_rev(self, base)
        head_sha = _resolve_rev(self, head)
        name_status = self._run_git("diff", "--name-status", f"{base_sha}...{head_sha}")
        if not name_status:
            logger.info(f"无差异: {base}...{head}")
            return result

        source_exts = extensions or [
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".c",
            ".cpp",
            ".h",
            ".rs",
            ".kt",
            ".swift",
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

        result.diff_content = self._run_git("diff", f"{base_sha}...{head_sha}")
        logger.info(
            f"增量扫描: {base}...{head}, "
            f"changed={len(result.changed_files)}, "
            f"added={len(result.added_files)}, "
            f"modified={len(result.modified_files)}, "
            f"deleted={len(result.deleted_files)}"
        )
        return result

    def get_file_at_commit(self, filepath: str, commit: str = "HEAD") -> str | None:
        commit_sha = _resolve_rev(self, commit)
        _validate_path_arg(filepath)
        content = self._run_git("show", f"{commit_sha}:{filepath}")
        return content if content else None

    def get_blame(self, filepath: str) -> str:
        _validate_path_arg(filepath)
        return self._run_git("blame", "--", filepath)

    def list_commits(self, base: str = "HEAD~10", head: str = "HEAD") -> list[dict]:
        base_sha = _resolve_rev(self, base)
        head_sha = _resolve_rev(self, head)
        log = self._run_git("log", "--oneline", "--format=%H|%s|%an|%ai", f"{base_sha}..{head_sha}")
        if not log:
            return []
        commits = []
        for line in log.split("\n"):
            parts = line.split("|", 3)
            if len(parts) >= 4:
                commits.append(
                    {
                        "hash": parts[0],
                        "subject": parts[1],
                        "author": parts[2],
                        "date": parts[3],
                    }
                )
        return commits
