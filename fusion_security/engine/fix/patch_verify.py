"""Patch verification — validate generated patches before applying."""

from __future__ import annotations

import difflib
import logging
import re
from dataclasses import dataclass, field

from ...models.patch import Patch

logger = logging.getLogger(__name__)


@dataclass
class PatchVerifyResult:
    patch_id: str = ""
    is_valid: bool = False
    syntax_ok: bool = False
    diff_applies: bool = False
    errors: list = field(default_factory=list)


class PatchVerifier:
    def verify(self, patch: Patch, original_code: str = "") -> PatchVerifyResult:
        result = PatchVerifyResult(patch_id=patch.id)

        if not patch.diff_content and not patch.patched_code:
            result.errors.append("空补丁")
            return result

        patched = patch.patched_code
        if not patched and patch.diff_content:
            patched = self._apply_patch_text(original_code, patch.diff_content)
            if patched is None:
                result.errors.append("补丁无法应用")
                return result
            result.diff_applies = True

        syntax_ok = self._check_syntax(patched, "patched.py")
        result.syntax_ok = syntax_ok
        result.is_valid = len(result.errors) == 0
        return result

    def _apply_patch_text(self, original: str, diff_text: str) -> str | None:
        try:
            lines = original.splitlines(keepends=True)
            hunks = self._parse_unified_diff(diff_text)
            if not hunks:
                return None
            for hunk in reversed(hunks):
                start = hunk["old_start"] - 1
                count = hunk["old_count"]
                new_lines = hunk["new_lines"]
                lines[start : start + count] = new_lines
            return "".join(lines)
        except Exception as e:
            logger.debug(f"[PatchVerify] 应用补丁失败: {e}")
            return None

    def _parse_unified_diff(self, diff_text: str) -> list:
        hunks = []
        current = None
        for line in diff_text.splitlines():
            m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if m:
                if current:
                    hunks.append(current)
                current = {
                    "old_start": int(m.group(1)),
                    "old_count": int(m.group(2) or 1),
                    "new_start": int(m.group(3)),
                    "new_count": int(m.group(4) or 1),
                    "new_lines": [],
                }
                continue
            if current is None:
                continue
            if line.startswith("+") and not line.startswith("++") or line.startswith(" "):
                current["new_lines"].append(line[1:] + "\n")
        if current:
            hunks.append(current)
        return hunks

    def _check_syntax(self, code: str, filename: str = "") -> bool:
        if filename.endswith(".py"):
            try:
                compile(code, filename, "exec")
                return True
            except SyntaxError:
                return False
        return True

    def _generate_git_diff(self, original: str, patched: str, filename: str = "file") -> str:
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff)
