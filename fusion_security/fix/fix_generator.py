"""修复补丁生成器 — 为漏洞生成可落地的修复代码。"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

from ..models import Vulnerability

logger = logging.getLogger(__name__)


class FixPatch:
    """修复补丁定义。"""
    def __init__(self, vuln: Vulnerability, original: str, patched: str):
        self.vuln = vuln
        self.original = original
        self.patched = patched
        self.applied = False

    def to_diff(self) -> str:
        """生成 diff 格式。"""
        lines = [
            f"--- a/{self.vuln.file_path}",
            f"+++ b/{self.vuln.file_path}",
            f"@@ -{self.vuln.line_number} +{self.vuln.line_number} @@",
        ]
        for line in self.original.split("\n"):
            lines.append(f"-{line}")
        for line in self.patched.split("\n"):
            lines.append(f"+{line}")
        return "\n".join(lines)


class FixGenerator:
    """修复补丁生成器 — 为漏洞生成修复代码。

    对标 Claude Security 的一键生成修复补丁能力。
    """

    def __init__(self, ai_analyzer=None):
        self.ai_analyzer = ai_analyzer

    def generate_fix(self, vuln: Vulnerability) -> FixPatch:
        """生成修复补丁。

        先尝试模板修复，然后 AI 优化。
        """
        original = self._extract_context(vuln)
        patched = self._apply_template_fix(vuln, original)

        if not patched or patched == original:
            patched = f"// TODO: 修复 {vuln.title}\n// {vuln.description}\n// CWE: {vuln.cwe_id}\n{original}"

        return FixPatch(vuln=vuln, original=original, patched=patched)

    def _extract_context(self, vuln: Vulnerability) -> str:
        """提取漏洞上下文。"""
        try:
            path = Path(vuln.file_path)
            if path.exists():
                lines = path.read_text(encoding="utf-8", errors="ignore").split("\n")
                start = max(0, vuln.line_number - 2)
                end = min(len(lines), vuln.line_number + 2)
                return "\n".join(lines[start:end])
        except Exception:
            pass
        return vuln.code_snippet

    def _apply_template_fix(self, vuln: Vulnerability, code: str) -> str:
        """应用模板修复。"""
        fixes = {
            "SQL001": code.replace("execute(", "execute_query(") if "execute(" in code else "",
            "CMD001": code.replace("os.system(", "subprocess.run(") if "os.system(" in code else "",
            "XSS001": code.replace("innerHTML", "textContent") if "innerHTML" in code else "",
            "SEC001": code.replace("= \"", "= os.environ.get(\"", 1) + "\", \"\")" if "= \"" in code else "",
        }
        return fixes.get(vuln.rule_id, "")

    async def ai_enhance_fix(self, patch: FixPatch) -> FixPatch:
        """使用 AI 增强修复补丁。"""
        if self.ai_analyzer:
            try:
                enhanced = await self.ai_analyzer.generate_fix(patch.vuln)
                if enhanced and len(enhanced) > 5:
                    patch.patched = enhanced
            except Exception as e:
                logger.warning(f"AI 修复增强失败: {e}")
        return patch