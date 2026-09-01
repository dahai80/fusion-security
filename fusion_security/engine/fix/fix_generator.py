from __future__ import annotations

import logging
import re
from pathlib import Path

from ...models.patch import Patch
from ...models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class FixGenerator:
    def __init__(self, ai_analyzer=None):
        self.ai_analyzer = ai_analyzer

    def generate_fix(self, vuln: Vulnerability) -> Patch:
        original = self._extract_context(vuln)
        patched = self._apply_template_fix(vuln, original)

        if not patched or patched == original:
            patched = f"// TODO: 修复 {vuln.title}\n// {vuln.description}\n// CWE: {vuln.cwe_id}\n{original}"

        p = Patch()
        p.vuln_id = vuln.id
        p.original_code = original
        p.patched_code = patched
        p.description = f"修复 {vuln.title}: {vuln.description}"
        p.strategy = "template"
        return p

    def generate_alternatives(self, vuln: Vulnerability, max_strategies: int = 3) -> list[Patch]:
        original = self._extract_context(vuln)
        strategies = self._get_all_strategies(vuln, original)
        patches = []
        for strategy_name, patched_code in strategies[:max_strategies]:
            if not patched_code or patched_code == original:
                continue
            p = Patch()
            p.vuln_id = vuln.id
            p.original_code = original
            p.patched_code = patched_code
            p.description = f"修复 {vuln.title} ({strategy_name}): {vuln.description}"
            p.strategy = strategy_name
            patches.append(p)
        if not patches:
            p = Patch()
            p.vuln_id = vuln.id
            p.original_code = original
            p.patched_code = f"// TODO: 修复 {vuln.title}\n// {vuln.description}\n{original}"
            p.description = f"修复 {vuln.title}: {vuln.description}"
            p.strategy = "placeholder"
            patches.append(p)
        logger.info(f"生成 {len(patches)} 个修复方案: vuln={vuln.id}")
        return patches

    def _get_all_strategies(self, vuln: Vulnerability, code: str) -> list[tuple]:
        strategies = []
        template = self._apply_template_fix(vuln, code)
        if template and template != code:
            strategies.append(("template", template))
        safe_api = self._apply_safe_api_fix(vuln, code)
        if safe_api and safe_api != code and safe_api != template:
            strategies.append(("safe_api", safe_api))
        validation = self._apply_validation_fix(vuln, code)
        if validation and validation != code and validation not in [s[1] for s in strategies]:
            strategies.append(("validation", validation))
        return strategies

    def _apply_safe_api_fix(self, vuln: Vulnerability, code: str) -> str:
        safe_fixes = {
            "SQL001": code.replace("execute(", "execute_query(") + "\n# 使用参数化查询代替字符串拼接"
            if "execute(" in code
            else "",
            "CMD001": code.replace("os.system(", "subprocess.run(shlex.split(") + ", check=True)"
            if "os.system(" in code
            else "",
            "XSS001": code.replace("innerHTML", "textContent") + "\n// 使用textContent避免XSS"
            if "innerHTML" in code
            else "",
            "EVAL001": code.replace("eval(", "ast.literal_eval(") if "eval(" in code else "",
        }
        return safe_fixes.get(vuln.rule_id, "")

    def _apply_validation_fix(self, vuln: Vulnerability, code: str) -> str:
        validation_fixes = {
            "SQL001": "if not re.match(r'^[a-zA-Z0-9_]+$', user_input):\n    raise ValueError('Invalid input')\n" + code
            if "execute(" in code
            else "",
            "CMD001": "if not re.match(r'^[a-zA-Z0-9_\\-]+$', cmd_arg):\n    raise ValueError('Invalid command argument')\n"
            + code
            if "os.system(" in code
            else "",
            "SSRF001": "if not url.startswith(('https://api.', 'https://trusted.')):\n    raise ValueError('URL not allowed')\n"
            + code
            if "requests.get" in code
            else "",
        }
        return validation_fixes.get(vuln.rule_id, "")

    def _extract_context(self, vuln: Vulnerability) -> str:
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
        fixes = {
            "SQL001": code.replace("execute(", "execute_query(") if "execute(" in code else "",
            "CMD001": code.replace("os.system(", "subprocess.run(") if "os.system(" in code else "",
            "XSS001": code.replace("innerHTML", "textContent") if "innerHTML" in code else "",
            "SEC001": self._fix_hardcoded_secret(code),
        }
        return fixes.get(vuln.rule_id, "")

    def _fix_hardcoded_secret(self, code: str) -> str:
        pattern = re.compile(r'(\w+)\s*=\s*"([^"]+)"')
        match = pattern.search(code)
        if not match:
            return ""
        var_name = match.group(1)
        return pattern.sub(f'{var_name} = os.environ.get("{var_name}", "")', code, count=1)

    async def ai_enhance_fix(self, patch: Patch) -> Patch:
        if not self.ai_analyzer:
            return patch
        try:
            from ...models.vulnerability import Vulnerability

            dummy_vuln = Vulnerability(
                id=patch.vuln_id,
                title="",
                description=patch.description,
                severity="medium",
                confidence=80,
                file_path="",
                line_number=0,
                code_snippet=patch.original_code,
            )
            enhanced = await self.ai_analyzer.generate_fix(dummy_vuln)
        except Exception as e:
            logger.warning(f"AI 修复增强失败, 保留模板补丁 {patch.vuln_id}: {e}")
            return patch

        # AI 可能返回失败标记串 (generate_fix 异常时返回 "// 修复生成失败: ...")，
        # 不得直接当作补丁内容落库。校验通过才采用，否则保留模板补丁。
        if not enhanced or not self._is_valid_ai_patch(enhanced, patch.original_code):
            logger.warning(f"AI 补丁内容非法或无效, 保留模板补丁 {patch.vuln_id}")
            return patch

        patch.patched_code = enhanced
        patch.strategy = "ai_enhanced"
        # AI 生成的补丁存在幻觉风险，必须标记人工审核后方可应用
        patch.needs_review = True
        logger.info(f"AI 增强补丁生成 (需人工审核) {patch.vuln_id}")
        return patch

    @staticmethod
    def _is_valid_ai_patch(candidate: str, original: str) -> bool:
        if not candidate or len(candidate) < 6:
            return False
        # 拒绝 generate_fix 的失败标记串
        if candidate.lstrip().startswith("// 修复生成失败"):
            return False
        # AI 返回原样未改动，无修复价值
        if candidate.strip() == original.strip():
            return False
        # 纯解释性输出 (无代码行) 风险高，拒绝：需含换行或任一代码结构字符。
        stripped = candidate.strip()
        return "\n" in stripped or any(c in stripped for c in ("{", "(", "=", ";", "<"))
