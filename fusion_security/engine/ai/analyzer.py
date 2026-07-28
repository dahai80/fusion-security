from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from ...models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class AIAnalyzer:
    def __init__(self, model: str = "", mlx_url: str = "http://localhost:8000/v1"):
        self.model = model
        self.mlx_url = mlx_url.rstrip("/")
        self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    async def aclose(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            logger.info("[AIAnalyzer] httpx client closed")

    @property
    def client(self):
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(base_url=self.mlx_url, timeout=120.0)
        return self._client

    async def _chat(self, messages: list[dict]) -> str:
        if not self.model:
            try:
                models = await self.client.get("/models")
                data = models.json()
                available = data.get("data", [])
                if available:
                    self.model = available[0].get("id", available[0].get("model", ""))
            except Exception:
                self.model = "qwen3.5-9b"

        payload = {
            "model": self.model or "qwen3.5-9b",
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 2048,
        }
        resp = await self.client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def verify_findings(
        self,
        findings: list[Vulnerability],
        files: list[Path],
    ) -> list[Vulnerability]:
        if not findings:
            return findings

        verified = []
        for vuln in findings:
            prompt = f"""你是一个安全专家。请验证以下代码是否存在真实的安全漏洞。

漏洞类型: {vuln.title}
漏洞描述: {vuln.description}
CWE编号: {vuln.cwe_id}
文件路径: {vuln.file_path}
代码片段:
```
{vuln.code_snippet[:1000]}
```

请回答：
1. 这是真实的漏洞还是误报？
2. 如果是真实漏洞，攻击者如何利用？
3. 请给出置信度评分(0-100的整数)

只返回JSON格式：{{"is_real": true/false, "reason": "...", "confidence": 0-100, "exploit": "..."}}"""
            try:
                response = await self._chat(
                    [
                        {"role": "system", "content": "你是一个代码安全专家。严格验证漏洞是否真实存在。"},
                        {"role": "user", "content": prompt},
                    ]
                )
                result = self._parse_json(response)
                if result and result.get("is_real", False):
                    vuln.verified = True
                    ai_conf = result.get("confidence", vuln.confidence)
                    if isinstance(ai_conf, float) and ai_conf <= 1.0:
                        ai_conf = int(round(ai_conf * 100))
                    vuln.confidence = ai_conf
                    verified.append(vuln)
                else:
                    logger.debug(f"AI 过滤误报: {vuln.id}")
            except Exception as e:
                logger.warning(f"AI 验证失败 {vuln.id}: {e}")
                verified.append(vuln)

        return verified

    async def semantic_scan(self, files: list[Path]) -> list[Vulnerability]:
        if not files:
            return []

        from ...engine.rules.engine import AI_SEMANTIC_RULES

        code_summary = []
        for f in files[:5]:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")[:2000]
                code_summary.append(f"--- {f.name} ---\n{content[:500]}")
            except Exception:
                pass

        if not code_summary:
            return []

        rule_hints = "\n".join(f"- {r.prdid} {r.name}: {r.prompt_hint}" for r in AI_SEMANTIC_RULES)

        prompt = f"""你是一个安全专家。分析以下代码，找出潜在的逻辑安全漏洞。

分析要点（按优先级）：
{rule_hints}

额外检查：
- 权限检查是否缺失
- 数据验证是否充分
- 多文件之间的信任关系是否安全

代码：
{chr(10).join(code_summary)}

只返回JSON数组格式，每项包含：title, description, severity(critical/high/medium/low), file, line, confidence, rule_id(使用FUS-XXX-NNN格式)
若无漏洞返回空数组 []"""

        try:
            response = await self._chat(
                [
                    {"role": "system", "content": "你是一个代码安全专家。分析代码中的逻辑漏洞。"},
                    {"role": "user", "content": prompt},
                ]
            )
            results = self._parse_json(response, as_array=True)
            findings = []
            for r in results:
                prdid = r.get("rule_id", "")
                rule_id = "AI_SEMANTIC"
                fix = ""
                for ar in AI_SEMANTIC_RULES:
                    if ar.prdid == prdid or ar.id == prdid:
                        rule_id = ar.id
                        fix = ar.fix_template
                        break
                vuln = Vulnerability(
                    id=f"AI_{uuid.uuid4().hex[:8]}",
                    title=r.get("title", "未知逻辑漏洞"),
                    description=r.get("description", ""),
                    severity=r.get("severity", "medium"),
                    confidence=r.get("confidence", 70),
                    file_path=r.get("file", str(files[0])),
                    line_number=r.get("line", 0),
                    code_snippet="[AI 语义分析发现]",
                    rule_id=rule_id,
                    cwe_id="CWE-000",
                    fix_suggestion=fix,
                    verified=True,
                )
                findings.append(vuln)
            return findings
        except Exception as e:
            logger.warning(f"AI 语义扫描失败: {e}")
            return []

    async def generate_fix(self, vuln: Vulnerability) -> str:
        prompt = f"""修复以下代码安全漏洞：

漏洞类型: {vuln.title}
漏洞描述: {vuln.description}
CWE编号: {vuln.cwe_id}
文件: {vuln.file_path}:{vuln.line_number}
代码:
```
{vuln.code_snippet[:1500]}
```

请生成修复后的代码，只返回代码本身，不要解释。"""
        try:
            return await self._chat(
                [
                    {"role": "system", "content": "你是一个安全修复专家。生成修复代码，只返回代码。"},
                    {"role": "user", "content": prompt},
                ]
            )
        except Exception as e:
            return f"// 修复生成失败: {e}"

    def _parse_json(self, text: str, as_array: bool = False) -> Any:
        text = text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        try:
            result = json.loads(text)
            if as_array:
                return result if isinstance(result, list) else []
            return result if isinstance(result, dict) else None
        except json.JSONDecodeError:
            return [] if as_array else None
