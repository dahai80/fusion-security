"""AI 语义分析层 — 通过 fusion-mlx 进行漏洞验证和逻辑漏洞发现。

对标 Claude Security 的 AI 语义理解能力：
- 多层校验降低误报
- 跨文件逻辑漏洞发现
- 数据流追踪
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..rules.engine import Vulnerability

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """AI 分析器 — 通过 fusion-mlx 进行安全分析。

    所有推理通过 HTTP 调用 fusion-mlx，不直接导入 MLX 代码。
    100% 本地离线，零代码上传。
    """

    def __init__(self, model: str = "", mlx_url: str = "http://localhost:8000/v1"):
        self.model = model
        self.mlx_url = mlx_url.rstrip("/")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(base_url=self.mlx_url, timeout=120.0)
        return self._client

    async def _chat(self, messages: List[Dict]) -> str:
        """调用 fusion-mlx 聊天接口。"""
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
        findings: List[Vulnerability],
        files: List[Path],
    ) -> List[Vulnerability]:
        """AI 验证漏洞发现 — 降低误报。

        对抗式自验证：模型反向验证漏洞是否真实存在，自动过滤假阳性。
        """
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
3. 请给出置信度评分(0-1)

只返回JSON格式：{{"is_real": true/false, "reason": "...", "confidence": 0.0-1.0, "exploit": "..."}}"""
            try:
                response = await self._chat([
                    {"role": "system", "content": "你是一个代码安全专家。严格验证漏洞是否真实存在。"},
                    {"role": "user", "content": prompt},
                ])
                result = self._parse_json(response)
                if result and result.get("is_real", False):
                    vuln.verified = True
                    vuln.confidence = result.get("confidence", vuln.confidence)
                    verified.append(vuln)
                else:
                    logger.debug(f"AI 过滤误报: {vuln.id}")
            except Exception as e:
                logger.warning(f"AI 验证失败 {vuln.id}: {e}")
                verified.append(vuln)  # 验证失败时保留原结果

        return verified

    async def semantic_scan(self, files: List[Path]) -> List[Vulnerability]:
        """AI 语义扫描 — 发现传统规则无法识别的逻辑漏洞。

        跨文件追踪数据流、信任边界、输入输出，发现多文件联动漏洞。
        """
        if not files:
            return []

        # 读取关键文件进行语义分析
        code_summary = []
        for f in files[:5]:  # 限制文件数避免超长上下文
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")[:2000]
                code_summary.append(f"--- {f.name} ---\n{content[:500]}")
            except Exception:
                pass

        if not code_summary:
            return []

        prompt = f"""你是一个安全专家。分析以下代码，找出潜在的逻辑安全漏洞。

分析要点：
- 权限检查是否缺失
- 数据验证是否充分
- 业务逻辑是否存在绕过风险
- 多文件之间的信任关系是否安全

代码：
{chr(10).join(code_summary)}

只返回JSON数组格式，每项包含：title, description, severity(critical/high/medium/low), file, line, confidence
若无漏洞返回空数组 []"""

        try:
            response = await self._chat([
                {"role": "system", "content": "你是一个代码安全专家。分析代码中的逻辑漏洞。"},
                {"role": "user", "content": prompt},
            ])
            results = self._parse_json_array(response)
            findings = []
            for r in results:
                vuln = Vulnerability(
                    id=f"AI_{hash(r.get('title', '')) % 10000}",
                    title=r.get("title", "未知逻辑漏洞"),
                    description=r.get("description", ""),
                    severity=r.get("severity", "medium"),
                    confidence=r.get("confidence", 0.7),
                    file_path=r.get("file", str(files[0])),
                    line_number=r.get("line", 0),
                    code_snippet="[AI 语义分析发现]",
                    rule_id="AI_SEMANTIC",
                    verified=True,
                )
                findings.append(vuln)
            return findings
        except Exception as e:
            logger.warning(f"AI 语义扫描失败: {e}")
            return []

    async def generate_fix(self, vuln: Vulnerability) -> str:
        """生成修复补丁。"""
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
            return await self._chat([
                {"role": "system", "content": "你是一个安全修复专家。生成修复代码，只返回代码。"},
                {"role": "user", "content": prompt},
            ])
        except Exception as e:
            return f"// 修复生成失败: {e}"

    def _parse_json(self, text: str) -> Optional[Dict]:
        """解析 JSON 响应。"""
        text = text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _parse_json_array(self, text: str) -> List[Dict]:
        """解析 JSON 数组响应。"""
        text = text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        try:
            result = json.loads(text)
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            return []