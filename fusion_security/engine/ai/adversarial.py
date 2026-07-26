from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...models.vulnerability import Vulnerability
from .analyzer import AIAnalyzer

logger = logging.getLogger(__name__)


class AdversarialVerifier:
    def __init__(self, ai_analyzer: AIAnalyzer, rounds: int = 2):
        self.ai = ai_analyzer
        self.rounds = rounds

    async def verify(self, vuln: Vulnerability, files: List[Path]) -> Tuple[bool, float, str]:
        attack_result = await self._attack(vuln)
        if not attack_result.get("is_exploitable", False):
            logger.debug(f"攻击代理判定不可利用: {vuln.id}")
            return False, 0.0, "攻击代理判定不可利用"

        defense_result = await self._defend(vuln, attack_result)
        if defense_result.get("refuted", False):
            logger.debug(f"防御代理反驳成功: {vuln.id}")
            return False, 0.0, f"防御反驳: {defense_result.get('reason', '')}"

        confidence = self._compute_confidence(attack_result, defense_result)
        exploit = attack_result.get("exploit", "")
        logger.info(f"对抗验证通过: {vuln.id}, confidence={confidence}")
        return True, confidence, exploit

    async def verify_batch(self, vulns: List[Vulnerability],
                           files: List[Path]) -> List[Vulnerability]:
        verified = []
        for vuln in vulns:
            try:
                is_real, confidence, exploit = await self.verify(vuln, files)
                if is_real:
                    vuln.verified = True
                    vuln.confidence = confidence
                    vuln.data_flow_path = exploit
                    verified.append(vuln)
                else:
                    logger.debug(f"对抗验证过滤: {vuln.id}")
            except Exception as e:
                logger.warning(f"对抗验证异常 {vuln.id}: {e}")
                verified.append(vuln)
        return verified

    async def _attack(self, vuln: Vulnerability) -> Dict[str, Any]:
        prompt = f"""你是攻击代理。你的任务是证明以下漏洞可以被真实利用。

漏洞: {vuln.title}
描述: {vuln.description}
CWE: {vuln.cwe_id}
文件: {vuln.file_path}:{vuln.line_number}
代码:
```
{vuln.code_snippet[:1500]}
```

请回答：
1. 攻击者能否利用此漏洞？给出具体攻击路径。
2. 利用难度(0-1, 0=极易)。
3. 影响范围(0-1)。

只返回JSON: {{"is_exploitable": true/false, "exploit": "具体攻击路径", "difficulty": 0.0-1.0, "impact": 0.0-1.0, "reason": "..."}}"""

        response = await self.ai._chat([
            {"role": "system", "content": "你是安全攻击专家，寻找漏洞利用路径。"},
            {"role": "user", "content": prompt},
        ])
        return self.ai._parse_json(response) or {"is_exploitable": False}

    async def _defend(self, vuln: Vulnerability,
                      attack_result: Dict[str, Any]) -> Dict[str, Any]:
        prompt = f"""你是防御代理。你的任务是反驳以下漏洞利用。

漏洞: {vuln.title}
描述: {vuln.description}
CWE: {vuln.cwe_id}
文件: {vuln.file_path}:{vuln.line_number}
代码:
```
{vuln.code_snippet[:1500]}
```

攻击者声称: {attack_result.get('exploit', '')}
攻击理由: {attack_result.get('reason', '')}

请反驳：
1. 这个攻击路径是否可行？是否有防护措施阻止？
2. 是否存在误判（如测试代码、开发配置、已有防护）？

只返回JSON: {{"refuted": true/false, "reason": "反驳理由", "defense": "具体防护说明"}}"""

        response = await self.ai._chat([
            {"role": "system", "content": "你是安全防御专家，寻找反驳漏洞利用的证据。"},
            {"role": "user", "content": prompt},
        ])
        return self.ai._parse_json(response) or {"refuted": False}

    def _compute_confidence(self, attack: Dict, defense: Dict) -> int:
        difficulty = attack.get("difficulty", 0.5)
        impact = attack.get("impact", 0.5)
        base_confidence = (1 - difficulty) * 0.4 + impact * 0.4 + 0.2

        if defense.get("refuted", False):
            base_confidence *= 0.3

        return int(round(min(1.0, max(0.1, base_confidence)) * 100))
