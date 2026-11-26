from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ...models.vulnerability import Vulnerability
from .analyzer import AIAnalyzer

logger = logging.getLogger(__name__)


class AdversarialVerifier:
    def __init__(self, ai_analyzer: AIAnalyzer, rounds: int = 2):
        self.ai = ai_analyzer
        self.rounds = rounds

    async def verify(self, vuln: Vulnerability, files: list[Path]) -> tuple[bool, float, str]:
        attack_result = await self._attack(vuln)
        if not attack_result.get("is_exploitable", False):
            logger.debug(f"attack agent judged not exploitable: {vuln.id}")
            return False, 0.0, "attack agent judged not exploitable"

        defense_result = await self._defend(vuln, attack_result)
        if defense_result.get("refuted", False):
            logger.debug(f"defense agent refutation succeeded: {vuln.id}")
            return False, 0.0, f"defense refutation: {defense_result.get('reason', '')}"

        confidence = self._compute_confidence(attack_result, defense_result)
        exploit = attack_result.get("exploit", "")
        logger.info(f"adversarial verification passed: {vuln.id}, confidence={confidence}")
        return True, confidence, exploit

    async def verify_batch(self, vulns: list[Vulnerability], files: list[Path]) -> list[Vulnerability]:
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
                    logger.debug(f"adversarial verification filtered: {vuln.id}")
            except Exception as e:
                logger.warning(f"adversarial verification exception {vuln.id}: {e}")
                verified.append(vuln)
        return verified

    async def _attack(self, vuln: Vulnerability) -> dict[str, Any]:
        prompt = f"""You are the attack agent. Your task is to prove that the following vulnerability can be exploited for real.

Vulnerability: {vuln.title}
Description: {vuln.description}
CWE: {vuln.cwe_id}
File: {vuln.file_path}:{vuln.line_number}
Code:
```
{vuln.code_snippet[:1500]}
```

Answer:
1. Can an attacker exploit this vulnerability? Give a concrete attack path.
2. Exploitation difficulty (0-1, 0 = trivially easy).
3. Impact scope (0-1).

Return JSON only: {{"is_exploitable": true/false, "exploit": "concrete attack path", "difficulty": 0.0-1.0, "impact": 0.0-1.0, "reason": "..."}}"""

        response = await self.ai._chat(
            [
                {
                    "role": "system",
                    "content": "You are a security attack expert looking for vulnerability exploit paths.",
                },
                {"role": "user", "content": prompt},
            ]
        )
        parsed = self.ai._parse_json(response)
        if not parsed:
            logger.warning(f"attack agent response parse failed, fail-closed keeps the vulnerability: {vuln.id}")
            return {
                "is_exploitable": True,
                "exploit": "AI parse failure",
                "difficulty": 0.5,
                "impact": 0.5,
                "reason": "AI unavailable or parse failed, conservatively kept",
            }
        return parsed

    async def _defend(self, vuln: Vulnerability, attack_result: dict[str, Any]) -> dict[str, Any]:
        prompt = f"""You are the defense agent. Your task is to refute the following exploitation.

Vulnerability: {vuln.title}
Description: {vuln.description}
CWE: {vuln.cwe_id}
File: {vuln.file_path}:{vuln.line_number}
Code:
```
{vuln.code_snippet[:1500]}
```

Attacker claims: {attack_result.get("exploit", "")}
Attack reasoning: {attack_result.get("reason", "")}

Refute:
1. Is this attack path feasible? Are there protections that block it?
2. Is there a misjudgment (e.g. test code, dev configuration, existing protection)?

Return JSON only: {{"refuted": true/false, "reason": "refutation reason", "defense": "concrete protection note"}}"""

        response = await self.ai._chat(
            [
                {
                    "role": "system",
                    "content": "You are a security defense expert looking for evidence that refutes the exploitation.",
                },
                {"role": "user", "content": prompt},
            ]
        )
        return self.ai._parse_json(response) or {"refuted": False}

    def _compute_confidence(self, attack: dict, defense: dict) -> int:
        difficulty = attack.get("difficulty", 0.5)
        impact = attack.get("impact", 0.5)
        base_confidence = (1 - difficulty) * 0.4 + impact * 0.4 + 0.2

        if defense.get("refuted", False):
            base_confidence *= 0.3

        return int(round(min(1.0, max(0.1, base_confidence)) * 100))
