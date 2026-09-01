from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ...models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class JiraConfig:
    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str = "Bug"
    labels: list[str] = field(default_factory=lambda: ["security"])
    custom_fields: dict[str, str] = field(default_factory=dict)


@dataclass
class JiraIssue:
    key: str
    summary: str
    status: str
    url: str


SEVERITY_JIRA_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


class JiraClient:
    def __init__(self, config: JiraConfig):
        self.config = config
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=f"{self.config.base_url.rstrip('/')}/rest/api/2",
                auth=(self.config.email, self.config.api_token),
                timeout=30.0,
            )
        return self._client

    def create_issue(self, vuln: Vulnerability) -> JiraIssue | None:
        priority = SEVERITY_JIRA_PRIORITY.get(vuln.severity, "Medium")
        summary = f"[Security] {vuln.severity.upper()}: {vuln.title}"
        description = self._build_description(vuln)
        fields: dict[str, Any] = {
            "project": {"key": self.config.project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": self.config.issue_type},
            "priority": {"name": priority},
            "labels": self.config.labels,
        }
        fields.update(self.config.custom_fields)
        try:
            resp = self.client.post("/issue", json={"fields": fields})
            if resp.status_code == 201:
                data = resp.json()
                key = data.get("key", "")
                url = f"{self.config.base_url}/browse/{key}"
                logger.info(f"[Jira] 创建工单: {key} for vuln {vuln.id}")
                return JiraIssue(key=key, summary=summary, status="Open", url=url)
            else:
                logger.warning(f"[Jira] 创建工单失败: HTTP {resp.status_code} {resp.text[:200]}")
                return None
        except Exception as e:
            logger.warning(f"[Jira] 创建工单异常: {e}")
            return None

    def create_issues_batch(self, vulns: list[Vulnerability]) -> list[JiraIssue]:
        issues = []
        for vuln in vulns:
            issue = self.create_issue(vuln)
            if issue:
                issues.append(issue)
        logger.info(f"[Jira] 批量创建 {len(issues)}/{len(vulns)} 个工单")
        return issues

    def get_issue(self, issue_key: str) -> JiraIssue | None:
        try:
            resp = self.client.get(f"/issue/{issue_key}", params={"fields": "summary,status"})
            if resp.status_code == 200:
                data = resp.json()
                return JiraIssue(
                    key=data.get("key", issue_key),
                    summary=data.get("fields", {}).get("summary", ""),
                    status=data.get("fields", {}).get("status", {}).get("name", ""),
                    url=f"{self.config.base_url}/browse/{issue_key}",
                )
        except Exception as e:
            logger.warning(f"[Jira] 获取工单失败 {issue_key}: {e}")
        return None

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> JiraClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _build_description(self, vuln: Vulnerability) -> str:
        parts = [
            f"h2. {vuln.title}",
            f"*Severity:* {vuln.severity.upper()}",
            f"*CWE:* {vuln.cwe_id}",
            f"*Rule ID:* {vuln.rule_id}",
            f"*File:* {vuln.file_path}:{vuln.line_number}",
            "",
            "h3. Description",
            vuln.description,
            "",
            "h3. Code Snippet",
            "{code}",
            vuln.code_snippet[:500],
            "{code}",
            "",
            "h3. Fix Suggestion",
            vuln.fix_suggestion or "N/A",
        ]
        if vuln.confidence:
            parts.append(f"\n*Confidence:* {vuln.confidence}%")
        return "\n".join(parts)
