"""API routes for integrations — gate, SARIF, custom rules, feedback, dashboard."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...engine.ci.gate import GatePolicy, SecurityGate
from ...engine.dashboard import DashboardAggregator
from ...engine.feedback.loop import FeedbackEntry, FeedbackStore
from ...engine.rules.custom import CustomRule, CustomRuleStore
from ...engine.scoring.compliance import ComplianceMapper
from ...engine.scoring.cvss import CVSS31Scorer

logger = logging.getLogger(__name__)

router = APIRouter()

feedback_store = FeedbackStore()
custom_rule_store = CustomRuleStore()
dashboard = DashboardAggregator()


@router.post("/gate", summary="安全质量门禁")
async def evaluate_gate(vulnerabilities: list[dict[str, Any]], policy: str = "standard"):
    gate = SecurityGate(GatePolicy(policy))
    from ...models.vulnerability import Vulnerability

    vulns = []
    for v in vulnerabilities:
        vulns.append(
            Vulnerability(
                id=v.get("id", ""),
                title=v.get("title", ""),
                description=v.get("description", ""),
                severity=v.get("severity", "medium"),
                confidence=v.get("confidence", 50),
                file_path=v.get("file_path", ""),
                line_number=v.get("line_number", 0),
                code_snippet=v.get("code_snippet", ""),
                rule_id=v.get("rule_id", ""),
            )
        )
    result = gate.evaluate(vulns)
    return result.to_dict()


@router.post("/cvss", summary="CVSS 3.1 评分")
async def calculate_cvss(
    av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N", s: str = "U", c: str = "N", i: str = "N", a: str = "N"
):
    scorer = CVSS31Scorer()
    result = scorer.calculate(av, ac, pr, ui, s, c, i, a)
    return {"vector": result.vector, "base_score": result.base_score, "severity": result.severity}


@router.post("/compliance", summary="合规映射")
async def map_compliance(vulnerabilities: list[dict[str, Any]]):
    mapper = ComplianceMapper()
    from ...models.vulnerability import Vulnerability

    vulns = []
    for v in vulnerabilities:
        vulns.append(
            Vulnerability(
                id=v.get("id", ""),
                title=v.get("title", ""),
                description=v.get("description", ""),
                severity=v.get("severity", "medium"),
                confidence=50,
                file_path=v.get("file_path", ""),
                line_number=0,
                code_snippet="",
                rule_id=v.get("rule_id", ""),
            )
        )
    return mapper.map_vulnerabilities(vulns)


@router.post("/feedback", summary="提交误报反馈")
async def add_feedback(
    vuln_id: str, rule_id: str, file_path: str, line_number: int, is_false_positive: bool, reason: str = ""
):
    entry = FeedbackEntry(
        vuln_id=vuln_id,
        rule_id=rule_id,
        file_path=file_path,
        line_number=line_number,
        is_false_positive=is_false_positive,
        reason=reason,
    )
    feedback_store.add_feedback(entry)
    return {"status": "ok", "vuln_id": vuln_id}


@router.get("/feedback/stats", summary="反馈统计")
async def feedback_stats():
    return feedback_store.get_stats()


@router.post("/rules", summary="创建自定义规则")
async def create_custom_rule(id: str, name: str, pattern: str, severity: str = "medium", language: str = "*"):
    rule = CustomRule(id=id, name=name, pattern=pattern, severity=severity, language=language)
    custom_rule_store.add_rule(rule)
    return {"status": "ok", "rule_id": id}


@router.get("/rules", summary="列出自定义规则")
async def list_custom_rules(enabled_only: bool = False):
    rules = custom_rule_store.list_rules(enabled_only)
    return {
        "rules": [
            {"id": r.id, "name": r.name, "pattern": r.pattern, "severity": r.severity, "enabled": r.enabled}
            for r in rules
        ]
    }


@router.delete("/rules/{rule_id}", summary="删除自定义规则")
async def delete_custom_rule(rule_id: str):
    if custom_rule_store.delete_rule(rule_id):
        return {"status": "ok"}
    raise HTTPException(status_code=404, detail="规则不存在")


@router.get("/dashboard", summary="仪表盘统计")
async def dashboard_stats():
    stats = dashboard.get_stats()
    return stats.to_dict()


# ===== Webhook CRUD =====

_webhooks: dict[str, dict] = {}


@router.post("/webhooks", summary="创建Webhook")
async def create_webhook(url: str, events: list[str] = None, secret: str = ""):
    import uuid

    if events is None:
        events = ["scan.completed"]
    wid = uuid.uuid4().hex[:16]
    _webhooks[wid] = {"id": wid, "url": url, "events": events, "secret": secret, "enabled": True}
    logger.info(f"创建Webhook: {wid} -> {url}")
    return _webhooks[wid]


@router.get("/webhooks", summary="列出Webhooks")
async def list_webhooks():
    return {"webhooks": list(_webhooks.values())}


@router.get("/webhooks/{webhook_id}", summary="获取Webhook")
async def get_webhook(webhook_id: str):
    if webhook_id not in _webhooks:
        raise HTTPException(status_code=404, detail="Webhook不存在")
    return _webhooks[webhook_id]


class WebhookUpdate(BaseModel):
    url: str | None = None
    events: list[str] | None = None
    enabled: bool | None = None


@router.patch("/webhooks/{webhook_id}", summary="更新Webhook")
async def update_webhook(webhook_id: str, body: WebhookUpdate):
    if webhook_id not in _webhooks:
        raise HTTPException(status_code=404, detail="Webhook不存在")
    if body.url is not None:
        _webhooks[webhook_id]["url"] = body.url
    if body.events is not None:
        _webhooks[webhook_id]["events"] = body.events
    if body.enabled is not None:
        _webhooks[webhook_id]["enabled"] = body.enabled
    return _webhooks[webhook_id]


@router.delete("/webhooks/{webhook_id}", summary="删除Webhook")
async def delete_webhook(webhook_id: str):
    if webhook_id not in _webhooks:
        raise HTTPException(status_code=404, detail="Webhook不存在")
    del _webhooks[webhook_id]
    return {"status": "ok"}


# ===== Notification (Feishu / DingTalk) =====

_notification_dispatcher = None


def _get_dispatcher():
    global _notification_dispatcher
    if _notification_dispatcher is None:
        from ...engine.ci.notifier import NotificationDispatcher

        _notification_dispatcher = NotificationDispatcher()
    return _notification_dispatcher


class FeishuConfigModel(BaseModel):
    webhook_url: str
    secret: str = ""
    mention_all: bool = False
    events: list[str] = ["scan.completed", "gate.failed"]


class DingTalkConfigModel(BaseModel):
    webhook_url: str
    secret: str = ""
    mention_all: bool = False
    at_mobiles: list[str] = []
    events: list[str] = ["scan.completed", "gate.failed"]


@router.post("/notify/feishu", summary="添加飞书通知")
async def add_feishu_notifier(body: FeishuConfigModel):
    from ...engine.ci.notifier import FeishuConfig

    config = FeishuConfig(
        webhook_url=body.webhook_url,
        secret=body.secret,
        mention_all=body.mention_all,
        events=body.events,
    )
    _get_dispatcher().add_feishu(config)
    return {"status": "ok", "type": "feishu"}


@router.post("/notify/dingtalk", summary="添加钉钉通知")
async def add_dingtalk_notifier(body: DingTalkConfigModel):
    from ...engine.ci.notifier import DingTalkConfig

    config = DingTalkConfig(
        webhook_url=body.webhook_url,
        secret=body.secret,
        mention_all=body.mention_all,
        at_mobiles=body.at_mobiles,
        events=body.events,
    )
    _get_dispatcher().add_dingtalk(config)
    return {"status": "ok", "type": "dingtalk"}


class NotifyRequest(BaseModel):
    event: str = "scan.completed"
    scan_id: str = ""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    gate_passed: bool = True


@router.post("/notify/send", summary="发送通知")
async def send_notification(body: NotifyRequest):
    dispatcher = _get_dispatcher()
    if not dispatcher.feishu_notifiers and not dispatcher.dingtalk_notifiers:
        raise HTTPException(status_code=400, detail="未配置任何通知渠道")
    results = dispatcher.notify(
        body.event,
        body.scan_id,
        body.total,
        body.critical,
        body.high,
        body.medium,
        body.low,
        body.gate_passed,
    )
    return {"results": results}


# ===== Jira Integration =====

from ...engine.ci.jira import JiraClient, JiraConfig  # noqa: E402

_jira_client: JiraClient | None = None


class JiraConfigModel(BaseModel):
    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str = "Bug"
    labels: list[str] = ["security"]


class JiraIssueCreate(BaseModel):
    vuln_ids: list[str] = []


@router.post("/jira/config", summary="配置Jira连接")
async def configure_jira(body: JiraConfigModel):
    global _jira_client
    if _jira_client is not None:
        _jira_client.close()
    config = JiraConfig(
        base_url=body.base_url,
        email=body.email,
        api_token=body.api_token,
        project_key=body.project_key,
        issue_type=body.issue_type,
        labels=body.labels,
    )
    _jira_client = JiraClient(config)
    logger.info(f"配置Jira: {body.base_url} project={body.project_key}")
    return {"status": "ok", "base_url": body.base_url, "project_key": body.project_key}


@router.post("/jira/sync", summary="同步漏洞到Jira")
async def sync_to_jira(body: JiraIssueCreate):
    global _jira_client
    if _jira_client is None:
        raise HTTPException(status_code=400, detail="未配置Jira连接，请先调用 /jira/config")
    from ...db import get_session
    from ...db.convert import orm_to_vuln
    from ...db.models import VulnerabilityORM

    db = next(get_session())
    try:
        vulns = []
        if body.vuln_ids:
            for vid in body.vuln_ids:
                o = db.query(VulnerabilityORM).filter(VulnerabilityORM.id == vid).first()
                if o:
                    vulns.append(orm_to_vuln(o))
        else:
            for o in db.query(VulnerabilityORM).filter(VulnerabilityORM.status == "open").limit(50).all():
                vulns.append(orm_to_vuln(o))
        if not vulns:
            return {"synced": 0, "issues": []}
        issues = _jira_client.create_issues_batch(vulns)
        return {
            "synced": len(issues),
            "issues": [{"key": i.key, "url": i.url, "summary": i.summary} for i in issues],
        }
    finally:
        db.close()


@router.get("/jira/issue/{issue_key}", summary="获取Jira工单状态")
async def get_jira_issue(issue_key: str):
    global _jira_client
    if _jira_client is None:
        raise HTTPException(status_code=400, detail="未配置Jira连接")
    issue = _jira_client.get_issue(issue_key)
    if not issue:
        raise HTTPException(status_code=404, detail="Jira工单未找到")
    return {"key": issue.key, "summary": issue.summary, "status": issue.status, "url": issue.url}
