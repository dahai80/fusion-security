"""Posture checklist —— 姿态合规分区(Issue #60)。

每个检查项 = {id, title, title_en, state, detail}:state ∈ ok/warn/todo/todo_roadmap。
可操作项(todo/warn)给出 route 深链;依赖上游的项落 todo_roadmap 并注明单号,
绝不伪造 ok。检查全部本地可判定(配置/环境/DB),不阻塞在 identity 上。
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

from ...db.session import get_session

logger = logging.getLogger(__name__)


def _check_retention() -> dict:
    # 审计留存在本仓为 append-only jsonl,无自动清理 —— 如未配置保留天数即待办。
    days = os.environ.get("FUSION_AUDIT_RETENTION_DAYS", "").strip()
    if days.isdigit() and int(days) > 0:
        return {"state": "ok", "detail": f"审计保留 {days} 天"}
    return {"state": "todo", "detail": "未配置审计保留天数(FUSION_AUDIT_RETENTION_DAYS)", "route": "/audit"}


def _check_rate_limit() -> dict:
    if os.environ.get("FUSION_RATE_LIMIT_DISABLE", "").strip() in ("1", "true", "True"):
        return {"state": "warn", "detail": "API 限流已全局关闭"}
    return {"state": "ok", "detail": "API 限流启用"}


def _check_jwt_verify() -> dict:
    # JWT 校验依赖 identity 服务令牌;缺失 = 双模式降级为纯 API Key(审计记 warn)。
    if os.environ.get("FUSION_IDENTITY_SERVICE_TOKEN", "").strip():
        return {"state": "ok", "detail": "JWT 校验已接入 fusion-identity"}
    return {"state": "todo", "detail": "未配置 FUSION_IDENTITY_SERVICE_TOKEN,JWT 校验不可用"}


def _check_master_key() -> dict:
    # master key 有独立 env 即视为显式管理;默认随机则每次重启轮换(告警提示)。
    if os.environ.get("FUSION_SECURITY_MASTER_KEY", "").strip():
        return {"state": "ok", "detail": "master key 显式配置"}
    return {"state": "warn", "detail": "master key 未显式配置,重启后既有 API key 失效"}


def _check_key_expiry_policy() -> dict:
    # 检查是否存在带过期时间的本地 key;全部永不过期 = 提示设过期策略。
    try:
        db = get_session()
        try:
            from ...db.models import ApiKeyORM

            keys = db.query(ApiKeyORM).filter(ApiKeyORM.enabled == True).all()  # noqa: E712
            now = datetime.utcnow()
            soon = now + timedelta(days=14)
            expiring = [k for k in keys if k.expires_at and k.expires_at <= soon]
            no_expiry = [k for k in keys if not k.expires_at]
            if expiring:
                return {"state": "warn", "detail": f"{len(expiring)} 个 key 即将过期或已过期", "route": "/keys"}
            if no_expiry:
                return {"state": "todo", "detail": f"{len(no_expiry)} 个 key 未设过期时间", "route": "/keys"}
            return {"state": "ok", "detail": "全部 key 均在有效期内"}
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"[Posture] key 过期检查失败: {e}")
        return {"state": "todo", "detail": "key 过期检查不可用", "route": "/keys"}


def build_posture_checklist(idp_summary: dict) -> list[dict]:
    # idp_summary 来自 IdentityAdminClient(可能 degraded);SSO 项如实反映。
    checks: list[dict] = []

    if idp_summary.get("available"):
        if idp_summary.get("configured"):
            types = ",".join(idp_summary.get("types", [])) or "unknown"
            checks.append({"id": "sso", "state": "ok", "detail": f"SSO 已配置({types})"})
        else:
            checks.append({"id": "sso", "state": "todo", "detail": "SSO 未配置", "route": "/keys"})
    else:
        checks.append(
            {
                "id": "sso",
                "state": "todo_roadmap",
                "detail": f"SSO 状态不可读:{idp_summary.get('reason', 'identity 不可达')}",
            }
        )

    checks.append({"id": "retention", **_check_retention()})
    checks.append({"id": "rate_limit", **_check_rate_limit()})
    checks.append({"id": "jwt_verify", **_check_jwt_verify()})
    checks.append({"id": "master_key", **_check_master_key()})
    checks.append({"id": "key_expiry", **_check_key_expiry_policy()})

    return [
        {
            "id": c["id"],
            "state": c["state"],
            "detail": c["detail"],
            "route": c.get("route", ""),
        }
        for c in checks
    ]
