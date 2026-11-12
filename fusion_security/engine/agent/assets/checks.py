"""Static checks over parsed agent-asset inventories (evolution plan P2.1).

Findings reuse the shared Vulnerability model (rule_id prefix AGT-) so
triage, gate, SARIF and the console pick them up unchanged. Every check is
deterministic and offline; the injection-based check reuses the P1.1 rule
engine so description-poisoning detection improves with the corpus.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from uuid import uuid4

from ....models import Vulnerability
from ..injection import detect as injection_detect
from .manifests import AssetInventory, McpServer, SkillPackage
from .signatures import SignatureLibrary

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Over-broad filesystem scopes: root, home, wildcard sweeps.
_WIDE_FS_RE = re.compile(r"^(?:/|~|\*\*|/[a-zA-Z]:|C:\\(?:\*\*)?)$")
# Secrets-bearing env vars passed to child processes.
_ENV_SECRET_RE = re.compile(r"(?i)(api[_-]?keys?|secrets?|tokens?|passwords?|credentials?|aws|ssh|private[_-]?keys?)")
# Unpinned package references in commands (npx -y pkg / uvx pkg / pip install pkg without ==).
_UNPINNED_NPX_RE = re.compile(r"\bnpx\s+(-y\s+)?@?[A-Za-z0-9@/._-]+(?![A-Za-z0-9@/._-]*@)\s*$")
_UNPINNED_UVX_RE = re.compile(r"\buvx\s+(?:--from\s+\S+\s+)?@?[A-Za-z0-9@/._-]+\s*$")
_UNPINNED_PIP_RE = re.compile(r"\bpip3?\s+install\s+(?:--upgrade\s+)?[^=]*[A-Za-z]\s*$")
# Risky shell fragments inside commands/args.
_CMD_RISK_RE = re.compile(
    r"curl[^|]*\|\s*(?:ba)?sh|wget[^|]*\|\s*(?:ba)?sh|\brm\s+-rf\s+[~/]|\beval\b|\bnc\s+-l|\bbase64\s+-d\s*\|"
)


def _finding(
    rule_id: str, title: str, description: str, severity: str, source: str, snippet: str, confidence: int
) -> Vulnerability:
    return Vulnerability(
        id=f"V-{uuid4().hex[:8]}",
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        file_path=source,
        line_number=0,
        code_snippet=snippet[:200],
        rule_id=rule_id,
        cwe_id="CWE-250" if "PERM" in rule_id else "CWE-20",
        fix_suggestion="限制声明范围、固定依赖版本、移除自动放行；确认误报可加入仓库级 allowlist",
    )


def check_mcp_server(server: McpServer, sigs: SignatureLibrary) -> list[Vulnerability]:
    findings: list[Vulnerability] = []

    # 1. Tool-description poisoning: injection patterns inside declared
    #    tool descriptions / resource text (P1.1 rules, deterministic tier).
    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        text = " ".join(str(v) for v in tool.values() if isinstance(v, str))
        if not text:
            continue
        result = injection_detect(text)
        if result["rule_findings"]:
            fams = sorted({f["family"] for f in result["rule_findings"]})
            findings.append(
                _finding(
                    "AGT-DESC-POISONING",
                    f"工具描述投毒({server.name}/{tool.get('name', '?')})",
                    f"工具声明文本包含注入模式 (families={fams})",
                    "critical",
                    server.source_file,
                    text[:120],
                    85,
                )
            )

    # 2. Over-broad env access.
    secret_env = [k for k in server.env if _ENV_SECRET_RE.search(k)]
    if secret_env:
        findings.append(
            _finding(
                "AGT-PERM-ENV",
                f"环境变量过度声明({server.name})",
                f"向 MCP 服务器进程传递敏感环境变量: {secret_env[:5]}",
                "high",
                server.source_file,
                ", ".join(secret_env[:5]),
                80,
            )
        )

    # 3. Over-broad filesystem / network scope in args.
    wide = [a for a in server.args if _WIDE_FS_RE.match(a.strip())]
    if wide:
        findings.append(
            _finding(
                "AGT-PERM-FS-WIDE",
                f"文件系统范围过宽({server.name})",
                f"声明了全盘/家目录级访问范围: {wide[:3]}",
                "high",
                server.source_file,
                " ".join(wide[:3]),
                85,
            )
        )

    # 4. Auto-approve lists (tools allowed without user confirmation).
    if server.auto_approve:
        findings.append(
            _finding(
                "AGT-AUTO-APPROVE",
                f"工具自动放行({server.name})",
                f"autoApprove 非空: {server.auto_approve[:5]} — 危险工具可无确认执行",
                "high",
                server.source_file,
                ", ".join(server.auto_approve[:5]),
                80,
            )
        )

    # 5. Unpinned dependency references in command+args.
    if server.command in {"npx", "uvx", "pip", "pip3"}:
        joined = " ".join(server.args).strip()
        pinned = "@" in joined or "==" in joined or "--from" in joined and "@" in joined
        if server.command == "pip":
            pinned = "==" in joined
        if joined and not pinned and not _UNPINNED_NPX_RE.search(joined + " "):
            pass  # regex below decides
        if joined and not pinned:
            findings.append(
                _finding(
                    "AGT-UNPINNED-DEP",
                    f"未固定依赖版本({server.name})",
                    f"{server.command} {joined} 未声明版本号，供应链不可复现且可被投毒",
                    "medium",
                    server.source_file,
                    f"{server.command} {joined}"[:120],
                    70,
                )
            )

    # 6. Risky shell fragments.
    joined_cmd = " ".join([server.command, *server.args])
    if _CMD_RISK_RE.search(joined_cmd):
        findings.append(
            _finding(
                "AGT-CMD-RISK",
                f"危险命令模式({server.name})",
                "启动命令包含管道执行/递归删除/eval 等高危模式",
                "high",
                server.source_file,
                joined_cmd[:120],
                85,
            )
        )

    # 7. Known-malicious signatures.
    for indicator in sigs.match_package(joined_cmd):
        findings.append(
            _finding(
                "AGT-SIGNATURE-MATCH",
                f"命中恶意签名({server.name})",
                f"命令/依赖命中本地签名库条目: {indicator}",
                "critical",
                server.source_file,
                indicator,
                95,
            )
        )
    if server.url:
        for indicator in sigs.match_domain(server.url):
            findings.append(
                _finding(
                    "AGT-SIGNATURE-MATCH",
                    f"命中恶意签名({server.name})",
                    f"远程端点命中本地签名库条目: {indicator}",
                    "critical",
                    server.source_file,
                    server.url[:120],
                    95,
                )
            )

    return findings


def check_skill(skill: SkillPackage, sigs: SignatureLibrary) -> list[Vulnerability]:
    findings: list[Vulnerability] = []

    # 1. Description / body poisoning via the P1.1 rule engine.
    for label, text in (("description", skill.description), ("body", skill.body[:4000])):
        if not text:
            continue
        result = injection_detect(text)
        if result["rule_findings"]:
            fams = sorted({f["family"] for f in result["rule_findings"]})
            findings.append(
                _finding(
                    "AGT-DESC-POISONING",
                    f"技能文本投毒({skill.name}/{label})",
                    f"技能{label}包含注入模式 (families={fams})",
                    "critical" if label == "description" else "high",
                    skill.source_file,
                    text[:120],
                    85,
                )
            )

    # 2. Over-broad allowed tools.
    for tool in skill.allowed_tools:
        if tool.strip() in {"*", "Bash", "bash(*)", "Bash(*)", "Web", "Web(*)"}:
            findings.append(
                _finding(
                    "AGT-PERM-FS-WIDE",
                    f"技能权限过宽({skill.name})",
                    f"allowed-tools 声明了无限制工具: {tool}",
                    "high",
                    skill.source_file,
                    tool,
                    85,
                )
            )

    # 3. Risky commands / unpinned installs in body.
    for line in skill.body.split("\n"):
        if _CMD_RISK_RE.search(line):
            findings.append(
                _finding(
                    "AGT-CMD-RISK",
                    f"危险命令模式({skill.name})",
                    "技能正文包含管道执行/递归删除/eval 等高危命令",
                    "high",
                    skill.source_file,
                    line.strip()[:120],
                    80,
                )
            )
        if _UNPINNED_PIP_RE.search(line) and "==" not in line:
            findings.append(
                _finding(
                    "AGT-UNPINNED-DEP",
                    f"未固定依赖版本({skill.name})",
                    "技能正文包含未固定版本的 pip install",
                    "medium",
                    skill.source_file,
                    line.strip()[:120],
                    70,
                )
            )

    # 4. Known-malicious signatures in body text (packages/commands).
    body = skill.body[:4000]
    indicators = sigs.match_package(body) + sigs.match_command(body)
    for indicator in indicators:
        findings.append(
            _finding(
                "AGT-SIGNATURE-MATCH",
                f"命中恶意签名({skill.name})",
                f"技能内容命中本地签名库条目: {indicator}",
                "critical",
                skill.source_file,
                indicator,
                95,
            )
        )

    return findings


def run_asset_checks(inventory: AssetInventory, sigs: SignatureLibrary) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    for server in inventory.mcp_servers:
        findings.extend(check_mcp_server(server, sigs))
    for skill in inventory.skills:
        findings.extend(check_skill(skill, sigs))
    logger.info(f"[Assets] checks done: {len(findings)} finding(s)")
    return findings


def scan_assets(root: Path, sigs: SignatureLibrary | None = None) -> tuple[AssetInventory, list[Vulnerability]]:
    from .manifests import discover_assets
    from .signatures import SignatureLibrary as _Sig

    lib = sigs if sigs is not None else _Sig.load()
    inventory = discover_assets(root)
    return inventory, run_asset_checks(inventory, lib)
