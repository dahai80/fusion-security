"""Inventory parsers for agent assets (evolution plan P2.1).

Discovers and parses MCP server manifests, skill packages and related agent
config files in a target tree. Parsers are deliberately tolerant: malformed
files yield zero entries (never findings) — static checks only run on
successfully parsed structures to keep the false-positive rate at zero.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

MCP_MANIFEST_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json"}
SKILL_FILE_NAMES = {"SKILL.md", "skill.md"}
MAX_ASSET_FILE_SIZE = 1_000_000

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$", re.MULTILINE)


@dataclass
class McpServer:
    name: str
    source_file: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    tools: list[dict] = field(default_factory=list)
    auto_approve: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class SkillPackage:
    name: str
    source_file: str
    description: str = ""
    allowed_tools: list[str] = field(default_factory=list)
    body: str = ""
    raw_meta: dict = field(default_factory=dict)


@dataclass
class AssetInventory:
    mcp_servers: list[McpServer] = field(default_factory=list)
    skills: list[SkillPackage] = field(default_factory=list)
    files_scanned: int = 0


def _parse_simple_yaml(meta: str) -> dict:
    # Skill frontmatter is flat key: value (plus simple lists); a full YAML
    # parser is deliberately avoided to stay dependency-light. Tolerant:
    # unparsable lines are dropped.
    meta_out: dict = {}
    current_list_key = None
    for line in meta.split("\n"):
        if not line.strip():
            continue
        if line.lstrip().startswith("- ") and current_list_key:
            meta_out[current_list_key].append(line.lstrip()[2:].strip().strip("'\""))
            continue
        m = _KV_RE.match(line.strip())
        if not m:
            current_list_key = None
            continue
        key, value = m.group(1), m.group(2).strip()
        if value == "":
            meta_out[key] = []
            current_list_key = key
        else:
            meta_out[key] = value.strip("'\"")
            current_list_key = None
    return meta_out


def parse_mcp_manifest(path: Path, rel: str) -> list[McpServer]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        logger.debug(f"[Assets] unparsable MCP manifest {rel}: {e}")
        return []
    if not isinstance(data, dict):
        return []
    servers_block = data.get("mcpServers", data)
    servers: list[McpServer] = []
    if not isinstance(servers_block, dict):
        return []
    for name, cfg in servers_block.items():
        if not isinstance(cfg, dict):
            continue
        tools = cfg.get("tools") if isinstance(cfg.get("tools"), list) else []
        servers.append(
            McpServer(
                name=str(name),
                source_file=rel,
                command=str(cfg.get("command", "")),
                args=[str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else [],
                env={str(k): str(v) for k, v in cfg.get("env", {}).items()} if isinstance(cfg.get("env"), dict) else {},
                url=str(cfg.get("url", "")),
                tools=tools,
                auto_approve=[str(a) for a in cfg.get("autoApprove", [])]
                if isinstance(cfg.get("autoApprove"), list)
                else [],
                raw=cfg,
            )
        )
    return servers


def parse_skill_file(path: Path, rel: str) -> list[SkillPackage]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.debug(f"[Assets] unreadable skill file {rel}: {e}")
        return []
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return []
    meta = _parse_simple_yaml(m.group(1))
    name = str(meta.get("name") or path.parent.name)
    description = str(meta.get("description", ""))
    allowed = meta.get("allowed-tools") or meta.get("allowed_tools") or []
    if isinstance(allowed, str):
        allowed = [t.strip() for t in allowed.split(",") if t.strip()]
    return [
        SkillPackage(
            name=name,
            source_file=rel,
            description=description,
            allowed_tools=[str(t) for t in allowed],
            body=text[m.end() :],
            raw_meta=meta,
        )
    ]


def discover_assets(root: Path) -> AssetInventory:
    inv = AssetInventory()
    if not root.exists():
        return inv
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.stat().st_size > MAX_ASSET_FILE_SIZE:
            continue
        rel_parts = f.relative_to(root).parts if f.is_relative_to(root) else f.parts
        if ".git" in rel_parts or "node_modules" in rel_parts or ".venv" in rel_parts:
            continue
        rel = str(f.relative_to(root)) if f.is_relative_to(root) else str(f)
        inv.files_scanned += 1
        if f.name in MCP_MANIFEST_NAMES:
            inv.mcp_servers.extend(parse_mcp_manifest(f, rel))
        elif f.name in SKILL_FILE_NAMES:
            inv.skills.extend(parse_skill_file(f, rel))
    logger.info(
        f"[Assets] inventory: {inv.files_scanned} files, {len(inv.mcp_servers)} MCP servers, {len(inv.skills)} skills"
    )
    return inv
