"""Fusion-Security CLI 入口。

引擎分工:
- scan --pipeline / --sca  -> ScanPipeline(6 阶段:Recon→Discover→Verify→Triage→Patch→Retest),权威扫描路径。
- scan(无 --pipeline)       -> Scanner(legacy 单遍并行批扫),保留兼容,结果与 pipeline 等价但无阶段/断点。
- check / gate / sarif      -> Scanner(use_ai=False),CI 友好的轻量路径(纯规则+AST,无 AI,快速)。
  这是刻意的 legacy 保留:CI 场景只需规则结果 + 退出码,不需要 AI 验证或补丁生成。
  API(POST /scans)已统一走 ScanPipeline,CLI 的 check/gate/sarif 不经 pipeline。
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import click

from . import __app_name__, __version__
from .engine.pipeline import PipelineConfig, ScanPipeline
from .engine.scanner import Scanner, ScanTarget
from .report.report import ReportGenerator
from .utils.logger import setup_logger

logger = logging.getLogger(__name__)


def _logs_to_stderr():
    # Machine-readable commands (JSON on stdout) send log lines to stderr;
    # the shared setup_logger binds the fusion_security handler to stdout.
    for handler in logging.getLogger("fusion_security").handlers:
        handler.stream = sys.stderr


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.version_option(version=__version__, prog_name=__app_name__)
def cli(verbose: bool):
    """Fusion-Security — 本地 AI 代码安全审计工具。

    100% 本地离线，基于 fusion-mlx，对标 Claude Security。
    代码不出境，隐私绝对安全。
    """
    level = logging.DEBUG if verbose else logging.INFO
    setup_logger(level=level, verbose=verbose)


@cli.command()
@click.argument("path", default=".")
@click.option(
    "--severity", "-s", default="low", type=click.Choice(["critical", "high", "medium", "low"]), help="最低报告级别"
)
@click.option("--output", "-o", default="", help="报告输出目录")
@click.option("--format", "-f", "fmt", default="md", type=click.Choice(["md", "json", "html", "all"]), help="报告格式")
@click.option("--no-ai", is_flag=True, help="禁用 AI 分析")
@click.option("--model", "-m", default="", help="fusion-mlx 模型名称")
@click.option("--pipeline", is_flag=True, help="使用5阶段流水线扫描")
@click.option("--sca", is_flag=True, help="启用 SCA 依赖漏洞扫描")
@click.option("--osv", is_flag=True, help="启用 OSV.dev 云端依赖漏洞查询(会向 osv.dev 外发依赖清单，打破离线)")
@click.option("--incremental", "-i", is_flag=True, help="增量扫描(仅扫描git diff变更文件)")
@click.option("--base", "-b", default="", help="增量扫描基准commit(默认HEAD~1)")
def scan(
    path: str,
    severity: str,
    output: str,
    fmt: str,
    no_ai: bool,
    model: str,
    pipeline: bool,
    sca: bool,
    osv: bool,
    incremental: bool,
    base: str,
):
    """扫描代码安全漏洞。"""
    asyncio.run(_async_scan(path, severity, output, fmt, no_ai, model, pipeline, sca, osv, incremental, base))


async def _async_scan(
    path: str,
    severity: str,
    output: str,
    fmt: str,
    no_ai: bool,
    model: str,
    pipeline: bool,
    sca: bool,
    osv: bool,
    incremental: bool,
    base: str,
):
    click.echo()
    click.echo("🔒 Fusion-Security 代码安全审计")
    click.echo("=" * 50)
    click.echo()

    if incremental:
        try:
            from .engine.vcs.git import GitHelper

            git = GitHelper(path)
            base_ref = base or "HEAD~1"
            diff = git.get_changed_files(base=base_ref, head="HEAD")
            if not diff.changed_files:
                click.echo("  ✅ 无代码变更，跳过扫描")
                return
            click.echo(f"  扫描模式: 🔄 增量扫描 ({base_ref}...HEAD)")
            click.echo(f"  变更文件: {len(diff.changed_files)} 个")
            click.echo()
            incremental_files = [str(Path(path) / f) for f in diff.changed_files]
            target = ScanTarget(path, incremental_files=incremental_files)
            scanner = Scanner(use_ai=not no_ai, model=model)
            with click.progressbar(length=100, label="增量扫描中...") as bar:
                result = await scanner.scan_incremental(target, diff.changed_files, severity_threshold=severity)
                bar.update(100)
        except ValueError as e:
            click.echo(f"  ⚠️  {e}，回退到全量扫描")
            incremental = False
        except Exception as e:
            logger.warning(f"增量扫描失败: {e}，回退到全量扫描")
            incremental = False

    if not incremental:
        if pipeline or sca:
            config = PipelineConfig(
                use_ai=not no_ai,
                model=model,
                severity_threshold=severity,
                enable_sca=sca or pipeline,
                enable_osv=osv,
            )
            pl = ScanPipeline(config)
            click.echo(f"  扫描目标: {path}")
            click.echo("  扫描模式: 🔄 5阶段流水线")
            click.echo(f"  AI 分析:  {'✅ 已启用' if not no_ai else '❌ 已禁用'}")
            click.echo(f"  SCA 扫描: {'✅ 已启用' if config.enable_sca else '❌ 已禁用'}")
            click.echo(f"  OSV 云查: {'✅ 已启用(将外发依赖清单)' if config.enable_osv else '❌ 已禁用(离线)'}")
            click.echo()

            with click.progressbar(length=100, label="扫描中...") as bar:
                ctx = await pl.run(path)
                bar.update(100)

            result = pl.to_scan_result(ctx)

            click.echo()
            click.echo("  📊 阶段结果:")
            for stage, info in ctx.stage_results.items():
                dur = info.get("duration_ms", 0)
                click.echo(f"    {stage}: {dur:.0f}ms")
            click.echo()
        else:
            target = ScanTarget(path)
            scanner = Scanner(use_ai=not no_ai, model=model)

            click.echo(f"  扫描目标: {target.path}")
            click.echo(f"  AI 分析:  {'✅ 已启用' if not no_ai else '❌ 已禁用'}")
            click.echo()

            with click.progressbar(length=100, label="扫描中...") as bar:
                result = await scanner.scan(target, severity_threshold=severity)
                bar.update(100)

    click.echo()
    click.echo(f"  📊 {result.summary}")
    click.echo(f"  扫描文件: {result.files_scanned} 个")
    click.echo(f"  扫描耗时: {result.duration_ms:.0f}ms")
    click.echo()

    if result.vulnerabilities:
        click.echo("  漏洞列表:")
        for i, vuln in enumerate(result.vulnerabilities[:10], 1):
            sev_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            icon = sev_color.get(vuln.severity, "⚪")
            click.echo(f"  {i}. {icon} [{vuln.severity.upper()}] {vuln.title}")
            click.echo(f"     {vuln.file_path}:{vuln.line_number}")
            if vuln.fix_suggestion:
                click.echo(f"     💡 {vuln.fix_suggestion}")

        if len(result.vulnerabilities) > 10:
            click.echo(f"     ... 还有 {len(result.vulnerabilities) - 10} 个漏洞")

    # 生成报告
    if output or fmt != "md":
        output_dir = output or "~/Desktop/fusion_security_reports"
        reporter = ReportGenerator()
        formats = ["md", "json", "html"] if fmt == "all" else [fmt]
        saved = reporter.save_report(result, output_dir, formats)
        click.echo()
        click.echo("  报告已保存:")
        for fmt_name, path in saved.items():
            click.echo(f"    📄 {fmt_name}: {path}")

    click.echo()


@cli.command()
@click.argument("path", default=".")
def check(path: str):
    """快速检查（仅输出结果，适合 CI）。"""
    asyncio.run(_async_check(path))


async def _async_check(path: str):
    # CI 轻量路径:Scanner(use_ai=False) 纯规则+AST,不经 ScanPipeline。刻意的 legacy。
    target = ScanTarget(path)
    scanner = Scanner(use_ai=False)
    result = await scanner.scan(target)

    data = result.to_dict()
    click.echo(
        json.dumps(
            {
                "vulnerabilities": data["total_vulnerabilities"],
                "critical": data["critical"],
                "high": data["high"],
                "medium": data["medium"],
                "low": data["low"],
                "summary": data["summary"],
            }
        )
    )


@cli.command()
def rules():
    """列出支持的检测规则。"""
    from .engine.rules.engine import RuleEngine

    engine = RuleEngine()

    click.echo()
    click.echo(f"📋 检测规则 ({engine.get_rule_count()} 条)")
    click.echo("=" * 50)
    click.echo()

    for rule in engine.get_rules():
        click.echo(f"  {rule.id:12s} [{rule.severity:8s}] {rule.name}")
        click.echo(f"  {'':12s}  {rule.description}")
        click.echo()


@cli.command()
@click.option("--host", default="127.0.0.1", help="监听地址")
@click.option("--port", default=11454, help="监听端口")
def serve(host: str, port: int):
    """启动 Web API 服务。"""
    import uvicorn

    from .api.app import app

    click.echo(f"🔒 Fusion-Security API 启动: http://{host}:{port}")
    click.echo(f"   API 文档: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="info")


@cli.command()
@click.argument("path", default=".")
@click.option(
    "--policy", "-p", default="standard", type=click.Choice(["strict", "standard", "permissive"]), help="Gate 策略"
)
def gate(path: str, policy: str):
    """安全质量门禁检查（适合 CI/CD）。"""
    asyncio.run(_async_gate(path, policy))


async def _async_gate(path: str, policy: str):
    # CI 门禁:Scanner(use_ai=False) 纯规则,不经 pipeline。
    from .engine.ci.gate import GatePolicy, SecurityGate

    target = ScanTarget(path)
    scanner = Scanner(use_ai=False)
    result = await scanner.scan(target)
    gate_policy = GatePolicy(policy)
    sg = SecurityGate(gate_policy)
    gate_result = sg.evaluate(result.vulnerabilities)
    click.echo(gate_result.to_json())
    if not gate_result.passed:
        sys.exit(1)


@cli.command()
@click.argument("path", default=".")
@click.option("--output", "-o", default="results.sarif", help="SARIF 输出文件")
def sarif(path: str, output: str):
    """导出 SARIF 格式扫描结果。"""
    asyncio.run(_async_sarif(path, output))


async def _async_sarif(path: str, output: str):
    # SARIF 导出:Scanner(use_ai=False) 纯规则,不经 pipeline。
    from .report.sarif import save_sarif

    target = ScanTarget(path)
    scanner = Scanner(use_ai=False)
    result = await scanner.scan(target)
    saved = save_sarif(result.vulnerabilities, output)
    click.echo(f"📄 SARIF 报告已保存: {saved}")


@cli.command(name="inject-scan")
@click.argument("target", default="-")
@click.option("--pretty", is_flag=True, help="Pretty-print JSON output")
def inject_scan(target: str, pretty: bool):
    """Prompt-injection scan for a file, directory of text files, or stdin ('-')."""
    _logs_to_stderr()
    from .engine.agent.injection import detect

    if target == "-":
        text = sys.stdin.read()
        results = [("[stdin]", detect(text))]
    else:
        p = Path(target).expanduser()
        if p.is_file():
            targets = [p]
        elif p.is_dir():
            targets = sorted(
                f
                for f in p.rglob("*")
                if f.is_file()
                and f.suffix.lower() in {".txt", ".md", ".json", ".yaml", ".yml"}
                and f.stat().st_size < 5_000_000
            )
        else:
            click.echo(f"error: no such file or directory: {target}", err=True)
            sys.exit(2)
        results = []
        for f in targets:
            text = f.read_text(encoding="utf-8", errors="ignore")
            results.append((str(f), detect(text)))

    flagged = [(name, r) for name, r in results if r["is_injection"]]
    payload = {
        "scanned": len(results),
        "flagged": len(flagged),
        "results": [{"target": name, **r} for name, r in results if r["is_injection"]],
    }
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None))
    if flagged:
        sys.exit(1)


@cli.command(name="secrets-scan")
@click.argument("target", default=".")
@click.option("--history", is_flag=True, help="Scan git history (all commits) instead of working tree")
@click.option("--base", "-b", default="", help="History incremental base ref (default: full history)")
@click.option("--max-commits", default=2000, help="Max commits to walk in history mode")
@click.option("--pretty", is_flag=True, help="Pretty-print JSON output")
def secrets_scan(target: str, history: bool, base: str, max_commits: int, pretty: bool):
    """Scan working tree or git history for hardcoded secrets (offline)."""
    _logs_to_stderr()
    from .engine.secrets import scan_history
    from .engine.secrets.integration import get_shared_scanner

    if history:
        p = Path(target).expanduser()
        try:
            result = scan_history(str(p), base=base, max_commits=max_commits)
        except (ValueError, RuntimeError) as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(2)
        payload = {
            "mode": "history",
            "commits_scanned": result.commits_scanned,
            "findings": [f.to_dict() for f in result.findings],
        }
    else:
        p = Path(target).expanduser()
        if not p.exists():
            click.echo(f"error: no such file or directory: {target}", err=True)
            sys.exit(2)
        files = (
            [p]
            if p.is_file()
            else sorted(
                f for f in p.rglob("*") if f.is_file() and f.stat().st_size < 1_000_000 and ".git" not in f.parts
            )
        )
        scanner = get_shared_scanner()
        findings = []
        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                logger.warning(f"secrets-scan: unreadable file {f}: {e}")
                continue
            rel = str(f.relative_to(p)) if f.is_relative_to(p) else str(f)
            findings.extend(scanner.scan_text(content, rel_path=rel))
        payload = {
            "mode": "worktree",
            "files_scanned": len(files),
            "findings": [f.to_dict() for f in findings],
        }

    click.echo(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None))
    if payload["findings"]:
        sys.exit(1)


@cli.command(name="agent-scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--signatures", "-s", default="", help="Override signature library bundle (offline import)")
@click.option("--pretty", is_flag=True, help="Pretty-print JSON output")
def agent_scan(path: str, signatures: str, pretty: bool):
    """Scan a repo for malicious MCP servers / skills / agent configs (offline)."""
    _logs_to_stderr()
    from .engine.agent.assets import SignatureLibrary, scan_assets

    root = Path(path).expanduser().resolve()
    lib = SignatureLibrary.load(signatures) if signatures else None
    inventory, findings = scan_assets(root, sigs=lib)

    payload = {
        "files_scanned": inventory.files_scanned,
        "mcp_servers": len(inventory.mcp_servers),
        "skills": len(inventory.skills),
        "findings": [
            {
                "rule_id": v.rule_id,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
                "file_path": v.file_path,
                "code_snippet": v.code_snippet,
                "fix_suggestion": v.fix_suggestion,
            }
            for v in findings
        ],
    }
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None))
    if findings:
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
