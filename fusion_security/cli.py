"""Fusion-Security CLI 入口。"""

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
    incremental: bool,
    base: str,
):
    """扫描代码安全漏洞。"""
    asyncio.run(_async_scan(path, severity, output, fmt, no_ai, model, pipeline, sca, incremental, base))


async def _async_scan(
    path: str,
    severity: str,
    output: str,
    fmt: str,
    no_ai: bool,
    model: str,
    pipeline: bool,
    sca: bool,
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
            )
            pl = ScanPipeline(config)
            click.echo(f"  扫描目标: {path}")
            click.echo("  扫描模式: 🔄 5阶段流水线")
            click.echo(f"  AI 分析:  {'✅ 已启用' if not no_ai else '❌ 已禁用'}")
            click.echo(f"  SCA 扫描: {'✅ 已启用' if config.enable_sca else '❌ 已禁用'}")
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
@click.option("--port", default=8765, help="监听端口")
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
    from .report.sarif import save_sarif

    target = ScanTarget(path)
    scanner = Scanner(use_ai=False)
    result = await scanner.scan(target)
    saved = save_sarif(result.vulnerabilities, output)
    click.echo(f"📄 SARIF 报告已保存: {saved}")


def main():
    cli()


if __name__ == "__main__":
    main()
