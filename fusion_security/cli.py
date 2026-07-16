"""Fusion-Security CLI 入口。"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__, __app_name__
from .scanner.scanner import Scanner, ScanTarget
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
@click.option("--severity", "-s", default="low",
              type=click.Choice(["critical", "high", "medium", "low"]),
              help="最低报告级别")
@click.option("--output", "-o", default="", help="报告输出目录")
@click.option("--format", "-f", "fmt", default="md",
              type=click.Choice(["md", "json", "html", "all"]),
              help="报告格式")
@click.option("--no-ai", is_flag=True, help="禁用 AI 分析")
@click.option("--model", "-m", default="", help="fusion-mlx 模型名称")
def scan(path: str, severity: str, output: str, fmt: str, no_ai: bool, model: str):
    """扫描代码安全漏洞。"""
    asyncio.run(_async_scan(path, severity, output, fmt, no_ai, model))


async def _async_scan(path: str, severity: str, output: str, fmt: str, no_ai: bool, model: str):
    click.echo()
    click.echo("🔒 Fusion-Security 代码安全审计")
    click.echo("=" * 50)
    click.echo()

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
    click.echo(json.dumps({
        "vulnerabilities": data["total_vulnerabilities"],
        "critical": data["critical"],
        "high": data["high"],
        "medium": data["medium"],
        "low": data["low"],
        "summary": data["summary"],
    }))


@cli.command()
def rules():
    """列出支持的检测规则。"""
    from .rules.engine import RuleEngine
    engine = RuleEngine()

    click.echo()
    click.echo(f"📋 检测规则 ({engine.get_rule_count()} 条)")
    click.echo("=" * 50)
    click.echo()

    for rule in engine.get_rules():
        click.echo(f"  {rule.id:12s} [{rule.severity:8s}] {rule.name}")
        click.echo(f"  {'':12s}  {rule.description}")
        click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()