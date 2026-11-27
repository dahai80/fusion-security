"""Fusion-Security CLI entry.

Engine split:
- scan --pipeline / --sca  -> ScanPipeline (6 stages: Recon->Discover->Verify->Triage->Patch->Retest), authoritative scan path.
- scan (no --pipeline)     -> Scanner (legacy single-pass parallel batch scan), kept for compatibility; results equal pipeline but without stages/checkpoints.
- check / gate / sarif     -> Scanner(use_ai=False), CI-friendly lightweight path (rules+AST only, no AI, fast).
  This legacy retention is deliberate: CI only needs rule results + exit code, no AI verification or patch generation.
  API (POST /scans) already goes through ScanPipeline; CLI check/gate/sarif do not.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

import click

from . import __app_name__, __version__
from .engine.pipeline import PipelineConfig, ScanPipeline
from .engine.scanner import Scanner, ScanTarget
from .report.report import ReportGenerator
from .utils.logger import setup_logger

logger = logging.getLogger(__name__)


def _logs_to_stderr(machine_only: bool = False):
    # Machine-readable commands (JSON on stdout) send log lines to stderr;
    # the shared setup_logger binds the fusion_security handler to stdout.
    log = logging.getLogger("fusion_security")
    for handler in log.handlers:
        handler.stream = sys.stderr
    if machine_only:
        # Subcommand output must be pure JSON on stdout; demote INFO chatter.
        log.setLevel(logging.WARNING)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.version_option(version=__version__, prog_name=__app_name__)
def cli(verbose: bool):
    """Fusion-Security - local AI code security audit tool.

    100% local and offline, powered by fusion-mlx, benchmarked against Claude Security.
    Code never leaves the machine; privacy is absolute.
    """
    level = logging.DEBUG if verbose else logging.INFO
    setup_logger(level=level, verbose=verbose)


@cli.command()
@click.argument("path", default=".")
@click.option(
    "--severity",
    "-s",
    default="low",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Minimum severity to report",
)
@click.option("--output", "-o", default="", help="Report output directory")
@click.option(
    "--format", "-f", "fmt", default="md", type=click.Choice(["md", "json", "html", "all"]), help="Report format"
)
@click.option(
    "--compliance",
    default="",
    type=click.Choice(["", "dengbao", "iso27001", "pci_dss", "eu_ai_act"]),
    help="Attach compliance mapping section to the report (P3.2 framework profile)",
)
@click.option("--no-ai", is_flag=True, help="Disable AI analysis")
@click.option("--model", "-m", default="", help="fusion-mlx model name")
@click.option("--pipeline", is_flag=True, help="Scan with the 6-stage pipeline")
@click.option("--sca", is_flag=True, help="Enable SCA dependency vulnerability scanning")
@click.option(
    "--osv",
    is_flag=True,
    help="Enable OSV.dev cloud dependency lookups (sends the dependency manifest to osv.dev, breaking offline mode)",
)
@click.option("--incremental", "-i", is_flag=True, help="Incremental scan (only files changed in git diff)")
@click.option("--base", "-b", default="", help="Incremental scan base commit (default HEAD~1)")
def scan(
    path: str,
    severity: str,
    output: str,
    fmt: str,
    compliance: str,
    no_ai: bool,
    model: str,
    pipeline: bool,
    sca: bool,
    osv: bool,
    incremental: bool,
    base: str,
):
    """Scan code for security vulnerabilities."""
    asyncio.run(
        _async_scan(path, severity, output, fmt, compliance, no_ai, model, pipeline, sca, osv, incremental, base)
    )


async def _async_scan(
    path: str,
    severity: str,
    output: str,
    fmt: str,
    compliance: str,
    no_ai: bool,
    model: str,
    pipeline: bool,
    sca: bool,
    osv: bool,
    incremental: bool,
    base: str,
):
    click.echo()
    click.echo("🔒 Fusion-Security code security audit")
    click.echo("=" * 50)
    click.echo()

    if incremental:
        try:
            from .engine.vcs.git import GitHelper

            git = GitHelper(path)
            base_ref = base or "HEAD~1"
            diff = git.get_changed_files(base=base_ref, head="HEAD")
            if not diff.changed_files:
                click.echo("  ✅ No code changes, skipping scan")
                return
            click.echo(f"  Scan mode: 🔄 incremental ({base_ref}...HEAD)")
            click.echo(f"  Changed files: {len(diff.changed_files)}")
            click.echo()
            incremental_files = [str(Path(path) / f) for f in diff.changed_files]
            target = ScanTarget(path, incremental_files=incremental_files)
            scanner = Scanner(use_ai=not no_ai, model=model)
            with click.progressbar(length=100, label="Incremental scanning...") as bar:
                result = await scanner.scan_incremental(target, diff.changed_files, severity_threshold=severity)
                bar.update(100)
        except ValueError as e:
            click.echo(f"  ⚠️  {e}, falling back to full scan")
            incremental = False
        except Exception as e:
            logger.warning(f"incremental scan failed: {e}, falling back to full scan")
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
            click.echo(f"  Scan target: {path}")
            click.echo("  Scan mode: 🔄 6-stage pipeline")
            click.echo(f"  AI analysis:  {'✅ enabled' if not no_ai else '❌ disabled'}")
            click.echo(f"  SCA scan: {'✅ enabled' if config.enable_sca else '❌ disabled'}")
            click.echo(
                f"  OSV lookup: {'✅ enabled (sends dependency manifest)' if config.enable_osv else '❌ disabled (offline)'}"
            )
            click.echo()

            with click.progressbar(length=100, label="Scanning...") as bar:
                ctx = await pl.run(path)
                bar.update(100)

            result = pl.to_scan_result(ctx)

            click.echo()
            click.echo("  📊 Stage results:")
            for stage, info in ctx.stage_results.items():
                dur = info.get("duration_ms", 0)
                click.echo(f"    {stage}: {dur:.0f}ms")
            click.echo()
        else:
            target = ScanTarget(path)
            scanner = Scanner(use_ai=not no_ai, model=model)

            click.echo(f"  Scan target: {target.path}")
            click.echo(f"  AI analysis:  {'✅ enabled' if not no_ai else '❌ disabled'}")
            click.echo()

            with click.progressbar(length=100, label="Scanning...") as bar:
                result = await scanner.scan(target, severity_threshold=severity)
                bar.update(100)

    click.echo()
    click.echo(f"  📊 {result.summary}")
    click.echo(f"  Files scanned: {result.files_scanned}")
    click.echo(f"  Scan duration: {result.duration_ms:.0f}ms")
    click.echo()

    if result.vulnerabilities:
        click.echo("  Vulnerabilities:")
        for i, vuln in enumerate(result.vulnerabilities[:10], 1):
            sev_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            icon = sev_color.get(vuln.severity, "⚪")
            click.echo(f"  {i}. {icon} [{vuln.severity.upper()}] {vuln.title}")
            click.echo(f"     {vuln.file_path}:{vuln.line_number}")
            if vuln.fix_suggestion:
                click.echo(f"     💡 {vuln.fix_suggestion}")

        if len(result.vulnerabilities) > 10:
            click.echo(f"     ... and {len(result.vulnerabilities) - 10} more vulnerabilities")

    # Generate reports
    if output or fmt != "md":
        output_dir = output or "~/Desktop/fusion_security_reports"
        reporter = ReportGenerator()
        formats = ["md", "json", "html"] if fmt == "all" else [fmt]
        saved = reporter.save_report(result, output_dir, formats, compliance_framework=compliance)
        click.echo()
        click.echo("  Reports saved:")
        for fmt_name, path in saved.items():
            click.echo(f"    📄 {fmt_name}: {path}")

    click.echo()


@cli.command()
@click.argument("path", default=".")
def check(path: str):
    """Quick check (results only, CI-friendly)."""
    asyncio.run(_async_check(path))


async def _async_check(path: str):
    # CI lightweight path: Scanner(use_ai=False), rules+AST only, no ScanPipeline. Deliberate legacy retention.
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


@cli.group(invoke_without_command=True)
@click.pass_context
def rules(ctx):
    """Detection rule management (lists all rules when no subcommand)."""
    if ctx.invoked_subcommand is None:
        from .engine.rules.engine import RuleEngine

        engine = RuleEngine()

        click.echo()
        click.echo(f"📋 Detection rules ({engine.get_rule_count()})")
        click.echo("=" * 50)
        click.echo()

        for rule in engine.get_rules():
            click.echo(f"  {rule.id:12s} [{rule.severity:8s}] {rule.name}")
            click.echo(f"  {'':12s}  {rule.description}")
            click.echo()


@rules.command(name="package")
@click.argument("rules_file", type=click.Path(exists=True))
@click.option("--name", default="custom-rules", help="Package metadata name")
@click.option("--version", "pkg_version", default="1.0.0", help="Package metadata version")
@click.option("--key", "-k", required=True, help="Ed25519 private key PEM (signing)")
@click.option("--out", "-o", required=True, help="Output .frpkg path")
def rules_package(rules_file: str, name: str, pkg_version: str, key: str, out: str):
    """Build and sign a rule package from a JSON rules file."""
    _logs_to_stderr(machine_only=True)
    from .engine.rules.packages import build_package

    rules_payload = json.loads(Path(rules_file).read_text(encoding="utf-8"))
    if not isinstance(rules_payload, list):
        rules_payload = rules_payload.get("rules", [])
    metadata = {"name": name, "version": pkg_version}
    pkg = build_package(metadata, rules_payload, Path(out).expanduser(), Path(key).expanduser())
    click.echo(json.dumps({"built": pkg.path, "digest": pkg.digest, "rules": len(pkg.rules)}))


@rules.command(name="install")
@click.argument("package_path", type=click.Path(exists=True))
@click.option("--from-file", is_flag=True, help="Install from a local .frpkg file (offline import)")
@click.option("--key", "-k", required=True, help="Ed25519 public key PEM (publisher verification)")
def rules_install(package_path: str, from_file: bool, key: str):
    """Verify and install a signed rule package (--from-file, offline)."""
    _logs_to_stderr(machine_only=True)
    from .engine.rules.packages import PackageError, install_rules, load_package
    from .engine.tenant.audit import get_audit_logger

    audit = get_audit_logger("default")
    try:
        pkg = load_package(Path(package_path).expanduser())
        installed = install_rules(pkg, Path(key).expanduser())
    except PackageError as e:
        audit.log(
            action="rule.package.rejected",
            actor="cli",
            resource_type="rule_package",
            resource_id=Path(package_path).name,
            details={"error": str(e)},
            risk_level="high",
        )
        click.echo(json.dumps({"installed": False, "error": str(e)}))
        sys.exit(1)
    audit.log(
        action="rule.package.install",
        actor="cli",
        resource_type="rule_package",
        resource_id=Path(package_path).name,
        details={"digest": pkg.digest, "rules": installed},
    )
    click.echo(json.dumps({"installed": True, "rules": installed, "digest": pkg.digest}))


@rules.command(name="keygen")
@click.argument("key_path", type=click.Path())
@click.option("--overwrite", is_flag=True, help="Overwrite an existing key pair")
def rules_keygen(key_path: str, overwrite: bool):
    """Generate an offline Ed25519 signing key pair (private + .pub)."""
    _logs_to_stderr(machine_only=True)
    from .engine.rules.packages import PackageError, generate_key_pair

    try:
        private_path = generate_key_pair(Path(key_path).expanduser(), overwrite=overwrite)
    except PackageError as e:
        click.echo(json.dumps({"error": str(e)}))
        sys.exit(1)
    click.echo(json.dumps({"private_key": str(private_path), "public_key": str(private_path) + ".pub"}))


@cli.command()
@click.option("--host", default="127.0.0.1", help="Listen address")
@click.option("--port", default=11454, help="Listen port")
def serve(host: str, port: int):
    """Start the Web API server."""
    import uvicorn

    from .api.app import app

    click.echo(f"🔒 Fusion-Security API starting: http://{host}:{port}")
    click.echo(f"   API docs: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="info")


@cli.command()
@click.argument("path", default=".")
@click.option(
    "--policy", "-p", default="standard", type=click.Choice(["strict", "standard", "permissive"]), help="Gate policy"
)
def gate(path: str, policy: str):
    """Security quality gate check (CI/CD friendly)."""
    asyncio.run(_async_gate(path, policy))


async def _async_gate(path: str, policy: str):
    # CI gate: Scanner(use_ai=False), rules only, no pipeline.
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
@click.option("--output", "-o", default="results.sarif", help="SARIF output file")
def sarif(path: str, output: str):
    """Export scan results in SARIF format."""
    asyncio.run(_async_sarif(path, output))


async def _async_sarif(path: str, output: str):
    # SARIF export: Scanner(use_ai=False), rules only, no pipeline.
    from .report.sarif import save_sarif

    target = ScanTarget(path)
    scanner = Scanner(use_ai=False)
    result = await scanner.scan(target)
    saved = save_sarif(result.vulnerabilities, output)
    click.echo(f"📄 SARIF report saved: {saved}")


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


SECRETS_DEFAULT_EXCLUDE_DIRS = {
    "node_modules",
    ".next",
    "dist",
    "build",
    "out",
    ".venv",
    "venv",
    "vendor",
    "coverage",
    "htmlcov",
    ".nyc_output",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".eggs",
}
SECRETS_DEFAULT_EXCLUDE_GLOBS = (
    "*.min.js",
    "*.min.css",
    "*.map",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
    "Podfile.lock",
)


def _secrets_path_excluded(rel_path: str, extra_excludes: tuple[str, ...] = (), use_default: bool = True) -> bool:
    parts = PurePosixPath(rel_path.replace("\\", "/")).parts
    name = parts[-1] if parts else rel_path
    if use_default:
        if any(part in SECRETS_DEFAULT_EXCLUDE_DIRS for part in parts):
            return True
        if any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(rel_path, g) for g in SECRETS_DEFAULT_EXCLUDE_GLOBS):
            return True
    for pattern in extra_excludes:
        clean = pattern.strip().strip("/")
        if not clean:
            continue
        if clean in parts or clean in rel_path or fnmatch.fnmatch(name, clean) or fnmatch.fnmatch(rel_path, clean):
            return True
    return False


def _secrets_summary(payload: dict, top_n: int = 10) -> dict:
    rule_counts = Counter(f["rule_id"] for f in payload["findings"])
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = sorted(
        payload["findings"], key=lambda f: (severity_rank.get(f.get("severity", "low"), 9), f.get("file", ""))
    )[:top_n]
    summary = {
        "mode": payload.get("mode"),
        "files_scanned": payload.get("files_scanned", 0),
        "total_findings": len(payload["findings"]),
        "rules": dict(sorted(rule_counts.items())),
        "top_findings": top,
    }
    if "commits_scanned" in payload:
        summary["commits_scanned"] = payload["commits_scanned"]
    return summary


@cli.command(name="secrets-scan")
@click.argument("target", default=".")
@click.option("--history", is_flag=True, help="Scan git history (all commits) instead of working tree")
@click.option("--base", "-b", default="", help="History incremental base ref (default: full history)")
@click.option("--max-commits", default=2000, help="Max commits to walk in history mode")
@click.option("--pretty", is_flag=True, help="Pretty-print JSON output")
@click.option("--exclude", "-e", multiple=True, help="Extra exclude pattern (repeatable): path substring or glob")
@click.option("--no-default-excludes", is_flag=True, help="Disable the built-in exclude set (node_modules, dist, ...)")
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write full JSON to this file; stdout gets a compact summary line only",
)
@click.option("--summary", is_flag=True, help="Print per-rule counts + top-10 findings to stdout instead of full JSON")
def secrets_scan(
    target: str,
    history: bool,
    base: str,
    max_commits: int,
    pretty: bool,
    exclude: tuple[str, ...],
    no_default_excludes: bool,
    output: Path | None,
    summary: bool,
):
    """Scan working tree or git history for hardcoded secrets (offline)."""
    _logs_to_stderr()
    from .engine.secrets import scan_history
    from .engine.secrets.integration import get_shared_scanner

    use_default = not no_default_excludes
    if history:
        p = Path(target).expanduser()
        try:
            result = scan_history(str(p), base=base, max_commits=max_commits)
        except (ValueError, RuntimeError) as e:
            click.echo(f"error: {e}", err=True)
            sys.exit(2)
        kept = [f for f in result.findings if not _secrets_path_excluded(f.file, exclude, use_default)]
        if len(kept) != len(result.findings):
            logger.info(f"secrets-scan: history excludes dropped {len(result.findings) - len(kept)} finding(s)")
        payload = {
            "mode": "history",
            "commits_scanned": result.commits_scanned,
            "findings": [f.to_dict() for f in kept],
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
                f
                for f in p.rglob("*")
                if f.is_file()
                and f.stat().st_size < 1_000_000
                and ".git" not in f.parts
                and not _secrets_path_excluded(
                    str(f.relative_to(p)) if f.is_relative_to(p) else str(f), exclude, use_default
                )
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

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None), encoding="utf-8")
        logger.info(f"secrets-scan: full JSON written to {output}")
        click.echo(json.dumps(_secrets_summary(payload, top_n=0), ensure_ascii=False))
    elif summary:
        click.echo(json.dumps(_secrets_summary(payload), ensure_ascii=False, indent=2 if pretty else None))
    else:
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
