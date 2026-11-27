"""Fusion-Security 6-stage scan pipeline — Recon→Discover→Verify→Triage→Patch→Retest."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..models.finding import Finding
from ..models.patch import Patch
from ..models.vulnerability import Vulnerability
from .ai.adversarial import AdversarialVerifier
from .ai.analyzer import AIAnalyzer
from .fix.fix_generator import FixGenerator
from .resume import CheckpointManager, CircuitBreaker, RetryPolicy, StageCheckpoint
from .rules.ast_parser import ASTParser
from .rules.engine import RuleEngine
from .rules.taint_tracker import TaintTracker
from .sca.scanner import SCAScanner
from .scanner import ScanResult, ScanTarget
from .secrets.integration import secrets_vulnerabilities

logger = logging.getLogger(__name__)


class PipelineStage(StrEnum):
    RECON = "recon"
    DISCOVER = "discover"
    VERIFY = "verify"
    TRIAGE = "triage"
    PATCH = "patch"
    RETEST = "retest"


@dataclass
class PipelineContext:
    scan_id: str = ""
    project_path: str = ""
    files: list[Path] = field(default_factory=list)
    language_stats: dict[str, int] = field(default_factory=dict)
    dependency_files: list[Path] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    current_stage: PipelineStage = PipelineStage.RECON
    stage_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = f"scan_{uuid.uuid4().hex[:12]}"


@dataclass
class PipelineConfig:
    use_ai: bool = True
    model: str = ""
    severity_threshold: str = "low"
    enable_taint: bool = True
    enable_adversarial: bool = True
    enable_sca: bool = True
    # P1.2: secrets module (entropy + provider validators), offline by default.
    enable_secrets: bool = True
    # OSV.dev is a cloud dependency vulnerability database; disabled by default to keep the 100% offline promise.
    # Enabling it sends the dependency manifest to https://osv.dev and requires explicit user consent.
    enable_osv: bool = False
    enable_patch: bool = True
    batch_size: int = 50
    max_files: int = 10000
    max_file_size: int = 1 * 1024 * 1024


STAGE_ORDER = [
    PipelineStage.RECON,
    PipelineStage.DISCOVER,
    PipelineStage.VERIFY,
    PipelineStage.TRIAGE,
    PipelineStage.PATCH,
    PipelineStage.RETEST,
]


class ScanPipeline:
    def __init__(
        self,
        config: PipelineConfig | None = None,
        db=None,
        project_id: str = "",
        tenant_id: str = "",
    ):
        self.config = config or PipelineConfig()
        self.tenant_id = tenant_id
        # Feature 1: load tenant custom rules into the RuleEngine (load failure does not block the scan; falls back to built-in rules).
        custom_rules = self._load_custom_rules(tenant_id)
        self.rule_engine = RuleEngine(custom_rules=custom_rules)
        self.ast_parser = ASTParser()
        self.taint_tracker = TaintTracker()
        self.ai_analyzer = AIAnalyzer(model=self.config.model) if self.config.use_ai else None
        self.adversarial = (
            AdversarialVerifier(self.ai_analyzer) if self.config.enable_adversarial and self.ai_analyzer else None
        )
        self.fix_generator = FixGenerator()
        self.sca_scanner = SCAScanner(use_osv=self.config.enable_osv) if self.config.enable_sca else None
        self.checkpoint_mgr = CheckpointManager()
        self.circuit_breaker = CircuitBreaker()
        self.retry_policy = RetryPolicy()
        self.project_id = project_id
        self._db = db
        self._project_cache = None
        if project_id and db:
            from .cache import ProjectScanCache

            self._project_cache = ProjectScanCache(db)

    def _load_custom_rules(self, tenant_id: str = ""):
        # Feature 1: load tenant-enabled custom rules from CustomRuleStore.
        # On load failure fall back to built-in rules without blocking the scan.
        if not tenant_id:
            return []
        try:
            from .rules.custom import CustomRuleStore

            store = CustomRuleStore()
            active = store.get_active_rules(tenant_id)
            logger.info(f"[Pipeline] tenant {tenant_id} loaded {len(active)} custom rules")
            return active
        except Exception as e:
            logger.warning(f"[Pipeline] custom rule load failed, falling back to built-in rules: {e}")
            return []

    async def run(
        self, path: str, changed_files: list[str] | None = None, scan_id: str | None = None
    ) -> PipelineContext:
        resume_from = None
        if scan_id:
            cp = self.checkpoint_mgr.load(scan_id)
            if cp and cp.completed_stage:
                resume_from = cp.completed_stage
                logger.info(f"[Pipeline] resumable scan scan_id={scan_id} resumed from {resume_from}")

        ctx = PipelineContext(project_path=path)
        if scan_id:
            ctx.scan_id = scan_id

        if resume_from:
            cp = self.checkpoint_mgr.load(scan_id)
            if cp and cp.stage_data:
                ctx.language_stats = cp.stage_data.get("language_stats", {})
                ctx.dependency_files = [Path(p) for p in cp.stage_data.get("dependency_files", [])]
                ctx.files = [Path(p) for p in cp.stage_data.get("files", [])]
                ctx.vulnerabilities = [Vulnerability.from_dict(v) for v in cp.stage_data.get("vulnerabilities", [])]
                ctx.findings = [Finding.from_dict(f) for f in cp.stage_data.get("findings", [])]
                ctx.patches = [Patch.from_dict(p) for p in cp.stage_data.get("patches", [])]
                logger.info(
                    f"[Pipeline] restored state vulns={len(ctx.vulnerabilities)} "
                    f"findings={len(ctx.findings)} patches={len(ctx.patches)}"
                )
        else:
            self.circuit_breaker.reset()
            logger.debug("[Pipeline] circuit breaker reset (new scan)")

        logger.info(f"[Pipeline] start scan_id={ctx.scan_id} resume_from={resume_from}")

        stage_methods = {
            PipelineStage.RECON: lambda: self._stage_recon(ctx, changed_files),
            PipelineStage.DISCOVER: lambda: self._stage_discover(ctx),
            PipelineStage.VERIFY: lambda: self._stage_verify(ctx),
            PipelineStage.TRIAGE: lambda: self._stage_triage(ctx),
            PipelineStage.PATCH: lambda: self._stage_patch(ctx),
            PipelineStage.RETEST: lambda: self._stage_retest(ctx),
        }

        start_idx = 0
        if resume_from:
            for i, stage in enumerate(STAGE_ORDER):
                if stage.value == resume_from:
                    start_idx = i + 1
                    break

        for stage in STAGE_ORDER[start_idx:]:
            if not self.circuit_breaker.allow_request():
                logger.error(f"[Pipeline] circuit breaker open, skipping stage={stage.value}")
                ctx.errors.append(f"circuit breaker open, skipped {stage.value}")
                break

            success = False
            last_error = None
            for attempt in range(self.retry_policy.max_retries + 1):
                try:
                    await stage_methods[stage]()
                    success = True
                    self.circuit_breaker.record_success()
                    cp = StageCheckpoint(
                        scan_id=ctx.scan_id,
                        project_path=ctx.project_path,
                        completed_stage=stage.value,
                        stage_data={
                            "files": [str(p) for p in ctx.files],
                            "language_stats": ctx.language_stats,
                            "dependency_files": [str(p) for p in ctx.dependency_files],
                            "vulnerabilities": [v.to_dict() for v in ctx.vulnerabilities],
                            "findings": [f.to_dict() for f in ctx.findings],
                            "patches": [p.to_dict() for p in ctx.patches],
                            "stage_results": {k: self._sanitize_stage_result(v) for k, v in ctx.stage_results.items()},
                        },
                        errors=ctx.errors,
                    )
                    self.checkpoint_mgr.save(cp)
                    break
                except Exception as e:
                    last_error = e
                    logger.warning(f"[Pipeline] stage={stage.value} failed attempt={attempt + 1}: {e}")
                    self.circuit_breaker.record_failure()
                    if attempt < self.retry_policy.max_retries:
                        delay = self.retry_policy.get_delay(attempt)
                        logger.info(f"[Pipeline] retry wait {delay:.1f}s")
                        await asyncio.sleep(delay)

            if not success:
                # F-P0: after retries are exhausted a stage must stop the pipeline; previously only an error was logged and later stages kept running, silently swallowing the failure.
                logger.error(f"[Pipeline] stage={stage.value} final failure, terminating pipeline: {last_error}")
                ctx.errors.append(f"{stage.value}: {last_error}")
                ctx.stage_results.setdefault("pipeline", {})["failed_stage"] = stage.value
                break

        if self.ai_analyzer:
            await self.ai_analyzer.aclose()
        self.checkpoint_mgr.remove(ctx.scan_id)
        logger.info(f"[Pipeline] done scan_id={ctx.scan_id} vulns={len(ctx.vulnerabilities)}")
        return ctx

    async def _stage_recon(self, ctx: PipelineContext, changed_files: list[str] | None = None) -> None:
        ctx.current_stage = PipelineStage.RECON
        start = time.time()
        logger.info("[Recon] recon stage started")

        target = ScanTarget(ctx.project_path, max_files=self.config.max_files, max_file_size=self.config.max_file_size)
        if changed_files:
            ctx.files = target.discover_incremental(changed_files)
        else:
            ctx.files = target.discover()

        for f in ctx.files:
            lang = self._detect_language(f)
            ctx.language_stats[lang] = ctx.language_stats.get(lang, 0) + 1

        dep_patterns = [
            "requirements*.txt",
            "Pipfile",
            "pyproject.toml",
            "setup.py",
            "package.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "go.mod",
            "go.sum",
            "pom.xml",
            "build.gradle*",
            "Cargo.toml",
            "Gemfile",
        ]
        for pattern in dep_patterns:
            for df in Path(ctx.project_path).rglob(pattern):
                if not any(p in df.parts for p in {".git", "node_modules", ".venv", "__pycache__"}):
                    ctx.dependency_files.append(df)

        ctx.stage_results["recon"] = {
            "files": len(ctx.files),
            "languages": dict(ctx.language_stats),
            "dependency_files": len(ctx.dependency_files),
            "duration_ms": (time.time() - start) * 1000,
        }
        logger.info(
            f"[Recon] done files={len(ctx.files)} langs={list(ctx.language_stats.keys())} deps={len(ctx.dependency_files)}"
        )

    async def _stage_discover(self, ctx: PipelineContext) -> None:
        ctx.current_stage = PipelineStage.DISCOVER
        start = time.time()
        logger.info("[Discover] vulnerability discovery stage started")

        all_vulns: list[Vulnerability] = []
        scan_failed = 0
        root = Path(ctx.project_path)

        async def scan_file(f: Path) -> list[Vulnerability]:
            nonlocal scan_failed
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                # Skip rule/taint recomputation on DB cache hits so a resumed scan re-running Discover does not burn compute twice.
                if self._project_cache:
                    rel = str(f.relative_to(root)) if f.is_relative_to(root) else str(f)
                    cached = self._project_cache.get(self.project_id, rel, content)
                    if cached is not None:
                        return cached
                vulns = self.rule_engine.scan_file(f, content)
                # A-P0-1: the pipeline previously ran regex only (scan_file), losing the Scanner's AST coverage.
                # Use scan_file_full (regex+AST) uniformly, equivalent to the retired Scanner, to avoid misses.
                vulns.extend(self.rule_engine.scan_file_ast(f, content))
                if self.config.enable_taint:
                    taint_result = self.taint_tracker.analyze(f, content)
                    for tp in taint_result.taint_paths:
                        if not tp.is_sanitized:
                            v = Vulnerability(
                                id=f"V-{uuid.uuid4().hex[:8]}",
                                title=f"Taint tracking: {tp.source} → {tp.sink}",
                                description=f"Data flows from {tp.source} to the dangerous operation {tp.sink} without proper sanitization",
                                severity="high",
                                confidence=70,
                                file_path=str(f),
                                line_number=tp.sink.line or 0,
                                code_snippet=tp.sink.name,
                                rule_id="TAINT-001",
                                data_flow_path=" → ".join(str(p.get("name", p.get("type", ""))) for p in tp.propagation)
                                if tp.propagation
                                else f"{tp.source.name} → {tp.sink.name}",
                            )
                            vulns.append(v)
                if self.config.enable_secrets:
                    # P1.2: secrets module as Discover sub-step (entropy +
                    # provider validators + allowlist), severity feeds gate.
                    # Runs before the cache put so cached results include it.
                    vulns.extend(secrets_vulnerabilities(f, content, root))
                if self._project_cache:
                    rel = str(f.relative_to(root)) if f.is_relative_to(root) else str(f)
                    self._project_cache.put(self.project_id, rel, content, vulns, commit=False)
                return vulns
            except Exception as e:
                scan_failed += 1
                logger.warning(f"[Discover] scan failed {f}: {e}")
                return []

        for i in range(0, len(ctx.files), self.config.batch_size):
            batch = ctx.files[i : i + self.config.batch_size]
            batch_results = await asyncio.gather(*[scan_file(f) for f in batch], return_exceptions=True)
            for findings in batch_results:
                if isinstance(findings, list):
                    all_vulns.extend(findings)

        if scan_failed:
            ctx.errors.append(f"discover {scan_failed} file scan failures")
            logger.warning(f"[Discover] {scan_failed} files failed to scan in total")

        if self._project_cache:
            self._project_cache.flush()

        if self.ai_analyzer and ctx.files:
            try:
                semantic = await self.ai_analyzer.semantic_scan(ctx.files)
                all_vulns.extend(semantic)
            except Exception as e:
                logger.warning(f"[Discover] AI semantic scan failed: {e}")
                ctx.errors.append(f"discover AI semantic scan failed: {e}")
                self.circuit_breaker.record_failure()

        if self.sca_scanner and ctx.dependency_files:
            try:
                sca_vulns = self.sca_scanner.scan(ctx.project_path)
                all_vulns.extend(sca_vulns)
                logger.info(f"[Discover] SCA found {len(sca_vulns)} dependency vulnerabilities")
            except Exception as e:
                logger.warning(f"[Discover] SCA scan failed: {e}")
                ctx.errors.append(f"discover SCA scan failed: {e}")
                self.circuit_breaker.record_failure()

        ctx.vulnerabilities = all_vulns
        ctx.stage_results["discover"] = {
            "vulnerabilities": len(all_vulns),
            "files_skipped": scan_failed,
            "duration_ms": (time.time() - start) * 1000,
        }
        logger.info(f"[Discover] done vulns={len(all_vulns)} files_skipped={scan_failed}")

    async def _stage_verify(self, ctx: PipelineContext) -> None:
        ctx.current_stage = PipelineStage.VERIFY
        start = time.time()
        logger.info(f"[Verify] adversarial verification stage started vulns={len(ctx.vulnerabilities)}")

        if not ctx.vulnerabilities:
            ctx.stage_results["verify"] = {"verified": 0, "duration_ms": 0}
            return

        verify_ok = True
        if self.ai_analyzer:
            try:
                ctx.vulnerabilities = await self.ai_analyzer.verify_findings(ctx.vulnerabilities, ctx.files)
            except Exception as e:
                verify_ok = False
                logger.warning(f"[Verify] AI verification failed: {e}")
                ctx.errors.append(f"verify AI verification failed: {e}")
                self.circuit_breaker.record_failure()

        if self.adversarial and ctx.vulnerabilities:
            try:
                file_contents = {}
                # P-P1: silently truncated to the first 100 files, limiting cross-file adversarial verification coverage; log explicitly to avoid assuming full coverage.
                sample_files = ctx.files[:100]
                if len(ctx.files) > len(sample_files):
                    logger.warning(
                        f"[Verify] adversarial verification sampled only first {len(sample_files)}/{len(ctx.files)} files"
                    )
                for f in sample_files:
                    with contextlib.suppress(Exception):
                        file_contents[str(f)] = f.read_text(encoding="utf-8", errors="ignore")
                ctx.vulnerabilities = await self.adversarial.verify_batch(ctx.vulnerabilities, file_contents)
            except Exception as e:
                verify_ok = False
                logger.warning(f"[Verify] adversarial verification failed: {e}")
                ctx.errors.append(f"verify adversarial verification failed: {e}")
                self.circuit_breaker.record_failure()

        # Only mark verified when verification actually succeeded; keep verified=False on failure so unverified vulns are not reported as verified.
        if verify_ok:
            for v in ctx.vulnerabilities:
                v.verified = True
        else:
            logger.warning("[Verify] verification did not complete successfully, vulnerabilities keep verified=False")

        ctx.stage_results["verify"] = {
            "verified": len(ctx.vulnerabilities),
            "duration_ms": (time.time() - start) * 1000,
        }
        logger.info(f"[Verify] done verified={len(ctx.vulnerabilities)}")

    async def _stage_triage(self, ctx: PipelineContext) -> None:
        ctx.current_stage = PipelineStage.TRIAGE
        start = time.time()
        logger.info("[Triage] triage stage started")

        # Feature 2: filter false positives via the feedback store first (previously unwired, so duplicate false positives re-entered triage).
        # filter_vulnerabilities has no DB dependency internally; on failure degrade to no filtering.
        before_fp = len(ctx.vulnerabilities)
        try:
            from .feedback.loop import FeedbackStore

            ctx.vulnerabilities = FeedbackStore().filter_vulnerabilities(ctx.vulnerabilities)
        except Exception as e:
            logger.warning(f"[Triage] feedback filtering failed, degrading to no filtering: {e}")
        filtered_fp = before_fp - len(ctx.vulnerabilities)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ctx.vulnerabilities.sort(key=lambda v: (severity_order.get(v.severity, 3), -v.confidence))

        threshold = severity_order.get(self.config.severity_threshold, 3)
        ctx.vulnerabilities = [v for v in ctx.vulnerabilities if severity_order.get(v.severity, 3) <= threshold]

        seen: set[str] = set()
        deduped: list[Vulnerability] = []
        for v in ctx.vulnerabilities:
            key = f"{v.file_path}:{v.line_number}:{v.rule_id}"
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        ctx.vulnerabilities = deduped

        for v in ctx.vulnerabilities:
            finding = Finding(
                vuln_id=v.id,
                scan_id=ctx.scan_id,
                file_path=v.file_path,
                line_number=v.line_number,
                code_snippet=v.code_snippet,
                data_flow_path=v.data_flow_path,
                confidence=v.confidence,
            )
            ctx.findings.append(finding)

        ctx.stage_results["triage"] = {
            "total": len(ctx.vulnerabilities),
            "filtered_false_positive": filtered_fp,
            "critical": sum(1 for v in ctx.vulnerabilities if v.severity == "critical"),
            "high": sum(1 for v in ctx.vulnerabilities if v.severity == "high"),
            "medium": sum(1 for v in ctx.vulnerabilities if v.severity == "medium"),
            "low": sum(1 for v in ctx.vulnerabilities if v.severity == "low"),
            "deduped": len(seen),
            "duration_ms": (time.time() - start) * 1000,
        }
        logger.info(f"[Triage] done total={len(ctx.vulnerabilities)}")

    async def _stage_patch(self, ctx: PipelineContext) -> None:
        ctx.current_stage = PipelineStage.PATCH
        start = time.time()
        logger.info("[Patch] patch generation stage started")

        if not self.config.enable_patch or not ctx.vulnerabilities:
            ctx.stage_results["patch"] = {"patches": 0, "duration_ms": 0}
            return

        critical_high = [v for v in ctx.vulnerabilities if v.severity in ("critical", "high")]
        for v in critical_high[:20]:
            try:
                alt_patches = self.fix_generator.generate_alternatives(v, max_strategies=3)
                for patch in alt_patches:
                    if self.ai_analyzer:
                        try:
                            patch = await self.fix_generator.ai_enhance_fix(patch)
                        except Exception as e:
                            logger.warning(f"[Patch] AI enhancement failed, keeping template patch {v.id}: {e}")
                    patch.vuln_id = v.id
                    patch.scan_id = ctx.scan_id
                    ctx.patches.append(patch)
            except Exception as e:
                logger.debug(f"[Patch] patch generation failed {v.id}: {e}")

        ctx.stage_results["patch"] = {
            "patches": len(ctx.patches),
            "duration_ms": (time.time() - start) * 1000,
        }
        logger.info(f"[Patch] done patches={len(ctx.patches)}")

    async def _stage_retest(self, ctx: PipelineContext) -> None:
        ctx.current_stage = PipelineStage.RETEST
        start = time.time()
        logger.info("[Retest] post-fix retest stage started")

        if not ctx.patches:
            ctx.stage_results["retest"] = {"retested": 0, "passed": 0, "failed": 0, "duration_ms": 0}
            return

        import re as _re

        retested = 0
        passed = 0
        failed = 0
        for patch in ctx.patches:
            if patch.status not in ("applied", "verified"):
                continue
            retested += 1
            patched_code = patch.patched_code
            vuln = next((v for v in ctx.vulnerabilities if v.id == patch.vuln_id), None)
            if not vuln:
                continue
            rule = next((r for r in self.rule_engine.get_rules() if r.id == vuln.rule_id), None)
            if not rule or not rule.pattern:
                patch.verified = True
                passed += 1
                continue
            try:
                match = _re.search(rule.pattern, patched_code, _re.IGNORECASE | _re.DOTALL)
                if not match:
                    patch.verified = True
                    patch.status = "verified"
                    passed += 1
                else:
                    patch.verified = False
                    failed += 1
            except Exception as e:
                # Regex exceptions (catastrophic backtracking/invalid escapes) must not fail-open and pass, otherwise a bad patch ships as "verified".
                logger.warning(f"[Retest] retest regex exception, judged failed {patch.vuln_id}: {e}")
                patch.verified = False
                failed += 1

        ctx.stage_results["retest"] = {
            "retested": retested,
            "passed": passed,
            "failed": failed,
            "duration_ms": (time.time() - start) * 1000,
        }
        logger.info(f"[Retest] done retested={retested} passed={passed} failed={failed}")

    def _sanitize_stage_result(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {str(k): self._sanitize_stage_result(v) for k, v in data.items()}
        if isinstance(data, (list, tuple)):
            return [self._sanitize_stage_result(v) for v in data]
        if isinstance(data, Path):
            return str(data)
        if isinstance(data, float):
            return round(data, 3)
        return data

    def _detect_language(self, path: Path) -> str:
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "jsx",
            ".tsx": "tsx",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".php": "php",
            ".rb": "ruby",
            ".swift": "swift",
            ".kt": "kotlin",
            ".scala": "scala",
            ".cs": "csharp",
        }
        return ext_map.get(path.suffix, "unknown")

    def to_scan_result(self, ctx: PipelineContext) -> ScanResult:
        target = ScanTarget(ctx.project_path)
        target.files = ctx.files
        result = ScanResult(target)
        result.vulnerabilities = ctx.vulnerabilities
        # A-P0-1: findings/patches were previously dropped and unreachable from the API. Now passed through to ScanResult for route persistence.
        result.findings = ctx.findings
        result.patches = ctx.patches
        result.files_scanned = len(ctx.files)
        # Pass through the scan failure count recorded in Discover (files_skipped was previously always 0, skewing reconciliation).
        result.files_skipped = ctx.stage_results.get("discover", {}).get("files_skipped", 0)

        triage = ctx.stage_results.get("triage", {})
        total_ms = sum(r.get("duration_ms", 0) for r in ctx.stage_results.values())
        result.duration_ms = total_ms

        t = triage.get("total", len(ctx.vulnerabilities))
        if t == 0:
            result.summary = "✅ No security vulnerabilities found"
        else:
            parts = [f"Found {t} security vulnerabilities"]
            for sev in ("critical", "high", "medium", "low"):
                c = triage.get(sev, 0)
                if c:
                    parts.append(f"{sev}: {c}")
            result.summary = " | ".join(parts)

        return result
