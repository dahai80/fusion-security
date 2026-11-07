---
doc_id: fusion-security/claude-guide
product: fusion-security
class: app
entry: guided-ui
doc_type: guide
title: { zh: "fusion-security Claude 工作指南", en: "fusion-security CLAUDE guide" }
audience: engineer
status: draft
version: 0.2.0rc14
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - CLAUDE.md
---

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Fusion-Security is a local AI-powered code security audit tool for macOS Apple Silicon. It scans source code for vulnerabilities using regex rules + tree-sitter AST + taint tracking + AI semantic analysis via fusion-mlx (local LLM). 100% offline, zero code upload. Exposes both a CLI and a FastAPI REST API with a React dashboard. Chinese/English bilingual UI/comments are intentional.

Current version: 0.2.0rc5 (see `fusion_security/__init__.py`). 37 built-in detection rules across 9 PRD categories.

## Build & Run Commands

```bash
source /Users/dahai/fusion/.venv/bin/activate   # monorepo shared venv, REQUIRED first

# fusion-core is an in-tree dependency (not on PyPI). In the monorepo it is an
# editable install; outside the monorepo / in CI it must come from git:
#   pip install git+https://github.com/dahai80/fusion-core.git
# (see dahai80/fusion-core#9 for the publish-track fix). Install fusion-core FIRST.
pip install -e fusion-core  # monorepo path; or the git install above

pip install -e ".[test]"   # install with test extras
pip install -e ".[lint]"   # install lint extras (ruff)

# Tests (asyncio_mode=auto, testpaths=["tests"])
pytest tests/ -v
pytest tests/test_core.py::TestRuleEngine::test_scan_sql_injection -v   # single test
pytest tests/ --cov=fusion_security --cov-report=html
pytest tests/ --cov=fusion_security --cov-fail-under=90   # CI coverage gate is 90%

# Lint / format
ruff check fusion_security/ tests/
ruff format --check fusion_security/ tests/

# CLI
fusion-security scan /path/to/project
fusion-security scan /path/to/project --pipeline --sca --severity high --format all --output ./reports
fusion-security scan /path/to/project --incremental --base HEAD~1   # git-diff only
fusion-security check /path/to/project          # CI-friendly JSON, no AI
fusion-security gate /path/to/project --policy strict   # CI quality gate, exits 1 on fail
fusion-security sarif /path/to/project --output results.sarif
fusion-security rules                            # list all detection rules
fusion-security serve --port 11454               # start FastAPI API

# API lifecycle (used by fusion-studio UpstreamServiceManager)
./start.sh start|stop|restart|status             # uvicorn on 127.0.0.1:11454, PID file .fusion-security.pid
```

## AI Backend

fusion-mlx runs locally, OpenAI-compatible API. The analyzer defaults to `http://localhost:11432/v1` (env `MLX_BASE_URL` overrides). Default model `qwen3.5-9b`; if unspecified, the analyzer auto-detects the first loaded model from `/models`, falling back to `qwen3.5-9b`. Start/stop the engine with `~/claude-home/fusion-mlx/start.sh start|stop`. When AI is unavailable, scanning gracefully degrades (rule/AST/taint results kept, AI steps skipped).

Note: the monorepo `CLAUDE.md` references fusion-mlx on port 11434, while this project's analyzer defaults to 11432. Trust the `MLX_BASE_URL` env / running instance, not the hardcoded default.

HTTP to fusion-mlx goes through `fusion_core.http_client` (`get_async_client` pooled `httpx.AsyncClient` + `with_retry`), adopted in Phase C — do not reintroduce a standalone httpx client in `engine/ai/`.

## Architecture

Two scan entry points share the same engine modules:

1. **Legacy `Scanner`** (`engine/scanner.py`) — single-pass parallel batch scan (50 files/batch) via `RuleEngine.scan_file()`, optional AI verify. Used by `check`, `gate`, `sarif`, and `scan` without `--pipeline`.
2. **`ScanPipeline`** (`engine/pipeline.py`) — 6-stage async pipeline with checkpoint/resume + circuit breaker + retry. Used by `scan --pipeline` / `--sca`. Stages run in fixed order:

   `Recon → Discover → Verify → Triage → Patch → Retest`

   - **Recon** — `ScanTarget.discover()` finds source files (multi-language, respects `max_files`/`max_file_size`, excludes .git/node_modules/.venv); also collects dependency files for SCA.
   - **Discover** — per-file `RuleEngine` regex + `TaintTracker` data-flow + AI `semantic_scan` + `SCAScanner` (OSV.dev) dependency vulns.
   - **Verify** — `AIAnalyzer.verify_findings()` (false-positive filter) + `AdversarialVerifier.verify_batch()` (cross-file adversarial check).
   - **Triage** — severity sort, severity-threshold filter, dedup by `file_path:line:rule_id`, emits `Finding` records.
   - **Patch** — `FixGenerator.generate_alternatives()` (template + AI-enhanced) for critical/high (top 20).
   - **Retest** — re-runs the rule regex against patched code to confirm the fix.

   Each stage writes a `StageCheckpoint`; on failure the `CircuitBreaker` can skip remaining stages and `RetryPolicy` retries with backoff. Pass a prior `scan_id` to `ScanPipeline.run()` to resume from the last completed stage.

**Module layout** (restructured — most logic lives under `engine/`, not the flat paths older docs describe):

```
fusion_security/
  cli.py                  click group: scan, check, rules, serve, gate, sarif
  shell_registry.py       union-web shell manifest registration + heartbeat (Issue #35, env-gated: FUSION_SHELL_GATEWAY_URL + FUSION_ADMIN_KEY)
  models.py               re-exports from models/ package (see below)
  models/                 Vulnerability, Finding, Patch, Project/Scan, Rule/RuleSet (dataclasses)
  engine/
    scanner.py            ScanTarget, ScanResult, Scanner (legacy orchestrator)
    pipeline.py           ScanPipeline + PipelineConfig + PipelineContext (6-stage)
    rules/engine.py       ScanRule + RuleEngine (37 rules, regex-based)
    rules/ast_parser.py   tree-sitter AST (9 langs: py/js/java/go/c/cpp/rust/ruby/php; ts/tsx map to js)
    rules/taint_tracker.py  source→sink data-flow tracking
    ai/analyzer.py        AIAnalyzer (fusion-mlx, fusion_core.http_client)
    ai/adversarial.py     AdversarialVerifier
    fix/fix_generator.py  FixGenerator (template fixes + AI enhancement)
    fix/patch_verify.py
    sca/scanner.py        SCAScanner (OSV.dev dependency vulns)
    scoring/              cvss, confidence, compliance
    resume/               CheckpointManager, CircuitBreaker, RetryPolicy, StageCheckpoint
    queue/task_queue.py
    vcs/git.py            GitHelper (changed-file diff for incremental scan)
    ci/                   gate (quality gate), notifier (Feishu/DingTalk), webhook, jira
    tenant/               audit logger (AuditLogger); TenantManager/Tenant RETIRED (RuntimeError stubs, Issue #32) — tenant identity now from fusion-identity
    identity/             fusion-identity client (IdentityVerifyClient: JWT verify + quota cache + usage report) + make_verify_jwt() callback
    feedback/             feedback loop
    dashboard.py, scheduler.py, cache.py
  api/
    app.py                create_app() — 8 routers under /api/v1/*, lifespan inits DB + master API key; install_tenant_middleware (fusion_core.tenant, require_jwt=False)
    auth.py               dual-mode principal: get_principal (X-API-Key OR Bearer JWT), fail-closed tenant check; RBAC roles admin/operator/viewer; get_current_key alias
    middleware.py         rate limiting + per-tenant scan quota (quota from fusion-identity cache or FUSION_MAX_CONCURRENT_SCANS)
    routes/               projects, scans, vulnerabilities, patches, reports, integrations, system, schedules
  db/
    session.py            SQLAlchemy + SQLite (sync + async aiosqlite), WAL, foreign_keys ON
    models.py             ORM models; convert.py ↔ dataclass conversion
  report/                 report.py (md/json/html via jinja2), sarif.py
  integrations/
```

**Data models:** `fusion_security/models.py` is a thin re-export shim over the `models/` package — import from `fusion_security.models` (or `fusion_security.models.vulnerability` etc.), not the old `rules/engine.py` path. `Vulnerability` is the shared dataclass threaded through every stage.

**Database:** default `~/.fusion-security/fusion_security.db` (SQLite, WAL mode, `StaticPool`). Set `FUSION_SECURITY_DB_URL` (full SQLAlchemy URL, e.g. `postgresql+asyncpg://...`) for a shared/multi-node DB — overrides the SQLite default; `docker-compose.postgres.yml` is the compose override for this (password from `POSTGRES_PASSWORD` env, never hardcoded). Resolution priority: explicit `db_url` arg > explicit `db_path` arg > `FUSION_SECURITY_DB_URL` > `FUSION_DB_PATH` > default. `init_db()` is sync; `init_async_db()` is async (aiosqlite). The FastAPI `lifespan` calls `init_db()` on startup and creates a `master` admin API key. ORM models in `db/models.py` are separate from the `models/` dataclasses; `db/convert.py` bridges them.

**API:** FastAPI on `127.0.0.1:11454` (env `FUSION_SECURITY_PORT` / `FUSION_SECURITY_HOST`). 8 routers under `/api/v1/` (projects, scans, vulnerabilities, patches, reports, integrations, system, schedules) plus `/api/v1/keys` auth endpoints. CORS origins from env `FUSION_CORS_ORIGINS` (default localhost:3000,8080); `allow_headers` includes `X-API-Key`, `X-Tenant-Id`, `Content-Type`. **Auth (Issue #32): dual-mode** — `TenantMiddleware` (from `fusion_core.tenant`, `require_jwt=False`) enforces mandatory `X-Tenant-Id` header + verifies Bearer JWT via `fusion-identity` (`/api/v1/auth/verify`, env `FUSION_IDENTITY_URL` default 11470 + `FUSION_IDENTITY_SERVICE_TOKEN`). `get_principal` then fail-closed checks: empty-tenant API key → 401, key/JWT tenant ≠ header → 401, cross-tenant record → 404. API-key-only requests proceed without consulting identity (degrade). Per-tenant concurrent-scan quota from identity `quota.max_concurrent_scans` or `FUSION_MAX_CONCURRENT_SCANS`. The `master` key (admin) is auto-created at startup. `/api/v1/system/health` is public (exempt from tenant middleware) — used by `start.sh`/fusion-studio health checks. Local `TenantManager`/`fs_tenant_`/`tenants.json` are RETIRED (RuntimeError stubs).

**Frontend:** React 18 + Ant Design 5 + Vite + TypeScript dashboard in `frontend/` (`npm run dev` / `vite build`). Dual-mode (Issue #35): standalone dev server on `:11476` (registered in port-registry.yaml), or union-web remote module — `frontend/manifest.json` (category=domain, devices desktop+desktop-only), embedded via same-origin iframe at `/shell/fusion-security/?embedded=1`, API calls through `@fusion/web-sdk` postMessage bridge (vendored at `frontend/vendor/@fusion/web-sdk`). Non-JWT-shaped Bearer tokens (gateway module proxy injects `Bearer <module API key>`) are validated as API keys by `get_principal` with the same fail-closed tenant checks. Issue #40: when `frontend/dist/` is built, `create_app` serves it via `SPAStaticFiles` at `/` and `/shell/fusion-security/` (client-route fallback to index.html; `_mount_spa` MUST be called after all `include_router` calls — a Mount at `/` registered earlier shadows every API route). SPA paths are exempt from TenantMiddleware via `_SpaExemptPaths` (prefix-matching frozenset subclass); `/api/*` keeps full fail-closed auth. `shell_registry.register_once` sends `api_key` (env `FUSION_SECURITY_SHELL_API_KEY`) in the registration body so the gateway proxy injects a valid upstream credential.

**Deploy:** `Dockerfile` + `docker-compose.yml` at root (`docker-compose.postgres.yml` override adds shared PostgreSQL for multi-node); Helm chart in `deploy/helm/`; GitHub Action in `ci/github/action.yml`; GitLab CI in `ci/gitlab/.gitlab-ci.yml`. CI (`.github/workflows/ci.yml`) runs ruff lint+format-check, pytest on Python 3.12, coverage gate 90%, then `python -m build`. CI runs on 3.12 only — fusion-core (in-tree dep, installed from git in CI) pins `requires-python>=3.12`, so 3.11 jobs cannot install it. CI also installs `fusion-identity` from git (sibling dep, no PyPI release — same as fusion-core). `docs/` holds API reference, benchmark methodology, and security self-assessment reports.

## Conventions

- Python ≥3.12 (monorepo unified version; fusion-core pins `>=3.12`), 4-space indentation (multiples of 4, never 5/9/11)
- No docstrings in code; module-level `"""..."""` docstring headers are the established style and may be kept
- All modules must have logging (`logger = logging.getLogger(__name__)`) and emit stage/step logs for traceability
- Shared data models live in `models/` (re-exported by top-level `models.py`) — do not duplicate across modules
- `report/report.py` imports `ScanResult` from `engine.scanner` (not a `Vulnerability` from `models/`) — existing pattern, don't change
- Chinese comments and UI text are intentional (bilingual product); do not translate away or mix EN/CN within a single file
- Ruff config: `target-version=py312`, `line-length=120`, select `E,F,W,I,UP,B,SIM,C4`, ignore `E501,B008`; `quote-style=double`, `indent-style=space`
- Tests use `pytest` + `pytest-asyncio` (`asyncio_mode=auto`, `testpaths=["tests"]`); `tests/conftest.py` sets `FUSION_RATE_LIMIT=0` (disables rate limiting — high-frequency test requests would otherwise 429)
