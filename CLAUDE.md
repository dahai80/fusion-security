# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Fusion-Security is a local AI-powered code security audit tool for macOS Apple Silicon. It scans source code for vulnerabilities using regex-based rules + AI semantic analysis via fusion-mlx (local LLM at `localhost:8000`). 100% offline, zero code upload. Chinese/English bilingual UI.

## Build & Run Commands

```bash
source .venv/bin/activate

# Install (editable)
pip install -e .

# Install with test deps
pip install -e ".[test]"

# Run all tests
pytest tests/ -v

# Run single test file / test class / test method
pytest tests/test_core.py -v
pytest tests/test_core.py::TestRuleEngine -v
pytest tests/test_core.py::TestRuleEngine::test_scan_sql_injection -v

# Run with coverage
pytest tests/ --cov=fusion_security --cov-report=html

# CLI usage
fusion-security scan /path/to/project
fusion-security scan /path/to/project --no-ai --severity high --format html --output ./reports
fusion-security check /path/to/project          # CI-friendly JSON output
fusion-security rules                            # List all detection rules
```

## Architecture

```
CLI (click) → Scanner → RuleEngine (regex pattern matching, 15 rules)
                    → AIAnalyzer (fusion-mlx HTTP, verify + semantic)
                    → FixGenerator (template + AI-enhanced patches)
                    → ReportGenerator (md/json/html)
```

**Data flow:**
1. `ScanTarget.discover()` — finds source files (multi-language, respects size/count limits, excludes .git/node_modules/.venv etc.)
2. `Scanner.scan()` — parallel batch scan (50 files/batch) via `RuleEngine.scan_file()` (regex match per rule per file)
3. If AI enabled: `AIAnalyzer.verify_findings()` — sends each finding to fusion-mlx for adversarial verification (filters false positives), then `AIAnalyzer.semantic_scan()` — cross-file logic flaw detection
4. Severity filtering, summary generation
5. `ReportGenerator` saves md/json/html; `FixGenerator` produces template diffs or AI-enhanced patches

**Key modules:**
- `fusion_security/models.py` — shared `Vulnerability` dataclass (used by all modules)
- `fusion_security/scanner/scanner.py` — `ScanTarget`, `ScanResult`, `Scanner` (orchestrator)
- `fusion_security/rules/engine.py` — `ScanRule` dataclass + `RuleEngine` (15 built-in rules, regex-based)
- `fusion_security/ai/analyzer.py` — `AIAnalyzer` (httpx async client to fusion-mlx OpenAI-compatible API)
- `fusion_security/fix/fix_generator.py` — `FixPatch`, `FixGenerator` (template fixes for SQL001/CMD001/XSS001/SEC001, AI enhancement optional)
- `fusion_security/report/report.py` — `ReportGenerator` (md/json/html output)
- `fusion_security/cli.py` — click CLI group with `scan`, `check`, `rules` commands

## AI Backend

fusion-mlx runs locally at `http://localhost:8000/v1` (OpenAI-compatible API). Start/stop with:
```bash
~/claude-home/fusion-mlx/start.sh start|stop
```
Default model: `qwen3.5-9b`. When AI is unavailable, the scanner gracefully degrades (rule results kept, AI steps skipped).

## Conventions

- Python 3.11+, 4-space indentation (multiples of 4, never 5/9/11)
- No docstrings in code
- All modules must have logging (`logger = logging.getLogger(__name__)`)
- Shared data models live in `models.py` — not duplicated across modules
- Chinese comments and UI text are intentional (bilingual product)
- `report.py` imports `Vulnerability` from `rules/engine.py` (not `models.py`) — existing pattern, don't change
- Tests use `pytest` + `pytest-asyncio` (asyncio_mode = "auto")
