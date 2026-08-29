# Deprecated / Legacy Modules

This file tracks modules deprecated due to upstream capability convergence (issue #23, decision A).

`fusion-guard` (Rust, runtime action authorization / DLP / macOS TCC audit) is the single source of truth for the **overlapping** capabilities listed below. `fusion-security` remains an active SAST tool — its core (scanner, pipeline, AI semantic analysis, SARIF, auto-fix, frontend, Helm, DB) is **untouched and not deprecated**.

## Overlap — deferred to fusion-guard

| Module | Capability | Successor (fusion-guard) | Status |
|---|---|---|---|
| `fusion_security/engine/rules/engine.py` | Rule engine (regex rule matching) | `fg-rules` (Rust) | Legacy — kept until guard reaches parity + consumers migrate |
| `fusion_security/engine/tenant/audit.py` | Tenant audit (`AuditEntry` / `AuditLogger`, JSONL `audit_{tenant}.jsonl`) | `fg-store` (Rust, +multi-tenant dimension) | Legacy — `AuditEntry` schema aligned toward guard's `AuditRecord` for mechanical migration |
| HTTP access surface `:11454` + `SecurityBridge.swift` consumer | API entrypoint consumed by fusion-studio | `fusion-guard` UDS (Rust) | Consumer migration tracked separately (see issue) |

## Why not delete now

fusion-guard has not yet reached feature parity on the overlap, and consumers (fusion-studio `SecurityBridge.swift`) have not migrated. Deleting would break the SAST product. Modules stay until:
1. fusion-guard `fg-rules` matches this engine's rule coverage.
2. fusion-guard `fg-store` absorbs the multi-tenant audit dimension.
3. fusion-studio `SecurityBridge.swift` migrates off `:11454` to fusion-guard UDS.

## Out of scope (NOT deprecated)

`fusion-security` core stays independent: `engine/scanner.py`, `engine/pipeline.py`, AI semantic analysis (fusion-mlx), `report/sarif.py`, auto-fix generation, `frontend/`, `deploy/`, `db/`.

## Refs

- Issue #23 — `arch: converge overlapping capabilities into fusion-guard (decision A)`
- `architecture/fusion-guard-prd-plan-v2-0826.md` §17, §18.1, §18.5
- `audit/fusion-guard-audit-0826.md` finding E3
