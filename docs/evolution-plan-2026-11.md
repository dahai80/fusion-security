---
doc_id: fusion-security/evolution-plan-2026-11
product: fusion-security
class: app
entry: developer
doc_type: architecture
title: { zh: "fusion-security 演进计划（2026-11）", en: "fusion-security evolution plan (2026-11)" }
audience: engineer
status: draft
version: 0.2.0rc17
updated: 2026-11-12
owner: "@dahai"
source_of_truth:
  - docs/evolution-plan-2026-11.md
---

# fusion-security Evolution Plan: Capability Catch-Up and Overtake (2026-11)

> Status: PROPOSED (plan only; no production impact).
> Branch: `plan/evolution-2026-11`. Input: `~/fusion/insight/fusion-security-evolution-2026-11.md` (industry insight, 2026-11-12).
> Scope: turns the insight's gap table (S1-S8) and three-phase roadmap into a concrete, testable delivery plan for this repo.

## 1. Where we stand

fusion-security v0.2.0rc15 is an offline-first code security scanning platform (6-stage pipeline, SAST/SCA/AI verify, CI gate, multi-tenant, 930+ tests). It is NOT an agent-security product:

- No prompt-injection detection, no LLM input/output guardrails (S2)
- No MCP/skills/agent-asset scanning — the industry already productized this (SkillSpector 25.5k stars) (S1)
- No dedicated secrets module (entropy + validators + git history) — only SAST regex (S4)
- No rule package format/signing; 46 hardcoded rules (S6)
- No LLM robustness self-test for our own AIAnalyzer (S7)
- Weak compliance mapping (compliance.py ~60 lines) (S8)
- No sandbox execution profile (S5)
- **Overtaking opportunity**: agent IAM — production-grade agent permission frameworks are absent in OSS (<100 stars); fusion-harness already ships the best-in-repo deny-first permission engine, but security does not consume or feed it (S3)

## 2. Defense lines (never violated by any item below)

1. **Offline-first**: no new default outbound calls. Agent scanning, guardrails, self-tests all run local (fusion-mlx / local datasets). OSV remains the only opt-in exception.
2. **Tenant + audit chassis**: every new module registers through the existing AuthManager / audit JSONL / rate-limit middleware. No parallel auth or logging stacks.
3. **Harness boundary**: security provides threat intel and policy inputs; harness keeps execution and deny-first decisions. We do NOT build a second permission engine.
4. **Evaluation discipline**: every detection rule ships with positive/negative sample validators; our LLM components must pass a local injection regression set before release.
5. **CI contract additive-only**: SecurityGate / SARIF / Jira integrations keep their current shapes; evolution adds, never breaks.

## 3. Phase 1 — tickets to the agent era (0-3 months)

Goal: close the two red gaps that block us from being taken seriously in the agent era, plus self-hardening. All three items are offline and additive.

### P1.1 Prompt-injection detection module (closes S2)

- New `engine/agent/injection.py`: three-tier detector —
  1. rule tier: known injection pattern families (instruction override, role-switch, tool-call smuggling, delimiter escapes, encoded payloads), each rule with positive+negative validators;
  2. heuristic tier: structural signals (imperative density, hidden-text ratios, suspicious tool references) feeding a local score;
  3. LLM tier: optional AIAnalyzer judgment reusing the dual-channel pattern (rule verdict + AI verdict must agree to escalate severity; AI unavailable = degrade to tier 1+2, never fail).
- CLI: `fusion-security inject-scan <file|dir|stdin>`; API: `POST /api/v1/agent/injection-scan`; both registered behind existing auth/audit middleware.
- Regression set: local corpus built from PIArena/RepoGuardBench sample styles (NOT downloaded at runtime; corpus committed as fixtures with license check) + homegrown cases for repo-local injection. Target: >=200 cases, reported precision/recall in `docs/benchmark.md`.
- Done when: detector passes the regression corpus in CI, degrades cleanly without MLX, and has >=95% unit-test coverage on the rule tier.

### P1.2 Secrets scanning upgrade (closes S4)

- Extract from SAST into `engine/secrets/`: entropy analysis (Shannon + charset heuristics), provider validators (regex shape + checksum where offline-verifiable, e.g. AWS/GitHub token structure), allowlist mechanism (path + content hash).
- Git history scan: `fusion-security secrets-scan --history` walking commits via existing `engine/vcs/git.py`; incremental mode reuses the diff helper.
- Every finding carries a confidence class; validators must reject a committed negative-sample corpus (no verified-true positives, no false positives on test fixtures).
- Done when: standalone module with its own test suite, wired into the pipeline as a Discover sub-step and into the gate as a severity source; SAST secret regexes remain for backward compat but are flagged deprecated.

### P1.3 AIAnalyzer robustness self-test (closes S7)

- Local adversarial suite for our own LLM calls: run a garak-compatible subset (or a port of its probe logic) against the semantic-scan and verify endpoints while MLX serves a local model; assert no prompt injection flips severity of a known finding.
- CI: nightly job (not per-PR — model load cost), results appended to `docs/benchmark.md`; failure blocks release tags, not PRs.
- Done when: `make robustness` (or equivalent script) exists and two consecutive runs are reproducible.

### Phase 1 acceptance

- All three modules offline by default (grep-verified: no new outbound hosts).
- Each new endpoint passes tenant-isolation and rate-limit tests in `tests/`.
- `docs/security-self-assessment.md` updated with the new attack surface.

## 4. Phase 2 — agent security productization (3-9 months)

Goal: the largest increment. Make fusion-security the offline agent-security scanner of the fusion stack, and wire the agent-IAM loop with fusion-harness.

### P2.1 MCP/Skills/agent-asset scanner (closes S1) — flagship

- New `engine/agent/assets/`: inventory parsers for MCP server manifests, skill packages, and agent config files found in a target repo (tools/paths/permissions declared, transport, env access).
- Static checks: tool-description poisoning, instruction-override payloads in descriptions/resources, over-broad permission declarations (filesystem/env/network scope), unsigned/unpinned dependency references, known-malicious-pattern library (local, signature-file based, updateable offline).
- Output: findings reuse the `Vulnerability` model with a new `agent` category — flows through triage, gate, SARIF, and the console for free.
- CLI: `fusion-security agent-scan <path>`; API: `POST /api/v1/agent/asset-scan`.
- **Differentiation vs SkillSpector/AI-Infra-Guard: fully offline, tenant-scoped, integrated into an existing 6-stage pipeline + CI gate.** They are cloud-flavored point tools; we are the in-perimeter platform.
- Done when: scans a fixture repo containing 1 poisoned MCP server + 1 over-privileged skill + 2 benign ones with 0 false positives; signature library update path documented (manual bundle import, still no default egress).

### P2.2 fusion-harness integration — agent IAM loop (closes S3)

- security exposes `POST /api/v1/agent/risk-score` (tool name, arguments schema, caller context) returning risk class + policy hints, powered by P1/P2 findings, rule reputation, and audit history.
- harness (separate repo — upstream issue first, per boundary rule) remains the deny-first executor; it calls us for intel and pushes decision records back.
- security ingests harness decision events into the audit stream; repeated denials feed rule reputation (closed feedback loop).
- Contract-first: JSON schema for the risk-score exchange lives in this repo and is versioned; harness integration proceeds only after the schema PR lands upstream.
- Done when: a scripted end-to-end demo (agent requests dangerous tool → harness asks security → deny/allow recorded → audit reflects it) runs on the monorepo test bench.

### P2.3 Guardrails service (completes S2 as a platform capability)

- `engine/guardrails/`: LLM input/output filtering as an API — injection module from P1.1 plus output filters (secret leakage, tool-invocation text, data-exfil patterns).
- Served under `/api/v1/guardrails/*`; agent-studio / cowork / code consume it via the shell/gateway route. Multi-tenant quotas and audit inherit from the chassis.
- Latency budget: rule+heuristic tier < 5ms p99 (pure local); LLM tier opt-in per tenant.
- Done when: one fusion app (agent-studio) integrates in dev mode and the latency budget holds in the benchmark doc.

### Phase 2 acceptance

- `agent-scan` + `risk-score` + guardrails all appear in the OpenAPI and the console UI.
- No default outbound traffic introduced (defense line 1 holds).
- Harness boundary respected: we ship intel, never enforcement (defense line 3).

## 5. Phase 3 — governance and trust (9-18 months)

### P3.1 Rule package format + signing (closes S6)

- Package format: versioned bundle (rules + validators + metadata), import/export CLI (`rules package` / `rules install --from-file`).
- Signature: sigstore-style offline signing (key pair + bundle digest), verification at install time; aligns with model-transparency thinking.
- Custom rules migrate from DB-only to packages; DB stays as storage backend.
- Done when: a signed package installs, an unsigned/tampered one is rejected with a clear audit event.

### P3.2 Compliance mapping expansion (closes S8)

- Map control items to findings: EU AI Act timeline awareness (2027-08 GPAI deadline), plus domestic requirements once verifiable sources exist.
- `compliance.py` grows from a flat mapper to control-item profiles per framework; reports gain a compliance section (report templates already exist as extension points).
- Done when: a scan report can render an EU-AI-Act-relevant control summary from a single profile flag.

### P3.3 Sandbox execution profile (closes S5)

- Run AI analysis and agent-asset analysis inside container execution profiles (Docker chassis already ships); profile = resource limits + no network + read-only target mount.
- Fallback to subprocess isolation (current AST parser pattern) when Docker unavailable — degradation, not failure.
- Done when: `FUSION_SECURITY_SANDBOX=docker` mode passes the full pipeline in CI with network disabled inside the container.

## 6. Overtake strategy: why agent IAM is ours to lose

Industry state (insight doc §2): permission frameworks for agents are research-grade or <100-star micro-projects, while scanner/guardrail categories already have 25k-star incumbents. Racing SkillSpector on scanner polish is a follower's game; owning agent IAM is not.

Our asymmetric assets:

1. fusion-harness already implements deny-first budget funnels + permission engine — the "decision" half of IAM exists in-tree.
2. fusion-security already has the "evidence" half: multi-tenant audit, rule reputation inputs, scan findings, offline intel.
3. The fusion monorepo is a real deployment of both — dogfooding beats benchmarks.

So the overtake is a composition, not a feature race:

- security = threat intel + policy input + audit memory (this repo)
- harness = enforcement + deny-first decisions (that repo)
- together = agent IAM with an audit trail, which no OSS stack currently offers as a coherent product

Sequence matters: P2.2 only starts after P1.1/P2.1 give the intel backend real content, and only via the contract-first route (schema here, integration upstream). If harness moves slower, P2.2's API still stands alone — it degrades to a documented intel endpoint, no sunk cost.

Success metric for "overtaken": one external (non-fusion) user or repo adopts the risk-score contract, or the agent-IAM combo is referenced in the union-web PRD as the stack's security layer.

## 7. Delivery cadence and branch strategy

- **Branch discipline**: this plan ships from `plan/evolution-2026-11` as a docs PR. Each implementation item (P1.1, P1.2, ...) gets its own feature branch `feat/<item>` and its own PR — no mega-branch, main stays releasable at all times.
- **Per-item vertical slice**: module + tests + CLI/API + docs in one PR; stage wiring can follow in a second PR if the diff exceeds review budget.
- **Release cadence**: unchanged — patch release per merged PR cycle (rc bump + tag + prerelease). Phase completion is a minor-version event (0.3.0 for Phase 1, 0.4.0 for Phase 2), not a big-bang.
- **Production safety**: nothing in this plan touches `start.sh` env contracts, port assignments, or the gateway module key; prod keeps running the last released rc throughout. Nightly robustness runs (P1.3) execute on a dev checkout, not the prod service.
- **Estimates** (calendar, single-cycle cadence assumed): P1.1 ~3 wks, P1.2 ~2 wks, P1.3 ~1 wk, P2.1 ~4 wks, P2.2 ~3 wks + upstream wait, P2.3 ~2 wks.

## 8. Risks and open questions

1. **Injection corpus licensing**: PIArena/RepoGuardBench fixtures cannot be committed blindly — license review before any vendoring; fallback is homegrown cases only (weaker but safe).
2. **Upstream dependency**: P2.2 needs harness-side cooperation (contract review, event push). Mitigation: contract-first, upstream issue first; the intel endpoint is independently valuable.
3. **Scanner false positives destroy trust faster than missing features**: the validator discipline (defense line 4) is the mitigation; 0-FP on fixtures is a merge gate, not an aspiration.
4. **Scope creep risk**: guardrails (P2.3) could balloon into a full LLM firewall product. Cap it at injection + output filters; anything else is a new plan.
5. **Compliance sources unverifiable**: EU AI Act items are cited from the insight doc's verified sources; domestic requirements stay out until a verifiable source exists (insight doc marks them UNVERIFIED — we do the same).
6. **Model supply for robustness tests**: nightly garak-style runs need a real loaded MLX model per monorepo rules; CI runners without the model skip gracefully (report "skipped", never "passed").
