# Fusion-Security Security Self-Assessment

**Date:** 2026-09-01
**Version audited:** 0.1.7+
**Scope:** Code-level self-audit of fusion-security against OWASP-oriented dimensions. Full third-party penetration testing is out of scope.
**Method:** Four parallel read-only security-review passes covering (1) Auth/RBAC/Secrets, (2) SSRF/Injection/Input-validation, (3) Infra/Deps/Config, (4) Data/Crypto/Availability. Each pass read the code and reported verifiable defects with `file:line`. Findings below are the consolidated, de-duplicated results ranked by severity. Real P0/P1 defects were remediated in the same change set (see "Remediation status" per finding).

## Summary

The audit surfaced **33 distinct findings** across all four dimensions: **8 P0, 9 P1, 11 P2, 5 P3**. The most serious cluster is **authorization**: the router-level `_AUTH` dependency authenticates but never authorizes, so a `viewer` key can perform every mutating operation, and no read/list endpoint is scoped by `tenant_id` (cross-tenant IDOR). The second cluster is **SSRF**: outbound HTTP follows redirects past the URL guard and DNS pin, and the Jira `base_url` is never validated at all. The third cluster is **data-at-rest / availability**: the SQLite file is created world-readable (0644), API keys use a single unsalted sha256, there is no rate limiting, and webhook HMAC signing is silently broken for DB-backed webhooks.

A focused set of the clearest, lowest-risk P0/P1 defects was fixed in this pass. The larger structural defects (full RBAC rework, tenant-scoping all reads, rate-limiting middleware, encrypted-at-rest webhook secrets, KDF for API keys, connection-pool refactor) are confirmed real and documented below with concrete remediation plans; they require dedicated follow-up waves because they touch many route files or add new dependencies, and doing them hastily in a single pass risks regressions. Their status is marked **identified — remediation planned**.

## Findings

### P0 — Critical

#### P0-1. Broken RBAC — router-level `_AUTH` only authenticates, never authorizes

**Files:** `fusion_security/api/app.py:21,132-142`; all route files under `fusion_security/api/routes/` (except `schedules.py`).

`_AUTH = [Depends(get_current_key)]` is applied to every non-public router. `get_current_key` (`api/auth.py:225-231`) only validates that the key exists and is enabled — it never calls `has_permission` / `require_permission`. A `viewer` key (whose only permissions are `scan:read` and `vuln:read`, per `auth.py:59`) can therefore call every mutating endpoint: `POST /projects`, `DELETE /projects/{id}`, `POST /scans`, `POST /scans/queue`, `PATCH /vulnerabilities/{id}`, `POST /patches/{id}/apply`, `POST /integrations/webhooks`, `POST /integrations/jira/config`, `POST /reports/generate`, etc. Only `schedules.py` and the `/api/v1/keys` endpoints correctly use `require_permission(...)`, confirming this is an oversight.

**Escalation:** a `viewer` key can register an attacker-controlled Jira `base_url` and trigger `/jira/sync` to exfiltrate every `open` vulnerability to the attacker's Jira.

**Fix:** replace router-level `_AUTH` with per-endpoint `Depends(require_permission("<perm>"))` matching each action.

**Status:** identified — remediation planned. Requires touching every route handler; dedicated RBAC wave.

---

#### P0-2. SSRF — outbound HTTP follows redirects, bypassing URL validation and DNS pinning

**Files:** `fusion_security/engine/ci/notifier.py:44-63` (`_urllib_post`); `fusion_security/engine/ci/webhook.py:67-103` (`_send`).

`urllib.request.urlopen` follows HTTP 3xx redirects by default. `_url_guard.validate_outbound_url` validates only the *original* URL. An attacker-controlled but validator-passing endpoint can return `302 Location: http://127.0.0.1:6379/...` or `http://169.254.169.254/...`; `urlopen` follows it and POSTs the attacker's body to the internal target. The `_PinnedResolver` (`engine/ci/_url_guard.py:76-117`) only pins when `host_arg == host` (the original hostname), so a redirect to a different host re-resolves normally and bypasses both validation and pinning.

**Fix:** disable redirect following (no-redirect handler) and re-validate each `Location`, or switch both callers to `httpx` with `follow_redirects=False` (already the default) routed through `validate_outbound_url`.

**Status:** identified — remediation planned.

---

#### P0-3. SSRF — Jira `base_url` is never validated against internal/loopback/metadata IPs

**Files:** `fusion_security/engine/ci/jira.py:41-54` (`JiraClient.client`); `fusion_security/api/routes/integrations.py:374-389` (`configure_jira`).

`configure_jira` accepts an arbitrary `base_url` and constructs `httpx.Client(base_url=...)` with no `validate_outbound_url` / `_url_guard` call. Any admin-key holder can set `base_url="http://127.0.0.1:8080"` or `http://169.254.169.254` and then trigger `/jira/sync`, issuing authenticated POSTs to internal endpoints. `issue_key` is also user-controlled, enabling arbitrary path segments.

**Fix:** call `_validate_outbound(body.base_url)` in `configure_jira`; in `JiraClient.__init__` validate as defense-in-depth; reject `issue_key` containing `/`, `?`, `#`, or whitespace.

**Status:** ✅ fixed (see "Remediation applied" below).

---

#### P0-4. DB file created world-readable (0644) — sensitive data at rest unprotected

**Files:** `fusion_security/db/session.py:96-99, 236-237`. Confirmed on disk: `~/.fusion-security/fusion_security.db` is mode `0644`.

`init_db()` / `init_async_db()` create the parent dir and the SQLite file via SQLAlchemy with no `os.umask()` / `os.chmod()`. The on-disk file (and `-wal`/`-shm` siblings) are `0644` — readable by every local user. The DB stores `api_keys.key_hash`, `webhooks.secret_hash`, source-code snippets (`vulnerabilities.code_snippet`, `patches.original_code`), and `projects.local_path`.

**Fix:** set `os.umask(0o077)` before any connection opens and `os.chmod(path, 0o600)` after create.

**Status:** ✅ fixed.

---

#### P0-5. DB-backed webhooks sign with empty secret — `X-Fusion-Signature` never sent

**Files:** `fusion_security/api/routes/scans.py:179-194` (`_notify_webhooks`); `fusion_security/api/routes/integrations.py:159-187` (`create_webhook`); `fusion_security/engine/ci/webhook.py:86`.

`create_webhook` stores only `secret_hash = sha256(secret)` (irreversible) and discards the plaintext. At fire time `_notify_webhooks` builds `WebhookConfig(url=row.url, events=events)` with **no `secret`**, so `if config.secret:` in `WebhookNotifier._send` is always `False` and the signature header is never emitted. No receiver can verify webhook authenticity; any party able to reach the webhook URL can forge scan-completion callbacks. The signing feature only works for in-memory configs never persisted by this API.

**Fix:** store the webhook secret encrypted-at-rest (e.g. `cryptography.fernet` keyed off `FUSION_SECURITY_MASTER_KEY`) and decrypt on load, or store an HMAC key directly (reversible) rather than a sha256 hash.

**Status:** identified — remediation planned. Needs a reversible-at-rest secret store (new dependency / key-derivation plumbing).

---

#### P0-6. No rate limiting on any API route — unauthenticated-flood + authenticated DoS

**Files:** `fusion_security/api/app.py:115-142` (no rate-limit middleware); `fusion_security/api/routes/scans.py:215-254, 314-356` (`POST /scans`, `POST /scans/queue`); `fusion_security/api/auth.py:124-160` (`validate_key` does sha256 + DB query per request, no lockout).

There is no `slowapi` / per-IP / per-key throttle anywhere. Any tenant with `scan:run` can enqueue unbounded `ScanTask`s and, via the non-queue `POST /scans` path (which bypasses the `WorkerPool` and spawns a free-standing `BackgroundTasks` coroutine per request), launch unbounded full-pipeline scans against arbitrary paths — exhausting disk/CPU/network to fusion-mlx and starving all other tenants.

**Fix:** add rate-limit middleware (per-IP + per-key) on auth + scan endpoints; in `create_scan`/`enqueue_scan` count active scans per `tenant_id` and reject (409) above a configured `MAX_CONCURRENT_SCANS_PER_TENANT`; route the non-queue `create_scan` through the `WorkerPool`.

**Status:** identified — remediation planned. Needs new middleware dependency + per-tenant quota state.

---

#### P0-7. Helm `fusion-mlx` Deployment runs as root with no security hardening

**File:** `deploy/helm/fusion-security/templates/mlx-deployment.yaml:17-25`.

The `fusion-mlx` Deployment `template.spec` has no `securityContext` at all — no `runAsNonRoot`, no `runAsUser`, no `cap_drop`, no `allowPrivilegeEscalation: false`. The container runs as root (UID 0). The sibling `deployment.yaml` correctly sets all of these for fusion-security; the MLX pod was missed. The MLX sidecar serves an unauthenticated LLM endpoint on the cluster network; a container-breakout or RCE in the MLX image gets root in the pod.

**Fix:** add `securityContext` (`runAsNonRoot: true`, `runAsUser: 1000`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`) to the MLX `template.spec`.

**Status:** ✅ fixed.

---

#### P0-8. Postgres override ships hardcoded default credentials

**File:** `docker-compose.postgres.yml:9, 18-20`.

`POSTGRES_USER=fusion`, `POSTGRES_PASSWORD=fusion`, `POSTGRES_DB=fusion`, and the DB URL `postgresql+asyncpg://fusion:fusion@...` are hardcoded literals, not env-var-substituted. Anyone bringing up the postgres override gets a known-password DB; `fusion` is also weak.

**Fix:** substitute from env with a fail-fast empty default, e.g. `POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?POSTGRES_PASSWORD required}`.

**Status:** ✅ fixed.

---

### P1 — High

#### P1-1. Cross-tenant IDOR — read/list endpoints do not filter by caller `tenant_id`

**Files:** `fusion_security/api/routes/scans.py:598-613`; `vulnerabilities.py:60-160`; `patches.py:53-152`; `projects.py:75-236`; `schedules.py:66-71`.

`ScanORM`, `VulnerabilityORM`, `PatchORM` all carry a `tenant_id` column and writes stamp the caller's `tenant_id` from the API key. But no read or list endpoint filters by it. An authenticated user from tenant A can read tenant B's scans/vulnerabilities/patches/schedules by enumerating IDs, or via the unscoped list endpoints (which return every tenant's rows). `delete_scan`, `update_project`, `apply_patch`, `verify_patch`, `mark_false_positive` likewise operate on any tenant's row.

**Fix:** inject `api_key: APIKey = Depends(get_current_key)` into every read/mutate handler, add `.filter(<ORM>.tenant_id == api_key.tenant_id)` to list queries, and reject single-record lookups where `o.tenant_id != api_key.tenant_id`.

**Status:** identified — remediation planned. Touches every route; dedicated tenant-scoping wave.

---

#### P1-2. SSRF — notifier discards pinned IPs, leaving DNS-rebinding TOCTOU open

**File:** `fusion_security/engine/ci/notifier.py:44-48`.

`_urllib_post` calls `validate_outbound_url(url)` (returns `pinned_ips`) but only uses `guard.ok` / `guard.safe_url`; the `pinned_ips` list is dropped. Between validate-time `getaddrinfo` and connect-time resolution inside `urlopen`, a flapping DNS record can pass validation on a public IP and connect on `127.0.0.1`. The webhook path uses `pin_url` correctly; the notifier path was not updated to match.

**Fix:** use `pin_url(url)` and enter the resolver context exactly as `webhook._send` does. (Still subject to P0-2 redirect bypass — fix both together.)

**Status:** identified — remediation planned (bundled with P0-2).

---

#### P1-3. CORS — `allow_credentials=True` combined with wildcard methods/headers

**File:** `fusion_security/api/app.py:123-130`.

The CORS middleware sets `allow_credentials=True` together with `allow_methods=["*"]` / `allow_headers=["*"]`. Origins are not wildcarded, but wildcard methods/headers with credentials is weak; if an operator sets `FUSION_CORS_ORIGINS=*`, `allow_credentials=True` silently becomes a real vulnerability (credentialed CORS to any origin).

**Fix:** replace wildcards with explicit lists and reject `*` when credentials are enabled.

**Status:** ✅ fixed.

---

#### P1-4. `system/model/config` leaks internal exception text to callers

**File:** `fusion_security/api/routes/system.py:102-104`.

`GET /api/v1/system/model/config` catches all exceptions and returns `{"error": str(e)}`. `str(e)` for `httpx` connection errors can include the full internal URL, host, port, and OS error detail; SQLAlchemy/network errors leak internal topology. This route is auth-gated but viewer is the least-privilege role.

**Fix:** log the exception server-side, return a generic message.

**Status:** ✅ fixed.

---

#### P1-5. Scan failure stores raw exception text in `scan.summary`, exposed via API

**Files:** `fusion_security/api/routes/scans.py:165-171`, `:583-589`.

On scan failure `scan_orm.summary = str(e)` is committed and returned by the scans list/detail endpoints (viewer-readable). `str(e)` can contain repo paths, the internal MLX URL, DB error details, or filesystem paths.

**Fix:** store a coarse status message in `summary`; log the full `str(e)` server-side only.

**Status:** ✅ fixed.

---

#### P1-6. `POST /scans/incremental` reflects `ValueError` text to caller

**File:** `fusion_security/api/routes/scans.py:638-639`.

`raise HTTPException(status_code=400, detail=str(e))` where `e` is a `ValueError` from `GitHelper(body.path)`, which embeds the user-supplied `body.path` resolved to an absolute server path. This confirms to an attacker whether arbitrary absolute paths exist as git repos on the server — a path-enumeration / filesystem probe oracle for any `scan:run` key.

**Fix:** return a generic `detail="invalid scan path or not a git repository"` and log the real message.

**Status:** ✅ fixed.

---

#### P1-7. API keys hashed with single unsalted sha256 — offline dictionary attack feasible

**File:** `fusion_security/api/auth.py:63-64, 81-83`.

Keys are generated with `secrets.token_hex(24)` (192 bits — strong) and `hmac.compare_digest` is correctly used. But the storage hash is plain sha256 with no salt and no KDF. Because the DB file is world-readable (P0-4) and the key format is a known prefix `fs_` + hex, an attacker who exfiltrates the DB can attack short/guessable keys offline at full GPU speed. The `master` key from `FUSION_SECURITY_MASTER_KEY` (user-chosen) is especially exposed: a weak env value is crackable instantly from the leaked `key_hash`.

**Fix:** use a password-strength KDF — `hashlib.pbkdf2_hmac("sha256", raw_key, salt, 600_000)` with a per-row random 16-byte `salt` column, or `argon2-cffi`. Store `salt` + derived `hash`; compare via `hmac.compare_digest`.

**Status:** identified — remediation planned. Needs a `salt` column + KDF migration for existing rows.

---

#### P1-8. `StaticPool` + `check_same_thread=False` shared across BackgroundTasks threadpool and async event loop

**Files:** `fusion_security/db/session.py:92-112`; `fusion_security/api/routes/scans.py:106, 242, 541`; `fusion_security/api/routes/integrations.py:404-424`.

`StaticPool` keeps one underlying DBAPI connection reused for every `Session`. SQLAlchemy `Session` objects are not thread-safe, and a single shared raw connection is not safe for concurrent use from multiple threads. The codebase routes sync DB work into `BackgroundTasks` (threadpool) **and** `run_in_threadpool` **and** the async event loop, all calling `get_session()` and binding to the same DBAPI connection. Concurrent `commit()`/`execute()` from different threads produces `sqlite3.ProgrammingError` or silent statement interleaving. The comment "进程内并发安全靠 GIL+check_same_thread=False" is incorrect.

**Fix:** use `poolclass=NullPool` (fresh connection per `Session`) with `connect_args={"check_same_thread": False, "timeout": 30}`, or serialize all DB access through one dedicated thread / lock.

**Status:** identified — remediation planned. Connection-pool refactor; needs careful regression testing.

---

#### P1-9. `cancel_active` returns False during the RUNNING-but-not-yet-tracked window

**File:** `fusion_security/engine/queue/task_queue.py:177-180` vs `:142-149`.

In `_worker_loop`, the task is dequeued, its status set to `RUNNING`, and `update_status` awaited **before** `self._active[task.task_id] = asyncio.current_task()` is recorded. A cancel issued in that window sees the task as `RUNNING` in `_tasks` but `cancel_active` reports "not running" and does not interrupt it — the scan runs to completion despite the cancel request.

**Fix:** record `self._active[task.task_id] = asyncio.current_task()` **before** `await self._queue.update_status(...)`.

**Status:** ✅ fixed.

---

### P2 — Medium

| ID | File:line | Defect | Status |
|----|-----------|--------|--------|
| P2-1 | `api/auth.py:132-135` | `hmac.compare_digest` on the key hash is dead — the DB `filter(key_hash == ...)` already selected the row; compares two equal strings, gives no timing protection. | ✅ fixed (documented). |
| P2-2 | `api/auth.py:210-219`, `app.py:68` | Master key unrecoverable when `FUSION_SECURITY_MASTER_KEY` unset — `lifespan` discards the generated plaintext; admin operations unreachable; incentivizes disabling auth. | identified — remediation planned. |
| P2-3 | `engine/ai/analyzer.py:189-203, 243-255` | Prompt injection: `semantic_scan` and `generate_fix` paste scanned code without `<CODE>` delimiters (unlike `verify_findings`); a malicious scanned file can influence AI output. `semantic_scan` findings are auto-marked `verified=True`. | identified — remediation planned. |
| P2-4 | `engine/sca/scanner.py:167-180, 349` | SCA `collect_dependencies` / `check_license` use `rglob` with no symlink skip and no root-containment check — a symlink to `/etc` traverses outside the project. | identified — remediation planned. |
| P2-5 | `docker-compose.yml:4-34` | Compose service has no `read_only: true`, no `tmpfs`, no `security_opt: ["no-new-privileges:true"]` — root filesystem writable. | identified — remediation planned. |
| P2-6 | `Dockerfile:30-31` | `apt-get install ... curl tini` unpinned; `curl` only needed for HEALTHCHECK. Prefer `httpx`-based healthcheck, drop `curl`. | identified — remediation planned. |
| P2-7 | `deploy/helm/fusion-security/values.yaml:81`, `templates/deployment.yaml:33-48` | `secrets: {}` default + no env binding for `FUSION_SECURITY_MASTER_KEY` → every Helm install bootstraps an unretrievable random master key. | identified — remediation planned. |
| P2-8 | `start.sh:14, 52` | `.fusion-security.pid` written with umask 0644, exposing the API PID to other local users. | ✅ fixed. |
| P2-9 | `engine/resume/checkpoint.py:73-80` | Corrupt checkpoints moved to `.corrupt` but never garbage-collected — unbounded disk growth. | identified — remediation planned. |
| P2-10 | `engine/cache.py:139-143` | `put_multi` final commit bypasses the `IntegrityError` upsert fallback that `put(commit=False)` skips — batch cache writes fail on race. | identified — remediation planned. |
| P2-11 | `engine/queue/task_queue.py:56-60` | Task recorded in `_tasks` before `queue.put`; a full/cancelled queue leaks entries (PENDING, never cleaned) — memory DoS amplifier on P0-6. | identified — remediation planned. |

### P3 — Low / Informational

| ID | File:line | Defect | Status |
|----|-----------|--------|--------|
| P3-1 | `engine/sca/scanner.py:167-180` | SCA has no `max_files`/`max_size` cap (unlike `ScanTarget.discover`) — unbounded `rglob` + `read_text` enables local DoS on scan input. | identified — remediation planned. |
| P3-2 | `engine/ai/analyzer.py:263-264` | `generate_fix` returns `f"// 修复生成失败: {e}"` — leaks exception text into the patched code that Retest re-scans. | ✅ fixed. |
| P3-3 | `pyproject.toml:40-42` | `psycopg2-binary` in `postgres` extra is unused (DB URL is `postgresql+asyncpg://`) — pulls a bundled-libpq wheel with CVE history. | identified — remediation planned. |
| P3-4 | `pyproject.toml:6-27` | Runtime deps use open floors (`>=` only) — non-reproducible outside the monorepo lock; risky for a shipped image. | identified — remediation planned. |
| P3-5 | `api/auth.py:143-144` | `validate_key` writes + commits `last_used_at` on every authenticated request — write amplification + writer-lock contention. | identified — remediation planned. |

## Remediation applied

The following defects were fixed in this change set (low-risk, high-value, surgical):

- **P0-3** — Jira `base_url` validated via `_url_guard`; `issue_key` sanitized.
- **P0-4** — DB file created with `umask 0o077` + `chmod 0o600`; `-wal`/`-shm` covered.
- **P0-7** — Helm MLX Deployment `securityContext` added (non-root, drop caps).
- **P0-8** — Postgres compose credentials env-substituted with fail-fast.
- **P1-3** — CORS wildcards replaced with explicit method/header lists; `*` origin rejected with credentials.
- **P1-4** — `/system/model/config` returns generic error, logs detail server-side.
- **P1-5** — Scan failure stores coarse `summary`, logs `str(e)` server-side.
- **P1-6** — `/scans/incremental` returns generic 400 detail, logs real message.
- **P1-9** — `cancel_active` records `_active` before `update_status` (race closed).
- **P2-1** — Dead `compare_digest` removed with explanatory comment.
- **P2-8** — `start.sh` PID file `chmod 600`.
- **P3-2** — `generate_fix` returns fixed sentinel, no `{e}`.

The remaining findings (RBAC rework P0-1, cross-tenant IDOR P1-1, SSRF redirect-bypass P0-2, DNS-rebinding P1-2, webhook HMAC P0-5, rate-limiting P0-6, KDF P1-7, pool refactor P1-8, and the P2/P3 items marked "identified") are confirmed real and documented above with concrete fixes; they require dedicated follow-up waves because they touch many route files, add dependencies, or need careful regression testing.

## Dimensions covered

| Dimension | Status | Findings |
|-----------|--------|----------|
| Authentication & Authorization | ⚠ issues | P0-1 (RBAC), P2-1, P2-2 |
| Secret handling | ✅ clean | keys hashed, never logged plaintext, `secret_hash`/`key_hash` omitted from responses |
| SSRF | ⚠ issues | P0-2, P0-3 (fixed), P1-2 |
| Injection (SQL / command / prompt) | ✅ mostly clean | SQL via ORM bound params; git via arg list + `--`; prompt-injection P2-3 (code treated as data only in `verify_findings`) |
| Input validation & path traversal | ⚠ issues | `ScanTarget` traversal clean; SCA symlink escape P2-4; incremental path probe P1-6 (fixed) |
| Container & deploy security | ⚠ issues | P0-7 (fixed), P0-8 (fixed), P2-5, P2-6, P2-7 |
| Dependency security | ⚠ minor | P3-3, P3-4 |
| Configuration security | ⚠ issues | P1-3 (fixed), P2-2, P2-7 |
| Error handling / info leakage | ⚠ issues | P1-4 (fixed), P1-5 (fixed), P1-6 (fixed), P3-2 (fixed) |
| Data protection at rest | ⚠ issues | P0-4 (fixed), P0-5, P1-7 |
| Cryptographic correctness | ⚠ issues | P1-7 (unsalted sha256); `compare_digest`/entropy otherwise correct |
| Availability / DoS | ⚠ issues | P0-6, P2-9, P2-11, P3-1, P3-5 |
| Race conditions / concurrency | ⚠ issues | P1-8, P1-9 (fixed), P2-10, P2-11 |

## Out of scope

- Third-party / network penetration testing
- Runtime exploitation of the local MLX inference engine (fusion-mlx — upstream, separate project)
- Physical / local-access attacks on the developer machine
- The fusion-core shared library (in-tree upstream dependency — issues/PRs only, no edits)
