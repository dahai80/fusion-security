<div align="center">
  <h1>🔒 Fusion-Security</h1>
  <p><strong>Local AI-powered code security audit tool for macOS Apple Silicon</strong></p>
  <p><em>100% offline, zero code upload, powered by fusion-mlx. The domestic alternative to Claude Security.</em></p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/macOS-Apple%20Silicon-brightgreen" alt="macOS">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/AI-MLX%20Native-orange" alt="MLX">
  <img src="https://img.shields.io/badge/Offline-First-important" alt="Offline">
  <img src="https://img.shields.io/badge/status-beta-yellow" alt="Beta">
  <img src="https://img.shields.io/badge/tests-690%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/React-18-blue" alt="React">
  <img src="https://img.shields.io/badge/K8s-Helm-blueviolet" alt="Helm">
</p>

<p align="center">
  <a href="README_CN.md">中文文档</a>
</p>

---

## 📋 Overview

**Fusion-Security** is a local AI-powered code security audit tool, designed as a domestic alternative to **Claude Security**. Built on `fusion-mlx`, it provides enterprise-grade vulnerability scanning, AI-powered semantic analysis, and automatic fix generation — all **100% offline** with zero code uploaded.

### Key Differentiators vs Claude Security

| Feature | Fusion-Security | Claude Security |
|---------|----------------|-----------------|
| **Data residency** | ✅ 100% local, no upload | ❌ Code uploaded to Anthropic servers |
| **Offline capable** | ✅ Fully offline | ❌ Requires internet |
| **China accessible** | ✅ Yes | ❌ Blocked |
| **AI model** | fusion-mlx (Apple Silicon) | Claude Opus 4.7 (cloud) |
| **Vulnerability scan** | ✅ Cross-file data flow | ✅ Cross-file + AST (10 langs) |
| **AI semantic analysis** | ✅ Logic flaw detection | ✅ Logic flaw detection |
| **Auto fix generation** | ✅ Template + AI enhanced | ✅ AI-generated patches |
| **Low false positives** | ✅ Adversarial verification | ✅ Adversarial validation |
| **Audit reports** | ✅ Markdown/JSON/HTML | ✅ Enterprise dashboard |
| **CI/CD integration** | ✅ CLI + GitHub Actions + GitLab CI | ✅ Webhook + API |
| **Web Dashboard** | ✅ React + Ant Design | ✅ Enterprise dashboard |
| **Notifications** | ✅ Feishu + DingTalk | ❌ |
| **Checkpoint/Resume** | ✅ Pipeline resume + circuit breaker | ❌ |
| **K8s Deployment** | ✅ Helm Chart | ❌ |
| **Web API** | ✅ FastAPI REST API | ✅ |
| **License** | MIT (free) | Enterprise subscription |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/dahai80/fusion-security.git
cd fusion-security

# Install
pip install -e .

# Scan a project
fusion-security scan /path/to/project

# Scan with AI analysis (requires fusion-mlx running)
fusion-security scan /path/to/project --model qwen3.5-9b

# Quick check (CI-friendly JSON output)
fusion-security check /path/to/project

# List detection rules
fusion-security rules

# Start Web API server
fusion-security serve --host 127.0.0.1 --port 8080

# Start frontend dashboard
cd frontend && npm install && npm run dev
```

---

## 📖 Command Reference

| Command | Description |
|---------|-------------|
| `scan <path>` | Full vulnerability scan |
| `scan --severity high` | Only report high/critical |
| `scan --output ./reports` | Save reports to directory |
| `scan --format html` | Generate HTML report |
| `scan --no-ai` | Disable AI analysis |
| `scan --pipeline` | 5-stage pipeline scan (Recon→Discover→Verify→Triage→Patch) |
| `scan --sca` | Enable SCA dependency vulnerability scan |
| `check <path>` | Quick check (JSON output, CI-friendly) |
| `gate <path>` | Security quality gate (CI/CD pass/fail) |
| `gate --policy strict` | Gate policy: strict/standard/permissive |
| `sarif <path>` | Export SARIF format results |
| `rules` | List all detection rules |
| `serve` | Start Web API server (FastAPI) |
| `serve --host 127.0.0.1` | Bind to all interfaces |
| `serve --port 8080` | Custom port (default 11454) |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Access Layer                               │
│    CLI │ Web Dashboard │ Web API │ IDE Plugin │ CI/CD │ REST API │
├──────────────────────────────────────────────────────────────────┤
│                        Service Layer                              │
│  ScanService │ VerifyService │ PatchService │ ReportService       │
├──────────────────────────────────────────────────────────────────┤
│                        Engine Layer                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │ Semantic     │  │ Taint        │  │ Adversarial             │ │
│  │ (RuleEngine) │  │ (TaintTracker)│  │ (AdversarialVerifier)  │ │
│  │ + AST Parser │  │ Source→Sink  │  │ Attack + Defense agents │ │
│  └─────────────┘  └──────────────┘  └─────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Rules Engine (37 rules) │ AI Analyzer │ SCA Scanner │ CVSS  │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ 5-Stage Pipeline │ Security Gate │ Feedback │ Custom Rules   │ │
│  │ Checkpoint/Resume │ Circuit Breaker │ Retry Policy           │ │
│  └─────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│                      Integration Layer                            │
│  Feishu Notifier │ DingTalk Notifier │ GitHub Actions │ GitLab CI│
├──────────────────────────────────────────────────────────────────┤
│                        Infra Layer                                │
│  SQLite+SQLAlchemy │ Local AI (fusion-mlx) │ Multi-tenant │ Audit│
│  Kubernetes (Helm) │ PVC Persistence │ HPA Autoscaling           │
└──────────────────────────────────────────────────────────────────┘
```

### Engine Components

| Component | Description |
|-----------|-------------|
| **5-Stage Pipeline** | Recon→Discover→Verify→Triage→Patch orchestration |
| **Checkpoint/Resume** | Save pipeline state, resume from last completed stage |
| **Circuit Breaker** | Auto-stop pipeline on consecutive failures (CLOSED→OPEN→HALF_OPEN) |
| **Retry Policy** | Exponential backoff with configurable max retries |
| **AST Parser** | Tree-sitter multi-language AST (Python/JS/TS/Java/Go/C/C++/Rust/Ruby/PHP) with subprocess isolation |
| **Taint Tracker** | Source → Propagation → Sink data flow analysis |
| **Adversarial Verifier** | Dual-agent verification (attack + defense) |
| **Rule Engine** | 37 built-in regex + AST-based detection rules (15 regex + 8 AI semantic + 3 SCA + 11 legacy) |
| **Custom Rule Engine** | User-defined rules with CRUD and gray-release |
| **SCA Scanner** | Dependency vulnerability scan (OSV.dev API + fallback) + deprecated packages (FUS-SCA-002) + license risk (FUS-SCA-003) + stale version (FUS-SCA-004) |
| **AI Analyzer** | Semantic scan via fusion-mlx (100% local) + 8 AI semantic rules (ACL, AUTH, CONF, LOGIC) |
| **CVSS 3.1 Scorer** | Full CVSS base score calculator |
| **Security Gate** | CI/CD quality gate (strict/standard/permissive) |
| **Feedback Loop** | False-positive learning and suppression |
| **Fix Generator** | Template + AI-enhanced patch generation with verification |
| **Jira Integration** | Create Jira issues from vulnerabilities (REST API v2, basic auth) |
| **Scan Cache** | LRU cache with TTL + project-level persistent cache (file hash → results) |
| **HTML Report** | Jinja2 template engine with XSS auto-escaping |
| **Compliance Mapper** | ISO 27001 / PCI DSS mapping |
| **SARIF Export** | SARIF 2.1.0 format for IDE/CI integration |
| **RBAC + API Key** | Role-based access (admin/operator/viewer) |
| **Multi-Tenant** | Tenant isolation with per-tenant data dirs |
| **Audit Logging** | Full operation audit trail (JSONL) |
| **Dashboard** | React + Ant Design frontend (scan metrics, trends, management) |
| **Scheduler** | Cron-like periodic scan (hourly/daily/weekly/monthly) |
| **Feishu Notifier** | Interactive card message + HMAC-SHA256 signing |
| **DingTalk Notifier** | Markdown message + HMAC-SHA256 signing |
| **GitHub Actions** | Composite action with severity gate + artifact upload |
| **GitLab CI** | Include template with full/incremental scan jobs |
| **Helm Chart** | Kubernetes deployment (fusion-security + fusion-mlx dual) |

### Vulnerability Coverage (37 rules)

| Category | Rules | CWE |
|----------|-------|-----|
| SQL Injection | SQL001, SQL002 | CWE-89 |
| Cross-Site Scripting | XSS001, XSS002 | CWE-79 |
| Command Injection | CMD001, CMD002 | CWE-78 |
| Path Traversal | PATH001 | CWE-22 |
| Hardcoded Secrets | SEC001, SEC002 | CWE-798 |
| Weak Cryptography | CRYPTO001 | CWE-327 |
| Hardcoded Encryption Key | CRYPTO002 | CWE-321 |
| Missing Authentication | AUTH001 | CWE-862 |
| XML External Entity | XXE001 | CWE-611 |
| Open Redirect | REDIR001 | CWE-601 |
| Log Injection | LOG001 | CWE-117 |
| Insecure Data Transmission | INSECURETRANS001 | CWE-319 |
| Directory Listing Exposure | DIRTRAVERS001 | CWE-548 |
| **AI Semantic Rules** | | |
| Horizontal Privilege Escalation | AI_ACL001 | CWE-639 |
| Vertical Privilege Escalation | AI_ACL002 | CWE-639 |
| Missing MFA | AI_AUTH006 | CWE-308 |
| Verbose Error Leakage | AI_CONF002 | CWE-209 |
| Payment Amount Tampering | AI_LOGIC001 | CWE-94 |
| Race Condition | AI_LOGIC002 | CWE-362 |
| Business Flow Bypass | AI_LOGIC003 | CWE-285 |
| Data Integrity Check Missing | AI_LOGIC004 | CWE-354 |
| **SCA Rules** | | |
| Known Vulnerabilities | OSV + local DB | Multiple |
| Deprecated Components | FUS-SCA-002 | CWE-1104 |
| License Risk | FUS-SCA-003 | CWE-1104 |
| Stale Dependencies | FUS-SCA-004 | CWE-1104 |

---

## 🖥️ Frontend Dashboard

React 18 + Ant Design 5 + Vite 5 + TypeScript web dashboard.

```bash
cd frontend
npm install
npm run dev        # Development server (http://localhost:5173)
npm run build      # Production build
npm run preview    # Preview production build
```

### Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Stats cards (scans, vulns, high severity, fixed) + system health |
| **Scans** | Scan list, create new scan, delete, status tracking |
| **Vulnerabilities** | Vuln table with filters, detail modal, mark false positive, generate patch |
| **Projects** | Project CRUD management |

The dashboard connects to the FastAPI backend at `http://localhost:11454/api/v1`.

---

## 🔄 Checkpoint & Resume

Pipeline scans can be interrupted and resumed from the last completed stage.

### How it works

1. **Checkpoint** — After each pipeline stage completes, state is saved to `.fusion_checkpoints/`
2. **Resume** — Pass `scan_id` to resume from the last checkpoint, skipping completed stages
3. **Circuit Breaker** — If consecutive stages fail, the pipeline auto-stops (CLOSED→OPEN)
4. **Retry** — Failed stages retry with exponential backoff before tripping the breaker

### Circuit Breaker States

```
CLOSED (normal) → OPEN (tripped, failure_threshold exceeded)
                      ↓ recovery_timeout
                 HALF_OPEN (probing, 1 request allowed)
                      ↓ success           ↓ failure
                 CLOSED                OPEN
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/scans/checkpoints` | List all saved checkpoints |
| POST | `/api/v1/scans/resume` | Resume a scan from checkpoint |

```bash
# Resume a scan
curl -X POST http://localhost:11454/api/v1/scans/resume \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "abc-123", "path": "/path/to/project"}'
```

---

## 📢 Notifications

Send scan results to Feishu (Lark) or DingTalk with HMAC-SHA256 webhook signing.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/integrations/notify/feishu` | Configure Feishu webhook |
| POST | `/api/v1/integrations/notify/dingtalk` | Configure DingTalk webhook |
| POST | `/api/v1/integrations/notify/send` | Send notification to all configured channels |

```bash
# Configure Feishu
curl -X POST http://localhost:11454/api/v1/integrations/notify/feishu \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx", "secret": "xxx"}'

# Configure DingTalk
curl -X POST http://localhost:11454/api/v1/integrations/notify/dingtalk \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=xxx", "secret": "xxx"}'

# Send notification
curl -X POST http://localhost:11454/api/v1/integrations/notify/send \
  -H "Content-Type: application/json" \
  -d '{"event": "scan_completed", "data": {"project": "my-app", "vulns": 5, "high": 2}}'
```

---

## 🌐 Web API (FastAPI)

Start the API server:

```bash
fusion-security serve
# or with options
fusion-security serve --host 127.0.0.1 --port 8080
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| **Projects** | | |
| POST | `/api/v1/projects` | Create project |
| GET | `/api/v1/projects` | List projects |
| GET | `/api/v1/projects/{id}` | Get project details |
| PUT | `/api/v1/projects/{id}` | Update project |
| DELETE | `/api/v1/projects/{id}` | Delete project |
| GET | `/api/v1/projects/{id}/scan-summary` | Project scan summary (scans, vulns, cache stats) |
| **Scans** | | |
| POST | `/api/v1/scans` | Start scan (async background) |
| GET | `/api/v1/scans` | List scans (filter by project/status) |
| GET | `/api/v1/scans/{id}` | Get scan details |
| DELETE | `/api/v1/scans/{id}` | Delete scan |
| GET | `/api/v1/scans/checkpoints` | List saved checkpoints |
| POST | `/api/v1/scans/resume` | Resume scan from checkpoint |
| **Vulnerabilities** | | |
| GET | `/api/v1/vulnerabilities` | List vulns (filter/severity/status) |
| GET | `/api/v1/vulnerabilities/{id}` | Get vulnerability details |
| PATCH | `/api/v1/vulnerabilities/{id}` | Update vulnerability status |
| PUT | `/api/v1/vulnerabilities/{id}/status` | Update status (with validation) |
| GET | `/api/v1/vulnerabilities/export` | Export vulns (JSON/CSV) |
| GET | `/api/v1/vulnerabilities/stats/summary` | Aggregated statistics |
| **Patches** | | |
| GET | `/api/v1/patches` | List patches |
| GET | `/api/v1/patches/{id}` | Get patch details |
| POST | `/api/v1/patches/{id}/verify` | Verify patch (test result) |
| **Reports** | | |
| GET | `/api/v1/reports/scans/{id}/sarif` | Export SARIF 2.1.0 report |
| **Integrations** | | |
| POST | `/api/v1/integrations/gate` | Security quality gate evaluation |
| POST | `/api/v1/integrations/cvss` | CVSS 3.1 score calculation |
| POST | `/api/v1/integrations/compliance` | Compliance mapping (ISO/PCI) |
| POST | `/api/v1/integrations/feedback` | Submit false-positive feedback |
| GET | `/api/v1/integrations/feedback/stats` | Feedback statistics |
| POST | `/api/v1/integrations/rules` | Create custom rule |
| GET | `/api/v1/integrations/rules` | List custom rules |
| DELETE | `/api/v1/integrations/rules/{id}` | Delete custom rule |
| GET | `/api/v1/integrations/dashboard` | Dashboard statistics |
| POST | `/api/v1/integrations/notify/feishu` | Configure Feishu notification |
| POST | `/api/v1/integrations/notify/dingtalk` | Configure DingTalk notification |
| POST | `/api/v1/integrations/notify/send` | Send notification |
| POST | `/api/v1/integrations/jira/config` | Configure Jira integration |
| POST | `/api/v1/integrations/jira/sync` | Sync vulnerabilities to Jira |
| GET | `/api/v1/integrations/jira/issue/{key}` | Get Jira issue details |
| **Auth** | | |
| POST | `/api/v1/keys` | Create API key |
| GET | `/api/v1/keys` | List API keys |
| **System** | | |
| GET | `/api/v1/system/health` | Health check |
| GET | `/api/v1/system/info` | Version & platform info |
| GET | `/api/v1/system/rules` | List built-in rules |
| PUT | `/api/v1/system/models` | Update default model config |

### API Example

```bash
# Create project
curl -X POST http://localhost:11454/api/v1/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "my-project", "local_path": "/path/to/project"}'

# Start scan
curl -X POST http://localhost:11454/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"project_id": "<id>", "scan_type": "full", "use_ai": true}'

# List vulnerabilities
curl http://localhost:11454/api/v1/vulnerabilities?severity=critical

# Get stats
curl http://localhost:11454/api/v1/vulnerabilities/stats/summary
```

---

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dahai80/fusion-security/ci/github@main
        with:
          path: '.'
          severity: 'high'
          fail-on-severity: 'critical'
          server-url: 'http://fusion-security:11454'
```

Inputs: `path`, `severity`, `no-ai`, `format`, `output`, `fail-on-severity`, `server-url`, `incremental`

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/dahai80/fusion-security/main/ci/gitlab/.gitlab-ci.yml'
    inputs:
      severity: 'high'
      fail_on: 'critical'
```

Jobs: `fusion-security-full` (scheduled), `fusion-security-incremental` (MR events)

CI variables: `FUSION_SECURITY_SEVERITY`, `FAIL_ON`, `NO_AI`, `FORMAT`, `SERVER`

---

## ☸️ Kubernetes Deployment (Helm)

```bash
# Install
helm install fusion-security deploy/helm/fusion-security \
  --set image.tag=latest \
  --set fusionMLX.enabled=true \
  --set persistence.enabled=true

# With ingress
helm install fusion-security deploy/helm/fusion-security \
  --set ingress.enabled=true \
  --set ingress.host=fusion-security.example.com
```

### Key Values

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image.repository` | `fusion-security` | Image repository |
| `image.tag` | `latest` | Image tag |
| `service.port` | `11454` | Service port |
| `ingress.enabled` | `false` | Enable ingress |
| `persistence.enabled` | `true` | Enable PVC |
| `persistence.size` | `5Gi` | PVC size |
| `fusionMLX.enabled` | `true` | Deploy fusion-mlx sidecar |
| `fusionMLX.image` | `fusion-mlx` | MLX image |
| `autoscaling.enabled` | `false` | Enable HPA |
| `autoscaling.maxReplicas` | `5` | Max replicas |

---

## 🔧 Example

```bash
# Scan a project
fusion-security scan ~/my-project

# Output:
# 🔒 Fusion-Security Code Security Audit
# ================================================
#   Target: /Users/me/my-project
#   AI Analysis:  ✅ Enabled
#
#   📊 3 vulnerabilities found | high: 2 | medium: 1
#   Files scanned: 42
#   Duration: 1250ms
#
#   Vulnerabilities:
#   1. 🟠 [HIGH] Hardcoded Secret
#      /Users/me/my-project/config.py:15
#      💡 Use environment variables or key management service
#   2. 🟠 [HIGH] Command Injection
#      /Users/me/my-project/utils.py:42
#      💡 Use subprocess.run with argument list instead of string
#   3. 🟡 [MEDIUM] Log Injection
#      /Users/me/my-project/app.py:88
#      💡 Filter newline characters in user input before logging
```

---

## 🧪 Running Tests

```bash
pip install -e ".[test]"
pytest tests/ -v
```

690 tests covering all modules: rule engine (37 rules), scanner, AI analyzer (8 semantic rules), SCA scanner (deprecated/license/stale), Jira integration, pipeline, checkpoint/resume, circuit breaker, notifications, fix generator, reports, API routes, CLI. 91% coverage.

---

## 🔒 Security & Compliance

- **100% Local Offline** — Zero code upload, zero data leakage
- **No Telemetry** — No analytics, no phoning home
- **Data Sovereignty** — All scanning and processing on local machine
- **Regulation Compliant** — No cross-border data transfer
- **Compliance Mapping** — ISO 27001 / PCI DSS
- **CVSS 3.1 Scoring** — Standardized vulnerability severity assessment
- **RBAC** — admin/operator/viewer role-based access control
- **Audit Trail** — Complete operation audit logs (JSONL)
- **Multi-Tenant Isolation** — Physical data isolation per tenant
- **API Key Auth** — Secure API access control
- **Webhook Signing** — HMAC-SHA256 for Feishu/DingTalk notifications

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Fusion-Security — Local AI Code Security. Zero Upload, Maximum Privacy.</strong>
</p>
<p align="center">
  <sub>Built with ❤️ and fusion-mlx</sub>
</p>
