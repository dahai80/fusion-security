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
fusion-security serve --host 0.0.0.0 --port 8080

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
| `serve --host 0.0.0.0` | Bind to all interfaces |
| `serve --port 8080` | Custom port (default 8000) |

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
| **Checkpoint/Resume** | 断点续扫 — save pipeline state, resume from last completed stage |
| **Circuit Breaker** | 熔断器 — auto-stop pipeline on consecutive failures (CLOSED→OPEN→HALF_OPEN) |
| **Retry Policy** | 指数退避重试 — exponential backoff with configurable max retries |
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
| **Compliance Mapper** | 等保2.0 / ISO 27001 / PCI DSS mapping |
| **SARIF Export** | SARIF 2.1.0 format for IDE/CI integration |
| **RBAC + API Key** | Role-based access (admin/operator/viewer) |
| **Multi-Tenant** | Tenant isolation with per-tenant data dirs |
| **Audit Logging** | Full operation audit trail (JSONL) |
| **Dashboard** | React + Ant Design frontend (scan metrics, trends, management) |
| **Scheduler** | Cron-like periodic scan (hourly/daily/weekly/monthly) |
| **Feishu Notifier** | 飞书交互式卡片消息 + HMAC-SHA256 签名 |
| **DingTalk Notifier** | 钉钉 Markdown 消息 + HMAC-SHA256 签名 |
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

The dashboard connects to the FastAPI backend at `http://localhost:8000/api/v1`.

---

## 🔄 Checkpoint & Resume (断点续扫)

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
curl -X POST http://localhost:8000/api/v1/scans/resume \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "abc-123", "path": "/path/to/project"}'
```

---

## 📢 Notifications (飞书/钉钉)

Send scan results to Feishu (Lark) or DingTalk with HMAC-SHA256 webhook signing.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/integrations/notify/feishu` | Configure Feishu webhook |
| POST | `/api/v1/integrations/notify/dingtalk` | Configure DingTalk webhook |
| POST | `/api/v1/integrations/notify/send` | Send notification to all configured channels |

```bash
# Configure Feishu
curl -X POST http://localhost:8000/api/v1/integrations/notify/feishu \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx", "secret": "xxx"}'

# Configure DingTalk
curl -X POST http://localhost:8000/api/v1/integrations/notify/dingtalk \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=xxx", "secret": "xxx"}'

# Send notification
curl -X POST http://localhost:8000/api/v1/integrations/notify/send \
  -H "Content-Type: application/json" \
  -d '{"event": "scan_completed", "data": {"project": "my-app", "vulns": 5, "high": 2}}'
```

---

## 🌐 Web API (FastAPI)

Start the API server:

```bash
fusion-security serve
# or with options
fusion-security serve --host 0.0.0.0 --port 8080
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
| POST | `/api/v1/integrations/compliance` | Compliance mapping (等保/ISO/PCI) |
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
curl -X POST http://localhost:8000/api/v1/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "my-project", "local_path": "/path/to/project"}'

# Start scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"project_id": "<id>", "scan_type": "full", "use_ai": true}'

# List vulnerabilities
curl http://localhost:8000/api/v1/vulnerabilities?severity=critical

# Get stats
curl http://localhost:8000/api/v1/vulnerabilities/stats/summary
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
          server-url: 'http://fusion-security:8000'
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
| `service.port` | `8000` | Service port |
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
# 🔒 Fusion-Security 代码安全审计
# ================================================
#   扫描目标: /Users/me/my-project
#   AI 分析:  ✅ 已启用
#
#   📊 发现 3 个安全漏洞 | high: 2 | medium: 1
#   扫描文件: 42 个
#   扫描耗时: 1250ms
#
#   漏洞列表:
#   1. 🟠 [HIGH] 硬编码密钥
#      /Users/me/my-project/config.py:15
#      💡 使用环境变量或密钥管理服务存储敏感信息
#   2. 🟠 [HIGH] 命令注入
#      /Users/me/my-project/utils.py:42
#      💡 使用subprocess.run传入参数列表而非字符串
#   3. 🟡 [MEDIUM] 日志注入
#      /Users/me/my-project/app.py:88
#      💡 对用户输入进行换行符过滤后再写入日志
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
- **Compliant with Chinese regulations** — No cross-border data transfer
- **Compliance Mapping** — 等保2.0 / ISO 27001 / PCI DSS
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

---

<br>

<div align="center">
  <h1>🔒 Fusion-Security</h1>
  <p><strong>本地 AI 代码安全审计工具 — macOS Apple Silicon 原生</strong></p>
  <p><em>100% 本地离线，代码不出境，基于 fusion-mlx。国内 Claude Security 替代方案。</em></p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/macOS-Apple%20Silicon-brightgreen" alt="macOS">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="许可证">
  <img src="https://img.shields.io/badge/AI-MLX%20Native-orange" alt="MLX">
  <img src="https://img.shields.io/badge/离线优先-核心特性-important" alt="离线优先">
  <img src="https://img.shields.io/badge/状态-beta-yellow" alt="Beta">
  <img src="https://img.shields.io/badge/测试-690%20通过-brightgreen" alt="测试">
  <img src="https://img.shields.io/badge/React-18-blue" alt="React">
  <img src="https://img.shields.io/badge/K8s-Helm-blueviolet" alt="Helm">
</p>

---

## 📋 产品简介

**Fusion-Security** 是一款本地 AI 代码安全审计工具，基于 `fusion-mlx` 构建，**100% 本地离线，代码不出境**，是国内环境下 Claude Security 的合规替代方案。

### 对标 Claude Security

| 能力 | Claude Security | Fusion-Security |
|------|----------------|-----------------|
| 数据本地化 | ❌ 上传境外服务器 | ✅ **100% 本地，不上传** |
| 国内可访问 | ❌ 被屏蔽 | ✅ **完全可用** |
| 离线运行 | ❌ 需要联网 | ✅ **完全离线** |
| 漏洞扫描 | ✅ 跨文件数据流 | ✅ 37 规则 + AST(10语言) + 污点追踪 + 8 AI语义规则 |
| AI 语义分析 | ✅ 逻辑漏洞识别 | ✅ fusion-mlx 语义分析 |
| 修复补丁 | ✅ AI 生成 | ✅ 模板 + AI 增强 |
| 低误报率 | ✅ 对抗式验证 | ✅ **对抗式双智能体验证** |
| 审计报告 | ✅ | ✅ Markdown/JSON/HTML |
| CI/CD 集成 | ✅ Webhook | ✅ **GitHub Actions + GitLab CI + CLI** |
| Web 仪表盘 | ✅ | ✅ **React + Ant Design** |
| 通知推送 | ❌ | ✅ **飞书 + 钉钉** |
| 断点续扫 | ❌ | ✅ **Checkpoint + 熔断器** |
| K8s 部署 | ❌ | ✅ **Helm Chart** |
| Web API | ✅ | ✅ **FastAPI REST API** |
| 开源免费 | ❌ 企业订阅 | ✅ **MIT 协议** |

### 快速开始

```bash
# 安装
git clone https://github.com/dahai80/fusion-security.git
cd fusion-security
pip install -e .

# 扫描项目
fusion-security scan /path/to/project

# 快速检查（CI 友好）
fusion-security check /path/to/project

# 列出检测规则
fusion-security rules

# 启动 Web API 服务
fusion-security serve

# 启动前端仪表盘
cd frontend && npm install && npm run dev
```

### 架构

```
┌──────────────────────────────────────────────────────────────────┐
│                          接入层                                   │
│    CLI │ Web 仪表盘 │ Web API │ IDE 插件 │ CI/CD │ REST API      │
├──────────────────────────────────────────────────────────────────┤
│                          服务层                                   │
│  扫描服务 │ 验证服务 │ 补丁服务 │ 报告服务                         │
├──────────────────────────────────────────────────────────────────┤
│                          引擎层                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │ 语义分析     │  │ 污点追踪     │  │ 对抗式验证              │ │
│  │ (规则引擎)   │  │ (TaintTracker)│  │ (AdversarialVerifier)  │ │
│  │ + AST 解析   │  │ 源→传播→汇   │  │ 攻击 + 防御双智能体    │ │
│  └─────────────┘  └──────────────┘  └─────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ 规则引擎 (37规则) │ AI分析器(8语义规则) │ SCA扫描器 │ CVSS评分   │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ 5阶段流水线 │ 安全门禁 │ 反馈闭环 │ 自定义规则                │ │
│  │ 断点续扫 │ 熔断器 │ 重试策略                              │ │
│  └─────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│                          集成层                                   │
│  飞书通知 │ 钉钉通知 │ GitHub Actions │ GitLab CI                 │
├──────────────────────────────────────────────────────────────────┤
│                          基础层                                   │
│  SQLite+SQLAlchemy │ 本地AI (fusion-mlx) │ 多租户 │ 审计日志     │
│  Kubernetes (Helm) │ PVC 持久化 │ HPA 弹性伸缩                   │
└──────────────────────────────────────────────────────────────────┘
```

### Web 仪表盘 (React)

```bash
cd frontend
npm install
npm run dev        # 开发服务器 (http://localhost:5173)
npm run build      # 生产构建
```

| 页面 | 说明 |
|------|------|
| **仪表盘** | 统计卡片（扫描数、漏洞数、高危、已修复）+ 系统健康 |
| **扫描管理** | 扫描列表、创建扫描、删除、状态跟踪 |
| **漏洞管理** | 漏洞表格（筛选）、详情弹窗、标记误报、生成补丁 |
| **项目管理** | 项目增删改查 |

### 断点续扫 + 熔断器

- **断点续扫** — 每阶段完成后保存检查点到 `.fusion_checkpoints/`，中断后可恢复
- **熔断器** — 连续失败自动熔断（CLOSED→OPEN→HALF_OPEN），保护系统
- **重试策略** — 指数退避重试，可配置最大重试次数和延迟

```bash
# 查看检查点
curl http://localhost:8000/api/v1/scans/checkpoints

# 恢复扫描
curl -X POST http://localhost:8000/api/v1/scans/resume \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "abc-123", "path": "/path/to/project"}'
```

### 通知推送 (飞书/钉钉)

```bash
# 配置飞书
curl -X POST http://localhost:8000/api/v1/integrations/notify/feishu \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx", "secret": "xxx"}'

# 配置钉钉
curl -X POST http://localhost:8000/api/v1/integrations/notify/dingtalk \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=xxx", "secret": "xxx"}'

# 发送通知
curl -X POST http://localhost:8000/api/v1/integrations/notify/send \
  -H "Content-Type: application/json" \
  -d '{"event": "scan_completed", "data": {"project": "my-app", "vulns": 5, "high": 2}}'
```

### CI/CD 集成

**GitHub Actions:**

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
```

**GitLab CI:**

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/dahai80/fusion-security/main/ci/gitlab/.gitlab-ci.yml'
```

### Kubernetes 部署 (Helm)

```bash
helm install fusion-security deploy/helm/fusion-security \
  --set image.tag=latest \
  --set fusionMLX.enabled=true \
  --set persistence.enabled=true
```

### Web API (FastAPI)

启动服务：

```bash
fusion-security serve
```

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/api/v1/projects` | 创建项目 |
| GET | `/api/v1/projects` | 项目列表 |
| PUT | `/api/v1/projects/{id}` | 更新项目 |
| POST | `/api/v1/scans` | 启动扫描（异步） |
| GET | `/api/v1/scans` | 扫描列表 |
| GET | `/api/v1/scans/checkpoints` | 查看检查点 |
| POST | `/api/v1/scans/resume` | 恢复扫描 |
| GET | `/api/v1/vulnerabilities` | 漏洞列表（支持筛选） |
| PATCH | `/api/v1/vulnerabilities/{id}` | 更新漏洞状态 |
| PUT | `/api/v1/vulnerabilities/{id}/status` | 更新状态（含验证） |
| GET | `/api/v1/vulnerabilities/export` | 导出漏洞（JSON/CSV） |
| GET | `/api/v1/vulnerabilities/stats/summary` | 统计摘要 |
| POST | `/api/v1/integrations/gate` | 安全门禁评估 |
| POST | `/api/v1/integrations/cvss` | CVSS 3.1 评分 |
| POST | `/api/v1/integrations/compliance` | 合规映射（等保/ISO/PCI） |
| POST | `/api/v1/integrations/feedback` | 提交误报反馈 |
| POST | `/api/v1/integrations/rules` | 创建自定义规则 |
| GET | `/api/v1/integrations/dashboard` | 仪表盘统计 |
| POST | `/api/v1/integrations/notify/feishu` | 配置飞书通知 |
| POST | `/api/v1/integrations/notify/dingtalk` | 配置钉钉通知 |
| POST | `/api/v1/integrations/notify/send` | 发送通知 |
| POST | `/api/v1/integrations/jira/config` | 配置 Jira 集成 |
| POST | `/api/v1/integrations/jira/sync` | 同步漏洞到 Jira |
| GET | `/api/v1/integrations/jira/issue/{key}` | 获取 Jira 工单 |
| POST | `/api/v1/keys` | 创建 API Key |
| GET | `/api/v1/system/health` | 健康检查 |
| GET | `/api/v1/system/rules` | 规则列表 |
| PUT | `/api/v1/system/models` | 更新默认模型配置 |

### 漏洞覆盖（37 规则）

| 类别 | 规则 | CWE |
|------|------|-----|
| SQL 注入 | SQL001, SQL002 | CWE-89 |
| XSS 跨站脚本 | XSS001, XSS002 | CWE-79 |
| 命令注入 | CMD001, CMD002 | CWE-78 |
| 路径穿越 | PATH001 | CWE-22 |
| 硬编码密钥 | SEC001, SEC002 | CWE-798 |
| 弱加密算法 | CRYPTO001 | CWE-327 |
| 硬编码加密密钥 | CRYPTO002 | CWE-321 |
| 缺少鉴权 | AUTH001 | CWE-862 |
| XXE 注入 | XXE001 | CWE-611 |
| 开放重定向 | REDIR001 | CWE-601 |
| 日志注入 | LOG001 | CWE-117 |
| 不安全数据传输 | INSECURETRANS001 | CWE-319 |
| 目录列表暴露 | DIRTRAVERS001 | CWE-548 |
| **AI 语义规则** | | |
| 水平越权访问 | AI_ACL001 | CWE-639 |
| 垂直越权访问 | AI_ACL002 | CWE-639 |
| 多因素认证缺失 | AI_AUTH006 | CWE-308 |
| 详细错误信息泄露 | AI_CONF002 | CWE-209 |
| 支付金额篡改 | AI_LOGIC001 | CWE-94 |
| 竞态条件 | AI_LOGIC002 | CWE-362 |
| 业务流程绕过 | AI_LOGIC003 | CWE-285 |
| 数据完整性校验缺失 | AI_LOGIC004 | CWE-354 |
| **SCA 规则** | | |
| 已知漏洞 | OSV + 本地库 | Multiple |
| 废弃组件 | FUS-SCA-002 | CWE-1104 |
| 许可证风险 | FUS-SCA-003 | CWE-1104 |
| 过期依赖 | FUS-SCA-004 | CWE-1104 |

### 测试

```bash
pip install -e ".[test]"
pytest tests/ -v
# 690 tests, 91% coverage
```

### 安全合规

- **100% 本地离线** — 零代码上传，零数据泄露
- **无遥测** — 无埋点、无回传
- **数据主权** — 所有扫描和处理在本地完成
- **符合国内法规** — 无跨境数据传输
- **合规映射** — 等保2.0 / ISO 27001 / PCI DSS
- **CVSS 3.1 评分** — 标准化漏洞严重度评估
- **RBAC 权限** — admin/operator/viewer 三级角色
- **审计溯源** — 完整操作审计日志（JSONL）
- **多租户隔离** — 租户数据物理隔离
- **API Key 认证** — 安全的 API 访问控制
- **Webhook 签名** — 飞书/钉钉 HMAC-SHA256 签名验证

### 开源协议

MIT License
