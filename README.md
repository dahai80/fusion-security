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
  <img src="https://img.shields.io/badge/tests-17%20passed-brightgreen" alt="Tests">
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
| **Vulnerability scan** | ✅ Cross-file data flow | ✅ Cross-file data flow |
| **AI semantic analysis** | ✅ Logic flaw detection | ✅ Logic flaw detection |
| **Auto fix generation** | ✅ Template + AI enhanced | ✅ AI-generated patches |
| **Low false positives** | ✅ AI self-validation | ✅ Adversarial validation |
| **Audit reports** | ✅ Markdown/JSON/HTML | ✅ Enterprise dashboard |
| **CI/CD integration** | ✅ CLI + JSON output | ✅ Webhook + API |
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
| `check <path>` | Quick check (JSON output, CI-friendly) |
| `rules` | List all detection rules |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI / CI Integration                       │
│         fusion-security scan | check | rules                  │
├─────────────────────────────────────────────────────────────┤
│                    Scanner Engine                              │
│  ScanTarget (discover) → RuleEngine (match) → AIAnalyzer     │
│                                                               │
│  1. File discovery (multi-language)                           │
│  2. Rule-based pattern matching (15+ rules)                   │
│  3. AI verification (reduce false positives)                  │
│  4. AI semantic analysis (logic flaws)                        │
├─────────────────────────────────────────────────────────────┤
│                    Fix Generator                               │
│  Template fix → AI-enhanced fix → Diff patch                  │
├─────────────────────────────────────────────────────────────┤
│                    Report Generator                            │
│  Markdown | JSON | HTML → Save to file                        │
├─────────────────────────────────────────────────────────────┤
│                    AI Backend (fusion-mlx)                     │
│  HTTP → http://localhost:8000/v1/chat/completions             │
│  100% local, zero data upload                                │
└─────────────────────────────────────────────────────────────┘
```

### Vulnerability Coverage (15+ rules)

| Category | Rules | CWE |
|----------|-------|-----|
| SQL Injection | SQL001, SQL002 | CWE-89 |
| Cross-Site Scripting | XSS001, XSS002 | CWE-79 |
| Command Injection | CMD001, CMD002 | CWE-78 |
| Path Traversal | PATH001 | CWE-22 |
| Hardcoded Secrets | SEC001, SEC002 | CWE-798 |
| Weak Cryptography | CRYPTO001 | CWE-327 |
| Missing Authentication | AUTH001 | CWE-862 |
| XML External Entity | XXE001 | CWE-611 |
| Open Redirect | REDIR001 | CWE-601 |
| Log Injection | LOG001 | CWE-117 |

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

---

## 🔒 Security & Compliance

- **100% Local Offline** — Zero code upload, zero data leakage
- **No Telemetry** — No analytics, no phoning home
- **Data Sovereignty** — All scanning and processing on local machine
- **Compliant with Chinese regulations** — No cross-border data transfer
- **Audit Trail** — Complete scan logs and fix records

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