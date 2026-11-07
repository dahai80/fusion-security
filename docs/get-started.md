---
doc_id: fusion-security/get-started
product: fusion-security
class: app
entry: guided-ui
doc_type: get-started
title: { zh: "fusion-security 快速上手", en: "fusion-security get started" }
audience: engineer
status: draft
version: 0.2.0rc14
updated: 2026-11-07
owner: @dahai
source_of_truth:
  - README.md
  - start.sh
  - fusion_security/cli.py
---

# 快速上手 / Get Started

## 1. 安装（macOS Apple Silicon，Python 3.12+）

```bash
git clone https://github.com/dahai80/fusion-security.git
cd fusion-security
pip install -e .
```

## 2. 命令行首扫（无需服务）

```bash
# Full scan (rule + AST)
fusion-security scan /path/to/project

# AI semantic analysis (requires local fusion-mlx running)
fusion-security scan /path/to/project --model qwen3.5-9b

# CI-friendly quick check (JSON, no AI)
fusion-security check /path/to/project

# CI/CD quality gate and SARIF export
fusion-security gate /path/to/project --policy standard
fusion-security sarif /path/to/project --output results.sarif

# List built-in detection rules
fusion-security rules
```

约束：`scan --pipeline` 启用六阶段管线（Recon→Discover→Verify→Triage→Patch→Retest）并支持断点续扫；`--sca` 默认只查本地漏洞库，`--osv` 才会联网（破坏离线承诺）。

## 3. 启动服务与 Dashboard

```bash
# Recommended: lifecycle script (PID file + logs, port 11454)
./start.sh start
./start.sh status

# Or directly
fusion-security serve --host 127.0.0.1 --port 11454
```

当 `frontend/dist/` 已构建时，API 服务同时托管 Dashboard：浏览器打开 `http://127.0.0.1:11454/`（或 `/shell/fusion-security/`）。健康检查：`/api/v1/system/health`（公开）。

```bash
# Build the dashboard (if dist is missing)
cd frontend && npm install && npm run build

# Or run it standalone in dev mode (port 11476, /api proxied to 11454)
cd frontend && npm install && npm run dev
```

## 4. 首次登录 Dashboard

1. 创建 API key（master 管理密钥经 `FUSION_SECURITY_MASTER_KEY` 稳定；明文仅在创建响应中返回一次）。
2. 打开 `http://127.0.0.1:11454/`，使用 API key 登录；默认落地页为 Admin Console（`/console`）。
3. 在 Scans 页创建扫描，在 Vulnerabilities 页筛选误报 / 生成补丁，在 Keys & Policies 页管理密钥与轮换。

约束：`/api/*` 强制租户鉴权（fail-closed）；RBAC 三级角色 admin / operator / viewer，每个端点经 `require_permission(...)` 校验具体权限。

## 5. Docker / Kubernetes

```bash
# Single container
docker compose up

# Multi-node with shared PostgreSQL (set POSTGRES_PASSWORD in your environment)
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up

# Kubernetes
helm install fusion-security deploy/helm/fusion-security/
```

## 下一步

- Dashboard 页面与功能明细见 [product-page.md](product-page.md)
- REST API 明细见 [api.md](api.md)
- 常见问题见 [troubleshooting.md](troubleshooting.md)
