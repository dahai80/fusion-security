---
doc_id: fusion-security/troubleshooting
product: fusion-security
class: app
entry: guided-ui
doc_type: troubleshooting
title: { zh: "fusion-security 故障排查", en: "fusion-security troubleshooting" }
audience: engineer
status: draft
version: 0.2.0rc14
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - README.md
  - start.sh
  - fusion_security/api/app.py
  - frontend/package.json
---

# 故障排查 / Troubleshooting

## 安装与 CLI

**Python 版本报错**
要求 Python ≥ 3.12（`pyproject.toml`）。建议使用工作区共享 venv：`source ~/fusion/.venv/bin/activate`。

**`fusion-security scan` 找不到命令**
确认已 `pip install -e .` 且 venv 激活；脚本入口见 `pyproject.toml` `[project.scripts]`。

**扫描结果为空但预期有漏洞**
先用 `fusion-security rules` 确认规则集已加载（37 条规则）；legacy `scan` 与 `--pipeline` 管线路径不同，调试时统一加 `--pipeline` 复现。

**AI 分析不生效**
AI 语义分析需要本机 fusion-mlx 运行；确认推理服务在线，或显式 `--no-ai` 走纯规则路径。`check` / `gate` / `sarif` 刻意不走 AI（CI 快速路径），不是缺陷。

**`--osv` 触发联网告警**
`--osv` 会把依赖列表发往 osv.dev，破坏 100% 离线承诺；离线环境保持默认（本地已知漏洞库）。

## 服务启动

**`start.sh status` 显示未运行**
查看 `logs/stdout.log` 与 `logs/stderr.log`；PID 文件为 `.fusion-security.pid`。端口默认 11454，可用 `FUSION_SECURITY_PORT` / `FUSION_SECURITY_HOST` 覆盖。

**Dashboard 打开是空白 / 404**
`frontend/dist/` 未构建时服务会静默跳过 SPA 托管。执行 `cd frontend && npm install && npm run build` 后重启服务；构建产物挂载在 `/` 与 `/shell/fusion-security/`。

**前端 dev server 起不来或 /api 报错**
dev server 端口为 11476，`/api` 代理到 11454；先确认后端已启动。生产构建 base 为 `/shell/fusion-security/`，直接以 `npm run preview` 之外的方式打开静态文件会 404。

**API 返回 401 / 403**
`/api/*` 强制租户鉴权（fail-closed），请求需带 `X-API-Key`；仅 `/api/v1/system/health` 公开。403 通常是 RBAC 权限不足——admin / operator / viewer 三级角色，各端点要求具体权限（如 `scan:run`、`system:manage`、`api_key:manage`）。

**创建扫描返回 409**
每租户并发活跃扫描上限默认 4（`FUSION_MAX_CONCURRENT_SCANS`）；等待在途扫描完成或调高配额。

**API 返回 429**
按 `(client_ip, api_key)` 滑动窗口限流，默认 120/分钟（`FUSION_RATE_LIMIT_PER_MINUTE`）；响应带 `Retry-After`，按提示退避。

## 多租户与上游

**Console 成员 / 密钥 / SSO 卡片显示降级原因**
identity 聚合依赖 `FUSION_IDENTITY_URL`（默认 `http://127.0.0.1:11470`）与 `FUSION_IDENTITY_SERVICE_TOKEN`；未配置 service token 时进入 API-key-only 降级模式，卡片显示原因而非假数据。这是设计行为。

**网关代理后鉴权失败**
经 fusion-web-shell 网关访问时设置 `FUSION_SECURITY_SHELL_API_KEY`，注册体携带 `api_key`，网关代理以该 key 作为上游 Bearer 凭证；否则网关签发的 `fm-` key 会被本服务拒绝。

**CORS 启动报错**
`FUSION_CORS_ORIGINS=*` 在启动时被直接拒绝（与 `allow_credentials=True` 组合不安全）；显式列出允许的来源。

## 通知与 CI

**Webhook 未送达**
出站 URL 经 SSRF 守卫校验（私网 / loopback / link-local / metadata IP 拒绝，重定向逐跳复检）；确认目标地址为公网地址。签名头为 `X-Fusion-Security-Signature`（HMAC-SHA256）。

**GitHub Actions / GitLab CI 集成失败**
模板见 README「CI/CD Integration」；`gate` 的退出码由 policy（strict/standard/permissive）决定，先在本地跑 `fusion-security gate <path> --policy <p>` 复现退出码。

## 测试与质量

```bash
pytest
cd frontend && npm test
```

README 徽标基线为 930 项测试通过；本地失败先排除环境因素（venv、端口占用、dist 缺失）再按用例定位。

## 仍未解决

- 在 `gh issue view <N> --repo dahai80/fusion-security` 查看已知问题，或新建 issue（英文描述，附 `fusion-security --version`、`start.sh status` 输出与最小复现步骤）。
- 安全机制细节见 [security-self-assessment.md](security-self-assessment.md)。
