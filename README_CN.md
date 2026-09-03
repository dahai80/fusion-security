<div align="center">
  <h1>🔒 Fusion-Security</h1>
  <p><strong>本地 AI 代码安全审计工具 — macOS Apple Silicon 原生</strong></p>
  <p><em>100% 本地离线，代码不出境，基于 fusion-mlx。国内 Claude Security 替代方案。</em></p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/macOS-Apple%20Silicon-brightgreen" alt="macOS">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="许可证">
  <img src="https://img.shields.io/badge/AI-MLX%20Native-orange" alt="MLX">
  <img src="https://img.shields.io/badge/离线优先-核心特性-important" alt="离线优先">
  <img src="https://img.shields.io/badge/状态-beta-yellow" alt="Beta">
  <img src="https://img.shields.io/badge/测试-847%20通过-brightgreen" alt="测试">
  <img src="https://img.shields.io/badge/React-18-blue" alt="React">
  <img src="https://img.shields.io/badge/K8s-Helm-blueviolet" alt="Helm">
</p>

<p align="center">
  <a href="README.md">English</a>
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
│  可插拔 DB（默认 SQLite / 多节点共享 PostgreSQL）│ 本地AI          │
│  多租户 │ 审计日志 │ Kubernetes (Helm) │ PVC │ HPA 弹性伸缩      │
└──────────────────────────────────────────────────────────────────┘
```

### 引擎组件

> **流水线为权威路径。** `POST /api/v1/scans` 与 `/resume` 走 6 阶段 `ScanPipeline`（侦察→发现→验证→分诊→补丁→复测），findings 与 patches 全程落库。旧版 `Scanner` 仅保留给无 AI 的 CI 友好 CLI 命令（`check`/`gate`/`sarif`）。支持 path-only 扫描（无 `project_id`）— `scans.project_id` 可空且无外键约束。

| 组件 | 说明 |
|------|------|
| **5阶段流水线** | 侦察→发现→验证→分诊→补丁 编排 |
| **断点续扫** | 每阶段完成后保存检查点，中断后可从上次位置恢复 |
| **熔断器** | 连续失败自动熔断（CLOSED→OPEN→HALF_OPEN） |
| **重试策略** | 指数退避重试，可配置最大重试次数和延迟 |
| **AST 解析器** | Tree-sitter 多语言 AST（Python/JS/TS/Java/Go/C/C++/Rust/Ruby/PHP），子进程隔离 |
| **污点追踪** | 源 → 传播 → 汇 数据流分析 |
| **对抗式验证** | 双智能体验证（攻击 + 防御） |
| **规则引擎** | 37 条内置规则（15 正则 + 8 AI语义 + 3 SCA + 11 遗留） |
| **自定义规则引擎** | 用户自定义规则，支持增删改查和灰度发布 |
| **SCA 扫描器** | 依赖漏洞扫描（OSV.dev API + 本地回退）+ 废弃组件(FUS-SCA-002) + 许可证风险(FUS-SCA-003) + 过期依赖(FUS-SCA-004) |
| **AI 分析器** | 基于 fusion-mlx 语义扫描（100% 本地）+ 8 条 AI 语义规则（ACL/AUTH/CONF/LOGIC） |
| **CVSS 3.1 评分** | 完整 CVSS 基础分计算器 |
| **安全门禁** | CI/CD 质量门禁（严格/标准/宽松） |
| **反馈闭环** | 误报学习与抑制 |
| **修复生成器** | 模板 + AI 增强补丁生成，含验证 |
| **Jira 集成** | 从漏洞创建 Jira 工单（REST API v2，基础认证） |
| **扫描缓存** | LRU 缓存 + TTL + 项目级持久缓存（文件哈希 → 结果） |
| **HTML 报告** | Jinja2 模板引擎，XSS 自动转义 |
| **合规映射** | 等保2.0 / ISO 27001 / PCI DSS |
| **SARIF 导出** | SARIF 2.1.0 格式，支持 IDE/CI 集成 |
| **RBAC + API Key** | 角色访问控制（管理员/操作员/只读） |
| **多租户** | 租户隔离，每租户独立数据目录 |
| **审计日志** | 完整操作审计溯源（JSONL） |
| **仪表盘** | React + Ant Design 前端（扫描指标、趋势、管理） |
| **调度器** | 类 Cron 定期扫描（每小时/每天/每周/每月） |
| **飞书通知** | 交互式卡片消息 + HMAC-SHA256 签名 |
| **钉钉通知** | Markdown 消息 + HMAC-SHA256 签名 |
| **GitHub Actions** | 组合动作，含严重度门禁 + 制品上传 |
| **GitLab CI** | 包含模板，全量/增量扫描任务 |
| **Helm Chart** | Kubernetes 部署（fusion-security + fusion-mlx 双容器） |

### 安全硬化

| 控制项 | 作用 |
|--------|------|
| **SSRF 防护** | Webhook/通知外发 URL 校验私网/环回/链路本地/元数据 IP，防 DNS 重绑定；跟随重定向但每个 `Location` 跳转重新校验、DNS 按请求钉定，302 无法重绑定内网 IP（`engine/ci/_url_guard.py`） |
| **日志脱敏** | 日志过滤器在落盘前清洗 `password`/`api_key`/`token`/`Bearer`/`Authorization` 值（`utils/logger.py`） |
| **离线优先 SCA** | 依赖扫描默认本地已知漏洞库；OSV.dev 云查询经 `--osv` 显式开启并告警 |
| **AI 补丁审核** | AI 生成修复经校验并标记 `needs_review=True`；失败标记串与空输出被拒绝 |
| **哈希密钥库** | API key 以 `sha256` 哈希存入 DB（`ApiKeyORM`）；明文仅在创建时返回一次，不落库不记日志 |
| **DB 文件权限** | SQLite 库文件（含 key 哈希与代码片段）以 `umask 0o077` 创建为 `0600` |
| **CORS 加固** | `allow_credentials=True` 配显式方法/头白名单；`FUSION_CORS_ORIGINS=*` 启动时即拒绝（带凭据时非法且危险） |
| **SSRF 纵深防御** | Jira `base_url` 在 API 配置与客户端初始化两处经 SSRF 守卫校验；`issue_key` 防路径/查询注入净化 |
| **错误脱敏** | 扫描失败 summary、`/system/model/config`、AI 修复失败标记均回通用文案 — 异常细节仅留服务端日志 |
| **租户路径安全** | 审计日志文件名将 `tenant_id` 净化为安全 slug（防路径穿越） |
| **验证器 fail-closed** | Retest 在规则正则抛异常时判 `failed`（非 `verified`）；Verify 在 AI 验证中止时保留 `verified=False` — 安全门禁绝不 fail-open |
| **孤儿扫描回收** | API 启动时将上次崩溃遗留的 `running` 扫描标 `failed`，`queued` 扫描重入队 — 重启后无扫描永久挂起 |
| **AI 背压** | MLX 调用受并发信号量限制（默认 4），并发扫描不会压垮单一推理实例导致 OOM |
| **缓存批量写入** | `ProjectScanCache` 每阶段统一 flush 而非逐文件 commit，消除大库的 N 次 fsync 风暴 |
| **API 限流** | 按 `(client_ip, api_key)` 滑动窗口限流（`FUSION_RATE_LIMIT_PER_MINUTE`，默认 120/分钟 → `429` + `Retry-After`），覆盖除公开健康探针外所有 `/api/v1/` 路由 |
| **每租户扫描配额** | 每租户并发活跃扫描（running/queued/pending）上限 `FUSION_MAX_CONCURRENT_SCANS`（默认 4 → `409`），单租户无法耗尽工作池 |
| **端点级 RBAC** | 每个路由强制具体权限（`scan:run`/`vuln:manage`/`system:manage`…）经 `require_permission`，非"任意有效 key" — 默认最小权限 |
| **租户 IDOR 闭合** | 扫描/漏洞/补丁/项目/webhook/计划任务查询按 `tenant_id` **fail-closed** 过滤（无 `if tenant_id:` 跳过）；跨租户请求返回 `404`，不泄露记录存在性。空租户 API Key 返回 `401`（不泄露全量数据）。租户身份归 fusion-identity 统一管理 |
| **Webhook 触发时 HMAC** | Webhook secret 以 Fernet 加密（密钥由 `FUSION_SECURITY_MASTER_KEY` 派生），事件触发时可回算 `X-Fusion-Security-Signature` HMAC，绝不存明文 secret |

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

---

## 🖥️ Web 仪表盘 (React)

React 18 + Ant Design 5 + Vite 5 + TypeScript 前端仪表盘。

```bash
cd frontend
npm install
npm run dev        # 开发服务器 (http://localhost:5173)
npm run build      # 生产构建
npm run preview    # 预览生产构建
```

| 页面 | 说明 |
|------|------|
| **仪表盘** | 统计卡片（扫描数、漏洞数、高危、已修复）+ 系统健康 |
| **扫描管理** | 扫描列表、创建扫描、删除、状态跟踪 |
| **漏洞管理** | 漏洞表格（筛选）、详情弹窗、标记误报、生成补丁 |
| **项目管理** | 项目增删改查 |

仪表盘连接后端 FastAPI 服务 `http://localhost:11454/api/v1`。

---

## 🔄 断点续扫 + 熔断器

流水线扫描支持中断后从上次完成阶段恢复。

### 工作原理

1. **检查点** — 每阶段完成后保存状态到 `.fusion_checkpoints/`
2. **恢复** — 传入 `scan_id` 从上次检查点恢复，跳过已完成阶段
3. **熔断器** — 连续阶段失败时自动熔断（CLOSED→OPEN）
4. **重试** — 失败阶段指数退避重试，超过阈值触发熔断

### 熔断器状态

```
CLOSED (正常) → OPEN (熔断，超过失败阈值)
                    ↓ 恢复超时
               HALF_OPEN (探测，允许1个请求)
                    ↓ 成功           ↓ 失败
               CLOSED            OPEN
```

### API 端点

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/v1/scans/checkpoints` | 查看所有检查点 |
| POST | `/api/v1/scans/resume` | 从检查点恢复扫描 |

```bash
# 恢复扫描
curl -X POST http://localhost:11454/api/v1/scans/resume \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "abc-123", "path": "/path/to/project"}'
```

---

## 📢 通知推送（飞书/钉钉）

支持飞书、钉钉 Webhook 通知，HMAC-SHA256 签名验证。

### API 端点

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/api/v1/integrations/notify/feishu` | 配置飞书 Webhook |
| POST | `/api/v1/integrations/notify/dingtalk` | 配置钉钉 Webhook |
| POST | `/api/v1/integrations/notify/send` | 向所有已配置渠道发送通知 |

```bash
# 配置飞书
curl -X POST http://localhost:11454/api/v1/integrations/notify/feishu \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx", "secret": "xxx"}'

# 配置钉钉
curl -X POST http://localhost:11454/api/v1/integrations/notify/dingtalk \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=xxx", "secret": "xxx"}'

# 发送通知
curl -X POST http://localhost:11454/api/v1/integrations/notify/send \
  -H "Content-Type: application/json" \
  -d '{"event": "scan_completed", "data": {"project": "my-app", "vulns": 5, "high": 2}}'
```

---

## 🌐 Web API (FastAPI)

启动 API 服务：

```bash
fusion-security serve
# 或指定参数
fusion-security serve --host 127.0.0.1 --port 8080
```

### API 端点

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/api/v1/projects` | 创建项目 |
| GET | `/api/v1/projects` | 项目列表 |
| GET | `/api/v1/projects/{id}` | 项目详情 |
| PUT | `/api/v1/projects/{id}` | 更新项目 |
| DELETE | `/api/v1/projects/{id}` | 删除项目 |
| GET | `/api/v1/projects/{id}/scan-summary` | 项目扫描摘要（扫描数、漏洞统计、缓存状态） |
| POST | `/api/v1/scans` | 启动扫描（异步） |
| GET | `/api/v1/scans` | 扫描列表 |
| GET | `/api/v1/scans/{id}` | 扫描详情 |
| DELETE | `/api/v1/scans/{id}` | 删除扫描 |
| GET | `/api/v1/scans/checkpoints` | 查看检查点 |
| POST | `/api/v1/scans/resume` | 恢复扫描 |
| GET | `/api/v1/vulnerabilities` | 漏洞列表（支持筛选） |
| GET | `/api/v1/vulnerabilities/{id}` | 漏洞详情 |
| PATCH | `/api/v1/vulnerabilities/{id}` | 更新漏洞状态 |
| PUT | `/api/v1/vulnerabilities/{id}/status` | 更新状态（含验证） |
| GET | `/api/v1/vulnerabilities/export` | 导出漏洞（JSON/CSV） |
| GET | `/api/v1/vulnerabilities/stats/summary` | 统计摘要 |
| GET | `/api/v1/patches` | 补丁列表 |
| GET | `/api/v1/patches/{id}` | 补丁详情 |
| POST | `/api/v1/patches/{id}/verify` | 验证补丁 |
| GET | `/api/v1/reports/scans/{id}/sarif` | 导出 SARIF 2.1.0 报告 |
| POST | `/api/v1/integrations/gate` | 安全门禁评估 |
| POST | `/api/v1/integrations/cvss` | CVSS 3.1 评分 |
| POST | `/api/v1/integrations/compliance` | 合规映射（等保/ISO/PCI） |
| POST | `/api/v1/integrations/feedback` | 提交误报反馈 |
| GET | `/api/v1/integrations/feedback/stats` | 反馈统计 |
| POST | `/api/v1/integrations/rules` | 创建自定义规则 |
| GET | `/api/v1/integrations/rules` | 自定义规则列表 |
| DELETE | `/api/v1/integrations/rules/{id}` | 删除自定义规则 |
| GET | `/api/v1/integrations/dashboard` | 仪表盘统计 |
| POST | `/api/v1/integrations/notify/feishu` | 配置飞书通知 |
| POST | `/api/v1/integrations/notify/dingtalk` | 配置钉钉通知 |
| POST | `/api/v1/integrations/notify/send` | 发送通知 |
| POST | `/api/v1/integrations/jira/config` | 配置 Jira 集成 |
| POST | `/api/v1/integrations/jira/sync` | 同步漏洞到 Jira |
| GET | `/api/v1/integrations/jira/issue/{key}` | 获取 Jira 工单 |
| POST | `/api/v1/keys` | 创建 API Key |
| GET | `/api/v1/keys` | API Key 列表 |
| GET | `/api/v1/system/health` | 健康检查 |
| GET | `/api/v1/system/info` | 版本与平台信息 |
| GET | `/api/v1/system/rules` | 内置规则列表 |
| PUT | `/api/v1/system/models` | 更新默认模型配置 |

### 认证与多租户（fusion-identity）

自 v0.2.0 起，fusion-security 将 **JWT 签发与租户注册**委托给 [`fusion-identity`](https://github.com/dahai80/fusion-identity) —— 生态内统一身份权威。本地租户注册表（`TenantManager`、`fs_tenant_*` 密钥、`tenants.json`）已**退役**；实例化 `TenantManager` 现抛 `RuntimeError`。

**双模式鉴权** —— 所有数据路由同时接受两种凭证：

| 模式 | 凭证 | 租户来源 | 角色来源 |
|------|------|----------|----------|
| API Key | `X-API-Key: <fs_...>` | key 的 `tenant_id`（与 `X-Tenant-Id` 头交叉校验） | key 的 `roles` |
| JWT | `Authorization: Bearer <jwt>` | JWT 的 `tid` 声明（与 `X-Tenant-Id` 头交叉校验） | JWT 的 `role` 声明 |

`X-Tenant-Id` 头为**必填**。`TenantMiddleware`（来自 `fusion_core.tenant`）强制头存在并校验 JWT↔头匹配；随后 principal 解析器（`get_principal`）做 **fail-closed** 租户校验：

- API Key 空租户 → `401`（不泄露全量数据）
- API Key `tenant_id` ≠ `X-Tenant-Id` 头 → `401`
- 跨租户扫描/漏洞/补丁/项目/webhook/计划任务查询 → `404`（不泄露存在性）
- 缺 `X-Tenant-Id` 头 → `401`
- Bearer JWT 的 `tid` ≠ `X-Tenant-Id` 头 → `401`
- 已吊销 JWT / identity 不可达（Bearer 路径）→ `401`（fail-closed；纯 API Key 请求不受影响，因不咨询 identity）

**每租户并发扫描配额**取自 fusion-identity `/verify` 返回的 `quota.max_concurrent_scans`（JWT 路径），纯 API Key 路径回退到 `FUSION_MAX_CONCURRENT_SCANS`（默认 4）。扫描完成时 best-effort 回报用量到 fusion-identity。

**环境变量：**

| 变量 | 默认值 | 用途 |
|------|--------|------|
| `FUSION_IDENTITY_URL` | `http://127.0.0.1:11470` | fusion-identity 基址 |
| `FUSION_IDENTITY_SERVICE_TOKEN` | _（空）_ | 调用 `/verify` 的服务令牌；未设时 JWT 校验不可用（API Key 模式仍可用） |

免租户中间件的公开端点：`/api/v1/system/health`、`/docs`、`/openapi.json`、`/redoc`。

---

## 🔗 CI/CD 集成

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
```

参数：`path`、`severity`、`no-ai`、`format`、`output`、`fail-on-severity`、`server-url`、`incremental`

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/dahai80/fusion-security/main/ci/gitlab/.gitlab-ci.yml'
    inputs:
      severity: 'high'
      fail_on: 'critical'
```

任务：`fusion-security-full`（定时全量）、`fusion-security-incremental`（MR 增量）

CI 变量：`FUSION_SECURITY_SEVERITY`、`FAIL_ON`、`NO_AI`、`FORMAT`、`SERVER`

---

## ☸️ Kubernetes 部署 (Helm)

```bash
# 安装
helm install fusion-security deploy/helm/fusion-security \
  --set image.tag=latest \
  --set fusionMLX.enabled=true \
  --set persistence.enabled=true

# 配置 Ingress
helm install fusion-security deploy/helm/fusion-security \
  --set ingress.enabled=true \
  --set ingress.host=fusion-security.example.com
```

### 关键参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `image.repository` | `fusion-security` | 镜像仓库 |
| `image.tag` | `latest` | 镜像标签 |
| `service.port` | `11454` | 服务端口 |
| `ingress.enabled` | `false` | 启用 Ingress |
| `persistence.enabled` | `true` | 启用 PVC |
| `persistence.size` | `5Gi` | PVC 大小 |
| `fusionMLX.enabled` | `true` | 部署 fusion-mlx 边车 |
| `fusionMLX.image` | `fusion-mlx` | MLX 镜像 |
| `autoscaling.enabled` | `false` | 启用 HPA |
| `autoscaling.maxReplicas` | `5` | 最大副本数 |

---

## 🗄️ 数据库（默认 SQLite / 多节点共享 PostgreSQL）

存储层基于 SQLAlchemy，可插拔。**单机部署仍用 SQLite（零配置、100% 离线）**，无需额外设置。**多节点集群**让所有节点指向同一个共享 PostgreSQL（或任意 SQLAlchemy 支持的库），扫描结果、项目、漏洞在节点间一致，不再每节点数据分叉。

### 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `FUSION_SECURITY_DB_URL` | _空_ | 共享库的完整 SQLAlchemy URL。设置后覆盖 SQLite 默认。示例：`postgresql+asyncpg://user:pass@host:5432/fusion` |
| `FUSION_DB_PATH` | `~/.fusion-security/fusion_security.db` | SQLite 文件路径（单机）。设置 `FUSION_SECURITY_DB_URL` 后忽略。 |

解析优先级：显式 `db_url` 参数 > 显式 `db_path` 参数 > `FUSION_SECURITY_DB_URL` > `FUSION_DB_PATH` > 默认 SQLite 文件。

### 单机（默认，无需操作）

```bash
fusion-security scan ~/my-project   # 写入 ~/.fusion-security/fusion_security.db
```

### 多节点集群（共享 PostgreSQL）

```bash
# 1. 安装可选数据库驱动
pip install -e ".[postgres]"     # asyncpg（异步）+ psycopg2-binary（同步）

# 2. 每个节点指向同一个共享库
export POSTGRES_PASSWORD="你的强密码"
export FUSION_SECURITY_DB_URL="postgresql+asyncpg://fusion:${POSTGRES_PASSWORD}@fusion-postgres:5432/fusion"
fusion-security serve --port 11454
```

Docker Compose 多节点：`docker-compose.postgres.yml` override 会拉起 `postgres:16` 服务并把 `FUSION_SECURITY_DB_URL` 指向它。PostgreSQL 密码**不硬编码** — 从 `POSTGRES_PASSWORD` 环境变量读取，未设置时 compose 直接启动失败。

```bash
export POSTGRES_PASSWORD="你的强密码"   # 必填
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up
```

> SQLite 专属优化（WAL 日志模式、`StaticPool`、`PRAGMA foreign_keys`、`PRAGMA table_info` 迁移）**仅在解析出的 URL 为 SQLite 时**自动启用。在 PostgreSQL/MySQL 上引擎使用标准连接池与可移植的 `information_schema` 迁移，不会向共享库发送任何 SQLite 专有 SQL。

---

## 🔧 使用示例

```bash
# 扫描项目
fusion-security scan ~/my-project

# 输出：
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

## 🧪 测试

```bash
pip install -e ".[test]"
pytest tests/ -v
# 847 测试用例，90% 覆盖率（CI 门禁 --cov-fail-under=90）
```

覆盖所有模块：规则引擎（37规则）、扫描器、AI 分析器（8语义规则）、SCA 扫描器（废弃/许可证/过期）、Jira 集成、流水线、断点续扫、熔断器、通知、修复生成器、报告、API 路由、CLI。

---

## 🔒 安全合规

- **100% 本地离线** — 零代码上传，零数据泄露
- **无遥测** — 无埋点、无回传
- **数据主权** — 所有扫描和处理在本地完成
- **符合国内法规** — 无跨境数据传输
- **合规映射** — 等保2.0 / ISO 27001 / PCI DSS
- **CVSS 3.1 评分** — 标准化漏洞严重度评估
- **RBAC 权限** — admin/operator/viewer 三级角色；每个 API 端点经 `require_permission(...)` 强制具体权限（如 `scan:run`/`vuln:manage`/`system:manage`），而非仅"已认证"
- **DB 落库哈希密钥** — API key 以 `sha256` 哈希存入 `api_keys` 表（绝不存明文）；master 管理密钥经 `FUSION_SECURITY_MASTER_KEY` 稳定，重启不丢失，明文**仅在创建响应中返回一次**，绝不写入日志
- **Webhook 密钥安全** — Webhook secret 用 Fernet 对称加密存储（密钥由 `FUSION_SECURITY_MASTER_KEY` 经 PBKDF2-HMAC-SHA256 派生），既能在触发时回算 HMAC 签名、又不落明文；`secret_hash` 绝不出现在 API 响应中
- **审计溯源** — 完整操作审计日志（JSONL）
- **多租户隔离** — 每租户独立数据目录 + `tenant_id` 贯穿扫描/漏洞/补丁路由；跨租户访问记录返回 `404`（不泄露存在性 — 关闭租户 IDOR）
- **API Key 认证** — `X-API-Key` 请求头；密钥以 `sha256` 哈希存入 DB，明文仅创建时返回一次
- **Webhook 签名** — 飞书/钉钉 HMAC-SHA256 签名验证；配置 secret 时发送 `X-Fusion-Security-Signature` 头
- **SSRF 重定向守卫** — Webhook/通知外发 HTTP 跟随重定向，但每个 `Location` 跳转都重新过 SSRF 守卫、DNS 按请求钉定，302 无法重绑定到内网 IP
- **API 限流** — 按 `(client_ip, api_key)` 滑动窗口限流（`FUSION_RATE_LIMIT_PER_MINUTE`，默认 120/分钟，超限 `429` + `Retry-After`），另加每租户并发扫描配额（`FUSION_MAX_CONCURRENT_SCANS`，默认 4，超限 `409`）

## 🔧 配置（环境变量）

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `FUSION_SECURITY_PORT` | `11454` | API 服务端口 |
| `FUSION_SECURITY_HOST` | `127.0.0.1` | API 服务绑定地址 |
| `FUSION_SECURITY_MASTER_KEY` | _自动生成_ | 稳定的 master 管理 API key。生产环境请显式设置，保证 admin key 重启不丢失、不在每次启动时重新生成。明文值**绝不记录日志**。 |
| `MLX_BASE_URL` | `http://localhost:11432/v1` | fusion-mlx OpenAI 兼容 API 地址。回退到 `FUSION_AI_URL` 再 `FUSION_MLX_URL`，兼容现有 Docker/Helm 配置。**请设为实际运行的 fusion-mlx 端口**（monorepo 默认 11434）。 |
| `FUSION_MODEL` | _自动_ | 模型名覆盖（如 `qwen3.5-9b`）。未设时分析器从 `/models` 自动探测首个已加载模型。 |
| `FUSION_SECURITY_DB_URL` | _空_ | 共享库完整 SQLAlchemy URL（见数据库章节） |
| `FUSION_DB_PATH` | `~/.fusion-security/fusion_security.db` | SQLite 文件路径（单机） |
| `FUSION_CORS_ORIGINS` | `localhost:3000,8080` | 允许的 CORS 来源（逗号分隔；`*` 被拒 — 带凭据时非法） |
| `FUSION_RATE_LIMIT` | `1` | 设为 `0` 关闭限流中间件（如测试 / 单机离线）。生产默认开启。 |
| `FUSION_RATE_LIMIT_PER_MINUTE` | `120` | 每 60 秒滑动窗口最大请求数，桶 key 为 `(client_ip, sha256(api_key))`。超限返回 `429` 并带 `Retry-After`。 |
| `FUSION_MAX_CONCURRENT_SCANS` | `4` | 每租户并发活跃扫描上限（running/queued/pending）。超限创建扫描返回 `409`。 |

## ✨ 已打通特性（v0.2.0rc0）

此前代码中声明但从未接通的 5 个特性现已全部接通到生产路径并**落库持久化**（重启不丢）：

| 特性 | 状态 |
|------|------|
| **自定义规则** | `CustomRuleStore` 注入 `RuleEngine`；经 `/api/v1/integrations/rules` 增删改查 |
| **反馈闭环** | `FeedbackStore.filter_vulnerabilities()` 在流水线 `_stage_triage` 运行；误报反馈落 `feedbacks` 表并抑制重复发现 |
| **多租户** | 租户身份由 fusion-identity 统一签发（`TenantMiddleware` 接入，本地 `TenantManager` 已退役）；`tenant_id` 从 API key 或 JWT 解析并 fail-closed 贯穿扫描/落库路径 |
| **扫描调度器** | `ScanScheduler.start()` 在应用启动时运行；计划落 `scheduled_scans` 表；定时/周期扫描自动派发 |
| **Webhook** | Webhook 落 `webhooks` 表（替代内存 dict）；两条扫描完成路径均触发 `WebhookNotifier` 的 `scan.completed` 事件 |

---

## 📄 开源协议

MIT License. 详情见 [LICENSE](LICENSE)。

---

<p align="center">
  <strong>Fusion-Security — 本地 AI 代码安全审计。零上传，最大隐私。</strong>
</p>
<p align="center">
  <sub>用 ❤️ 和 fusion-mlx 构建</sub>
</p>
