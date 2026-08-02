# 架构合规整改计划

> 审计日期: 2026-08-02
> 关联 Issue: #3
> 违规等级: P1 + P2
> 合规评级: C

## 层级定位

**五、垂直行业产品** — 安全（层级归属存疑）

## P1 违规项与整改

| # | 违规项 | 整改方案 | 截止 |
|---|--------|----------|------|
| 1 | fusion_security/engine/ai/analyzer.py 绕过 fusion-core | 改为使用 fusion_core.mlx_client.FusionMLXClient | P1-S1 |

## P2 违规项与整改

| # | 违规项 | 整改方案 | 截止 |
|---|--------|----------|------|
| 2 | 代码安全审计更接近 L4 | 重新评估层级归属，建议移至 L4 通用开发工具 | P2-S1 |
| 3 | 与 fusion-code-modelization SecurityScanner 重叠 | 合并或明确调用关系 | P2-S1 |
| 4 | tree-sitter AST 解析通用能力 | 抽取为通用模块 | P2-S2 |

## 合规标准

- 使用 fusion_core.mlx_client.FusionMLXClient
- 重新评估层级归属
- 与相关项目明确边界
