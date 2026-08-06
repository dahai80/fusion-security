# Fusion-Security Helm Chart

部署 Fusion-Security 到 Kubernetes 集群。

## 快速开始

```bash
helm install fusion-security ./deploy/helm/fusion-security
```

## 配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `replicaCount` | `1` | 副本数 |
| `image.repository` | `fusion-security` | 镜像名 |
| `image.tag` | `0.1.0` | 镜像标签 |
| `service.type` | `ClusterIP` | Service 类型 |
| `service.port` | `11454` | Service 端口 |
| `ingress.enabled` | `false` | 启用 Ingress |
| `persistence.enabled` | `true` | 启用持久化 |
| `persistence.size` | `5Gi` | 存储大小 |
| `fusionMLX.enabled` | `true` | 部署 MLX 后端 |
| `fusionMLX.persistence.size` | `20Gi` | 模型存储大小 |
| `config.logLevel` | `INFO` | 日志级别 |
| `config.severityThreshold` | `low` | 最低严重级别 |
| `config.enableAI` | `true` | 启用 AI 分析 |
| `autoscaling.enabled` | `false` | 启用 HPA |

## 示例

```bash
helm install fusion-security ./deploy/helm/fusion-security \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=security.example.com

helm install fusion-security ./deploy/helm/fusion-security \
  --set config.enableAI=false \
  --set fusionMLX.enabled=false

helm install fusion-security ./deploy/helm/fusion-security \
  --set resources.limits.cpu=4000m \
  --set resources.limits.memory=4Gi
```
