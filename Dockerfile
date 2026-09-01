# syntax=docker/dockerfile:1.6
# 多阶段构建:builder 安装依赖,runtime 仅拷贝产物,非 root 运行。
# git 保留(incremental scan 需要 git diff);AST/SCA 不强依赖 git 但保留以兼容 CLI --incremental。

FROM python:3.12-slim AS builder

WORKDIR /build

# fusion-core 是 in-tree 上游依赖,CI/容器内从 git 安装(见 CLAUDE.md)。
ARG FUSION_CORE_REF=main
COPY pyproject.toml README.md ./
COPY fusion_security/ fusion_security/

RUN pip install --no-cache-dir --prefix=/install \
    git+https://github.com/dahai80/fusion-core.git@${FUSION_CORE_REF} \
    . \
    && pip install --no-cache-dir --prefix=/install ".[postgres]"


FROM python:3.12-slim AS runtime

# git 仅供 incremental scan(git diff)使用,非核心依赖。
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl tini && rm -rf /var/lib/apt/lists/*

# 非 root 用户运行(S-P0:此前以 root 运行)。
RUN useradd -r -u 1000 -d /app -s /sbin/nologin fusion

WORKDIR /app

COPY --from=builder /install /usr/local
COPY fusion_security/ fusion_security/
COPY pyproject.toml README.md ./

# 数据目录由 compose/helm 挂载;确保目录存在且属主为 fusion。
RUN mkdir -p /app/data && chown -R fusion:fusion /app

USER fusion

ENV FUSION_DB_PATH=/app/data/fusion.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 11454

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD curl -f http://localhost:11454/api/v1/system/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["fusion-security", "serve", "--host", "0.0.0.0", "--port", "11454"]
