# syntax=docker/dockerfile:1.6
# 多阶段构建:builder 安装依赖,runtime 仅拷贝产物,非 root 运行。
# git 保留(incremental scan 需要 git diff);AST/SCA 不强依赖 git 但保留以兼容 CLI --incremental。

FROM python:3.12-slim AS builder

WORKDIR /build

# builder 需要 git:fusion-core 从 git+https 安装,pip 依赖 git clone。
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# fusion-core 是 in-tree 上游依赖,CI/容器内从 git 安装(见 CLAUDE.md)。
# 用 builder venv 而非 --prefix:fusion-security 依赖 fusion-core,--prefix 隔离
# 会让后续 pip 解析看不到刚装的 fusion-core(报 No matching distribution)。
ARG FUSION_CORE_REF=master
COPY pyproject.toml README.md ./
COPY fusion_security/ fusion_security/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir \
        git+https://github.com/dahai80/fusion-core.git@${FUSION_CORE_REF} \
        ".[postgres]"


FROM python:3.12-slim AS runtime

# git 仅供 incremental scan(git diff)使用,非核心依赖。
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl tini && rm -rf /var/lib/apt/lists/*

# 非 root 用户运行(S-P0:此前以 root 运行)。
RUN useradd -r -u 1000 -d /app -s /sbin/nologin fusion

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY fusion_security/ fusion_security/
COPY pyproject.toml README.md ./

# 数据目录由 compose/helm 挂载;确保目录存在且属主为 fusion。
RUN mkdir -p /app/data && chown -R fusion:fusion /app

USER fusion

ENV FUSION_DB_PATH=/app/data/fusion.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH

EXPOSE 11454

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD curl -f http://localhost:11454/api/v1/system/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["fusion-security", "serve", "--host", "0.0.0.0", "--port", "11454"]
