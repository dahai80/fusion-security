FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY fusion_security/ fusion_security/

RUN pip install --no-cache-dir -e .

EXPOSE 11454

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:11454/api/v1/system/health || exit 1

CMD ["fusion-security", "serve", "--host", "0.0.0.0", "--port", "11454"]
