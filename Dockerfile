# syntax=docker/dockerfile:1
# Swordholder 0.7.1 —— 最小可运行镜像：只要 Python，不需要本机环境
# 用法：
#   docker build -t swordholder:0.7.1 .
#   docker run --rm swordholder:0.7.1 --help
#   docker run --rm -v "$PWD:/work" swordholder:0.7.1 keygen --out /work/keys
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

LABEL org.opencontainers.image.title="swordholder" \
      org.opencontainers.image.description="给 AI 结论盖章：告警分诊结论封成可离线独立验签的 ed25519 凭证" \
      org.opencontainers.image.version="0.7.1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/mzymazy/swordholder"

WORKDIR /src

# 只拷贝打包所需文件：契约 JSON / 策略 YAML / 样例都在这些目录里
COPY pyproject.toml README.md LICENSE ./
COPY swordholder ./swordholder
COPY mcp_server ./mcp_server

RUN pip install . && rm -rf /src

# 不以 root 运行（镜像内任何写盘都落在 /work）
RUN useradd --create-home --uid 10001 sword
USER sword
WORKDIR /work

ENTRYPOINT ["swordholder"]
CMD ["--help"]
