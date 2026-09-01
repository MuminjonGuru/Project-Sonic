FROM python:3.13.15-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f

ARG UV_VERSION=0.12.6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN python -m pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY configs ./configs
COPY rules ./rules
COPY schemas ./schemas
COPY src ./src

RUN uv sync --frozen --no-dev

ENTRYPOINT ["/app/.venv/bin/agentsec-evidence"]
