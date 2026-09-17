FROM ghcr.io/astral-sh/uv:0.12.6@sha256:88bc6eb1ccd4b82efd0e1b530caffabddf50dc2bf612e66c14ea25b8ee8a4d3d AS uv
FROM python:3.13.15-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f AS certificates
FROM ubuntu:24.04@sha256:69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9

COPY --from=uv /uv /usr/local/bin/uv
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    UV_SYSTEM_CERTS=true \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis

RUN uv python install 3.13.15
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY configs ./configs
COPY rules ./rules
COPY schemas ./schemas
COPY tests ./tests
COPY test_cases ./test_cases
RUN uv sync --frozen --all-groups --python 3.13.15

USER 65534:65534
CMD ["/app/.venv/bin/python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
