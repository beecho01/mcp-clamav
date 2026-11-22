# syntax=docker/dockerfile:1.7
#
# clamav-mcp: MCP server image. The ClamAV engine itself runs in the official
# clamav/clamav-debian image (see compose.yaml); this image only talks to clamd over TCP.
#
# Published to ghcr.io/beecho01/mcp-clamav by .github/workflows/docker-publish.yml.
#
# Base images are pinned by (multi-arch index) digest for reproducible, tamper-evident builds.
# Dependabot (.github/dependabot.yml) proposes updates; keep the FROM lines literal so it can parse them.

FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS python

# ---- build: resolve exactly what uv.lock pins (hash-checked) into a venv -------------------------
FROM python AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src

# Dependencies first (better layer caching), then the project itself.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# ---- runtime: no build tools, no pip, non-root ----------------------------------------------------
FROM python AS runtime

LABEL org.opencontainers.image.title="clamav-mcp" \
      org.opencontainers.image.description="Hardened MCP server that scans files for malware with ClamAV" \
      org.opencontainers.image.licenses="Apache-2.0"

# Nothing installs packages at runtime, so remove pip; create an unprivileged user with no shell or home.
RUN python -m pip uninstall --yes --root-user-action=ignore pip \
 && groupadd --system --gid 10001 mcp \
 && useradd --system --uid 10001 --gid mcp --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mcp

COPY --from=builder /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONSAFEPATH=1 \
    CLAMAV_MCP_HOST=0.0.0.0 \
    CLAMAV_MCP_PORT=8000 \
    CLAMAV_MCP_CLAMD_HOST=clamav

USER 10001:10001
WORKDIR /
EXPOSE 8000

ENTRYPOINT ["clamav-mcp"]
# HTTP by default; it refuses to start until authentication is configured.
# For stdio: docker run -i --rm ... mcp-clamav serve --transport stdio
CMD ["serve", "--transport", "http"]
