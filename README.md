# ClamAV MCP

A hardened [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI assistants scan files for malware with the [ClamAV](https://www.clamav.net) engine. It ships as two locked-down containers: this server, and the official ClamAV daemon.

![Cursor ClamAV Integration](image.png)

* Implements MCP **2026-07-28** (stateless requests, `server/discover`) and still serves clients on
  2025-era protocol versions.
* Streamable HTTP with bearer-token or OAuth 2.1 authentication, or stdio.
* No shell, no subprocess, no temp files: bytes are streamed straight to `clamd`.
* Read-only tools with structured results, sanitised output, and rate, size and time limits.

See [SECURITY.md](SECURITY.md) for the threat model and how each control maps to the MCP spec and to [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security).

## How it fits together

```
 Cursor / Claude / VS Code
 POST /mcp  (Authorization: Bearer …)
            │  
            ▼
 ┌─────────────────────┐      internal "scan" network     ┌───────────────────────┐   egress    ┌───────────────┐
 │ mcp  (clamav-mcp)   │ ──────── clamd INSTREAM ───────▶ │ clamav (clamd +       │ ──────────▶ │ ClamAV        │
 │ 127.0.0.1:8000 only │           (no internet)          │ freshclam), port 3310 │             │ signature CDN │
 └─────────────────────┘                                  │ never published       │             └───────────────┘
                                                          └───────────────────────┘
```

## Quick start (Docker Compose)

Requires Docker with Compose v2. The first start downloads about 300 MB of signatures and needs about
1–2 GB of RAM for clamd.

```bash
# 1. Create a bearer token. The token goes to your MCP client; only its hash goes on the server.
docker compose run --rm --no-deps mcp gen-token --label my-laptop

# 2. Put the printed hash in .env
cp .env.example .env
#    CLAMAV_MCP_AUTH_TOKEN_HASHES=my-laptop:3f2a…

# 3. Start. The MCP server waits until clamd is healthy.
docker compose up -d     # pulls ghcr.io/beecho01/mcp-clamav; use `up -d --build` to build from source
docker compose ps        # both services should become "healthy"
```

The server now listens on `http://127.0.0.1:8000/mcp` (loopback only).

Check the whole chain with a real EICAR test scan:

```bash
MCP_TOKEN=cmcp_… uv run scripts/smoke_test.py
```

### Connect a client

Replace `<token>` with the `cmcp_…` token from step 1, and keep it out of version control.

**Claude Code**

```bash
claude mcp add --transport http clamav http://127.0.0.1:8000/mcp --header "Authorization: Bearer <token>"
```

**Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "clamav": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`). VS Code prompts for the token and stores it securely:

```json
{
  "inputs": [
    { "type": "promptString", "id": "clamav-token", "description": "ClamAV MCP token", "password": true }
  ],
  "servers": {
    "clamav": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer ${input:clamav-token}" }
    }
  }
}
```

### Stdio through Docker (Claude Desktop and other local clients)

With stdio the client launches the server itself, so no port and no token are needed (the MCP spec's
recommended model for local servers). Start clamd once (`docker compose up -d clamav`), then configure the
client to run a throwaway, locked-down container on the internal scan network:

```json
{
  "mcpServers": {
    "clamav": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--init",
        "--network", "mcp-clamav_scan",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--memory", "512m", "--pids-limit", "128",
        "-e", "CLAMAV_MCP_CLAMD_HOST=clamav",
        "ghcr.io/beecho01/mcp-clamav:latest", "serve", "--transport", "stdio"
      ]
    }
  }
}
```

That network has no internet access, so the stdio container can reach clamd and nothing else.

## Tools

| Tool | Arguments | What it does |
| --- | --- | --- |
| `scan_file` | `base64_data` (required), `filename` (optional label) | Scans file content sent inline. Accepts standard or URL-safe base64, MIME line breaks, missing padding and `data:` URLs. Default limit is 10 MiB after decoding. |
| `scan_path` | `path` | Only present when a scan directory is configured (see below). Scans one file inside it. |
| `get_scanner_info` | none | Reports whether clamd is reachable, engine and signature versions, signature age and limits. |

All tools are annotated read-only and non-destructive. Results are structured (`outputSchema`), for example:

```json
{
  "verdict": "infected",
  "infected": true,
  "signatures": ["Eicar-Test-Signature"],
  "source": "inline",
  "name": "eicar.com",
  "size_bytes": 68,
  "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "engine_version": "1.5.5",
  "database_version": 28191,
  "scanned_at": "2026-11-22T10:22:57.687000Z",
  "duration_ms": 6,
  "detail": "Malware detected: Eicar-Test-Signature."
}
```

`verdict` is one of:

* `clean`: no known signature matched. This does not prove the file is safe.
* `infected`: a signature matched.
* `inconclusive`: the file hit a scan limit (oversized archive, zip bomb and so on), so it was not fully
  inspected. Treat it as untrusted.

Errors (bad base64, too large, rate limited, clamd down) come back as tool errors with a short message the
model can act on.

### Scanning a host directory (optional)

Sending big files through an LLM as base64 is slow and costly, and the file passes through the model
provider. Instead you can share one directory, read-only, and let the model scan files by path:

```bash
SCAN_DIR=/home/me/Downloads docker compose -f compose.yaml -f compose.scan-dir.yaml up -d
```

Paths are relative to that directory, for example `invoices/march.pdf`. Anything that resolves outside it,
including through symlinks, is refused. The container runs as uid 10001, so the files must be readable by
that user. Alternatively, set `MCP_UID`/`MCP_GID` to your own IDs.

## Authentication

HTTP always requires authentication. The server refuses to start without it unless you set
`CLAMAV_MCP_AUTH_MODE=none`, which is only appropriate for a trusted, loopback-only setup.

**Bearer tokens (default).** `clamav-mcp gen-token` creates a 256-bit random token and prints its SHA-256.
Configure one or more `label:hash` entries in `CLAMAV_MCP_AUTH_TOKEN_HASHES`, or one per line in a file
named by `CLAMAV_MCP_AUTH_TOKEN_HASHES_FILE`. Labels show up in audit logs and key the rate limiter. To
revoke a token, remove its line and restart.

**OAuth 2.1 (resource-server mode).** Use this when you already have an identity provider (Keycloak, Entra
ID, Auth0, Authentik and so on). The server validates JWT access tokens locally against the provider's JWKS
and publishes [Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) at
`/.well-known/oauth-protected-resource/mcp`, so spec-compliant clients can discover where to log in.

```bash
CLAMAV_MCP_OAUTH_ISSUER=https://auth.example.com/realms/main
CLAMAV_MCP_OAUTH_JWKS_URL=https://auth.example.com/realms/main/protocol/openid-connect/certs
CLAMAV_MCP_OAUTH_RESOURCE_URL=https://mcp.example.com/mcp    # tokens must carry this as "aud"
CLAMAV_MCP_OAUTH_REQUIRED_SCOPES=clamav:scan
```

Configure your provider to put the resource URL in the token's `aud` claim and to grant the
`clamav:scan` scope. Tokens issued for any other audience are rejected.

## Container image

Every push to `main` publishes a multi-arch image (linux/amd64, linux/arm64) to GitHub Container Registry,
built by [.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml) after the tests pass:

| Tag | Meaning |
| --- | --- |
| `latest`, `main` | Current `main` branch |
| `1.2.3`, `1.2` | Release tags (`git tag v1.2.3 && git push --tags`) |
| `sha-<short>` | One specific commit |

```bash
docker pull ghcr.io/beecho01/mcp-clamav:latest
```

Pin a release tag (or a digest) for deployments, for example `MCP_IMAGE=ghcr.io/beecho01/mcp-clamav:1.0.0` in
`.env`. Each image carries an SBOM and signed SLSA build provenance, which you can check with the GitHub CLI:

```bash
gh attestation verify oci://ghcr.io/beecho01/mcp-clamav:latest --owner beecho01
```

## Exposing it beyond localhost

The compose file binds `127.0.0.1` only. To use the server from other machines:

1. Put a TLS-terminating reverse proxy in front (Caddy, Traefik, nginx).
2. Add the public hostname to `CLAMAV_MCP_ALLOWED_HOSTS` (and its origin to `CLAMAV_MCP_ALLOWED_ORIGINS` if
   browsers are involved). Otherwise the DNS-rebinding protection rejects requests with 421 or 403.
3. Set `CLAMAV_MCP_FORWARDED_ALLOW_IPS` to the proxy's address so client IPs in logs are correct.
4. Prefer OAuth mode, or at least one token per client so each can be revoked on its own.

## Configuration

All settings are environment variables prefixed with `CLAMAV_MCP_`. Invalid values stop the server at
startup with a clear message.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRANSPORT` | `stdio` (`http` in compose) | `stdio` or `http`. Also `serve --transport`. |
| `HOST` / `PORT` | `127.0.0.1` / `8000` (`0.0.0.0` in the image) | HTTP bind address. |
| `HTTP_PATH` | `/mcp` | MCP endpoint path. |
| `ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*,[::1]:*` | Accepted `Host` headers (`:*` = any port). |
| `ALLOWED_ORIGINS` | `http://127.0.0.1:*,http://localhost:*,http://[::1]:*` | Accepted `Origin` headers. Requests without `Origin` are allowed. |
| `HTTP_MAX_CONNECTIONS` | `64` | Concurrent HTTP connections before 503. |
| `FORWARDED_ALLOW_IPS` | unset | Trust `X-Forwarded-*` from these proxy IPs. |
| `CLAMD_HOST` / `CLAMD_PORT` | `127.0.0.1` / `3310` (`clamav` in the image) | clamd TCP endpoint. |
| `CLAMD_SOCKET` | unset | clamd Unix socket (instead of TCP). |
| `CLAMD_CONNECT_TIMEOUT` | `5` | Seconds. |
| `SCAN_TIMEOUT` | `120` | Seconds per scan. |
| `MAX_INLINE_BYTES` | `10M` | `scan_file` limit after decoding (at most `64M`). |
| `MAX_FILE_BYTES` | `100M` | `scan_path` limit. Keep it at or below clamd's `StreamMaxLength`. |
| `SCAN_ROOT` | unset | Directory for `scan_path`. The tool exists only when this is set. |
| `MAX_CONCURRENT_SCANS` | `4` | Scans in flight at once. |
| `QUEUE_TIMEOUT` | `15` | Seconds a scan waits for a free slot before "busy". |
| `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_BURST` | `30` / `10` | Per-principal token bucket (all tools). |
| `AUTH_MODE` | auto | `token`, `oauth` or `none`. Inferred from the settings below. |
| `AUTH_TOKEN_HASHES` | unset | `label:sha256hex` entries, comma-separated. |
| `AUTH_TOKEN_HASHES_FILE` | unset | File with one entry per line (`#` comments allowed). |
| `OAUTH_ISSUER` / `OAUTH_JWKS_URL` / `OAUTH_RESOURCE_URL` | unset | OAuth resource-server mode (HTTPS required, except loopback). |
| `OAUTH_REQUIRED_SCOPES` | `clamav:scan` | Comma-separated scopes every token must carry. |
| `OAUTH_ALGORITHMS` | `RS256,ES256` | Accepted JWT algorithms (asymmetric only). |
| `OAUTH_LEEWAY_SECONDS` | `30` | Clock-skew allowance. |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `json` | Logs go to stderr; one JSON audit line per scan. |

clamd itself is configured in [docker/clamav/clamd.conf](docker/clamav/clamd.conf) (scan limits,
`AlertExceedsMax`, timeouts) and [docker/clamav/freshclam.conf](docker/clamav/freshclam.conf).

## Running without Docker

You need a reachable clamd (`apt install clamav-daemon`, `brew install clamav`, …) and
[uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run clamav-mcp check                         # is clamd reachable?
uv run clamav-mcp serve --transport stdio       # for a local client
```

## Development

```bash
uv sync                 # installs dev tools too
uv run pytest           # unit + in-process HTTP tests against a fake clamd
uv run ruff check . && uv run ruff format --check .
```

The tests never write the EICAR string to disk, so desktop antivirus won't quarantine files mid-run.
To check a real deployment, run `scripts/smoke_test.py` as shown above.

Dependencies are locked in `uv.lock`. After changing `pyproject.toml`, run `uv lock`. Base images are pinned
by digest in the `Dockerfile`; update them deliberately, for example with Renovate or Dependabot.

## Upgrading from 0.1

* The single `main.py` is replaced by the `clamav_mcp` package (`clamav-mcp` command).
* The deprecated SSE transport (`/sse`) is gone. Point clients at `http://127.0.0.1:8000/mcp` and send a
  bearer token.
* `scan_file` keeps its `base64_data` and `filename` arguments. Results are now structured (`verdict`,
  `signatures`, `sha256`, …) instead of raw `clamscan` text plus `success`.
* ClamAV runs as a separate daemon container instead of `clamscan` per request. That is much faster, because
  signatures load once rather than on every scan.
