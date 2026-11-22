# Security model

This document describes what clamav-mcp protects against, how, and what it leaves to you.
It maps each control to the [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
(and its [security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices))
and to the attack classes collected in [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security).

## What the server is

A small, read-only MCP server with at most three tools:

| Tool | Effect |
| --- | --- |
| `scan_file` | Streams caller-supplied bytes (base64) to clamd and returns a verdict. |
| `scan_path` | Optional. Streams one file from an operator-chosen, read-only directory to clamd. |
| `get_scanner_info` | Reports clamd reachability, engine/signature versions and limits. |

Nothing is written to disk, nothing is executed, and the scanned content is never returned.

## Trust boundaries

```
 MCP client / LLM ──HTTP(S) + bearer token──▶ mcp container ── internal network──▶ clamav container ──▶ signature mirror
   (untrusted input)          edge network     (uid 10001,          "scan"             (uid 1000,        egress network
                                            read-only rootfs)    no internet)      read-only rootfs)    (freshclam only)
```

* **Everything arriving from the client is untrusted**: tool arguments, filenames, paths, file bytes, headers.
* **The LLM is untrusted as a source of intent**: it may have been prompt-injected elsewhere.
* **clamd output is semi-trusted**: signature names come from signature databases, so they are sanitised too.
* **The file being scanned is hostile by definition** and is only ever handled as opaque bytes.

## Controls

### Protocol and transport (MCP 2026-07-28)

| Requirement | How it is met |
| --- | --- |
| Servers MUST validate `Origin` to prevent DNS rebinding; invalid → 403 | Always on, including in containers where the server binds 0.0.0.0. Unlisted `Origin` → 403, unlisted `Host` → 421. Configure with `CLAMAV_MCP_ALLOWED_ORIGINS` / `_HOSTS`; wildcards are refused. |
| SHOULD bind to localhost when running locally | Default bind is `127.0.0.1`; compose publishes the port on `127.0.0.1` only. |
| SHOULD authenticate all connections | HTTP refuses to start without auth unless `CLAMAV_MCP_AUTH_MODE=none` is set explicitly. Auth is deny-by-default for every path except `/healthz` and `/readyz`. |
| Stateless protocol; no `Mcp-Session-Id`; GET/DELETE → 405 | Built on the official Python SDK 2.x (implements 2026-07-28: per-request `_meta`, `server/discover`, `resultType`). Legacy clients (2025-xx) are served statelessly too, so no session IDs are ever minted and there is no session to hijack. Non-POST requests to `/mcp` get 405. |
| `Mcp-Method` / `Mcp-Name` header ↔ body validation (`HeaderMismatch`, -32020) | Enforced by the SDK; covered by tests. |
| Tools: servers MUST validate inputs, implement access controls, rate-limit, sanitise outputs | See the sections below. |
| Deterministic `tools/list` | The tool list is fixed at start-up, in a fixed order, and never changes (`listChanged: false`, no `subscriptions/listen`). |
| Stdio: log to stderr only | All logging goes to stderr; stdout carries only JSON-RPC. HTTP auth settings are ignored on stdio, as the spec directs. |

### Authorization (OAuth 2.1 resource-server mode)

| Best practice | How it is met |
| --- | --- |
| MUST NOT accept tokens not issued for this server (audience) | JWT `aud` must equal `CLAMAV_MCP_OAUTH_RESOURCE_URL` (RFC 8707 / RFC 9068); the SDK re-checks the resource. |
| Token passthrough is forbidden | Tokens are never forwarded anywhere; the server calls no downstream APIs. |
| Protected Resource Metadata (RFC 9728) and `WWW-Authenticate` discovery | Served by the SDK at `/.well-known/oauth-protected-resource/mcp`; 401s carry `resource_metadata`. |
| Scope minimisation | One narrow scope (`clamav:scan` by default) is required and advertised. |
| Signature/algorithm safety | Asymmetric algorithms only (`HS*` and `none` cannot be configured); issuer, expiry and signature are verified; keys come from the configured JWKS over HTTPS. |
| Don't let forged tokens amplify traffic | JWKS is cached; an unknown `kid` triggers at most one refetch per 30 s. |
| SSRF from metadata URLs | Not applicable server-side: the only outbound URL (JWKS) is operator-configured and must be HTTPS (HTTP only on loopback). |

Static-token mode stores only SHA-256 hashes of 256-bit random tokens (`gen-token`), compares in constant
time, and never keeps or logs the raw token. Audit logs show the token's label, not the token.

### Attack classes from awesome-mcp-security

| Attack class | Mitigation here |
| --- | --- |
| **Tool poisoning / line jumping** (malicious instructions hidden in tool metadata that act before a tool is called) | Descriptions are short, factual and static, and contain no instructions to the model. Annotations are truthful: `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: false`. |
| **Rug pulls** (tool definitions change after approval) | The tool set is fixed at process start and never changes at runtime. Dependencies are hash-pinned in `uv.lock`, base images are digest-pinned, so a rebuild cannot silently pull different code. |
| **Output poisoning / indirect prompt injection** ("no output from your MCP server is safe") | File content is never echoed. Every string returned (filename label, path, signature names) is NFC-normalised and stripped of control, format, bidi-override and zero-width characters, collapsed to one line, and length-capped. Signature names are further limited to ClamAV's character set. Results are structured (`outputSchema` + `structuredContent`). |
| **Deceptive ANSI terminal codes** | CSI/OSC escape sequences and all C0/C1 controls are removed from output and from text-format logs. JSON logs escape them. |
| **Command injection / chained-command bypass** | No subprocess, no shell, no `clamscan` invocation. Bytes are streamed over the clamd socket protocol (`INSTREAM`). |
| **Path traversal / arbitrary file read** | `scan_path` is off unless an operator mounts a directory. Paths are resolved (symlinks included) and must stay inside the scan root; the final open uses `O_NOFOLLOW` and the type check runs on the opened descriptor (`fstat`, regular files only) to avoid TOCTOU races. The mount is read-only. Errors are uniform, so they don't reveal what exists outside the root. |
| **Data exfiltration / toxic flows** (one tool reads secrets, another sends them out) | The server holds no secrets worth stealing, exposes no outbound or write tools, and the scanner network has no internet access. Scanned content is never stored, logged or returned (only its SHA-256). |
| **Insecure credential storage** | Token hashes only; the OAuth mode keeps no credentials at all. Tokens are not accepted from tool arguments, so they never pass through the model context. |
| **Conversation / data harvesting** | The server receives only what a tool call sends; it requests nothing else (no sampling, no elicitation, no roots). |
| **Denial of service** | Size caps on inline (default 10 MiB) and path (100 MiB) scans, checked before allocation; HTTP body cap derived from them; per-principal token-bucket rate limit; global concurrency cap with bounded queue wait; scan and connect timeouts; uvicorn connection cap; container memory, CPU and PID limits; clamd `StreamMaxLength`, `MaxScanSize`, `MaxRecursion` and `MaxFiles` limits. |
| **False "clean" on evasive files** (zip bombs, oversized archives) | clamd runs with `AlertExceedsMax yes`; files that hit scan limits are reported as **inconclusive**, never clean. |
| **Information leakage in errors** | Clients get short, generic messages ("the ClamAV daemon is unavailable"). Hostnames, socket paths and daemon error text go only to server logs. |

### Container and supply chain

* **MCP image**: multi-stage build; runtime has no compiler, no `pip`, no shell user; runs as uid 10001; `PYTHONSAFEPATH`.
* **Both containers**: read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, memory and PID limits, `noexec,nosuid,nodev` tmpfs.
* **clamd** runs as the unprivileged `clamav` user from the start, rather than as root dropping privileges.
* **Networks**: the clamd port is never published; `scan` is an internal network (no egress); only the ClamAV container can reach the signature mirror.
* **Pinned inputs**: `uv.lock` with hashes, base images by digest (`Dockerfile`), GitHub Actions by commit SHA, all kept current by Dependabot. The `.dockerignore` allowlist keeps secrets and VCS data out of the build context.
* **Published images** (`ghcr.io/beecho01/mcp-clamav`) are built only by CI after the tests pass, and carry an SBOM and signed SLSA build provenance (`gh attestation verify`).

### Audit logging

One JSON line per scan on stderr (`logger: clamav_mcp.audit`): principal (token label or OAuth client/subject), source, sanitised name, size, SHA-256, verdict, signatures and duration. Rejections (rate limit, busy, timeout, unavailable) are logged too. No file content and no tokens are logged.

## Residual risks and your responsibilities

* **A clean verdict is not proof of safety.** ClamAV detects known signatures and some heuristics. Treat results as one signal.
* **Inline content passes through the model provider.** With `scan_file`, the LLM produces the base64, so the file has already been seen by the model and its provider. Use `scan_path` for sensitive files.
* **clamd parses hostile input.** A ClamAV parser bug could compromise the ClamAV container. It is isolated (non-root, read-only, no capabilities, and no access to the MCP server's configuration), but it keeps internet egress for signature updates. Keep the image current (`docker compose pull`).
* **No TLS built in.** The server listens on plain HTTP bound to loopback. To reach it from other machines, put a TLS-terminating reverse proxy in front, add its hostname to `CLAMAV_MCP_ALLOWED_HOSTS`, and set `CLAMAV_MCP_FORWARDED_ALLOW_IPS` to the proxy's address.
* **No failed-authentication throttling.** Tokens carry 256 bits of entropy, so guessing isn't feasible. Put a proxy or WAF in front if you expose the port beyond loopback.
* **The human in the loop is the client's job.** Hosts should show tool calls and allow users to deny them, as the spec recommends.

## Reporting a vulnerability

Please report security issues privately through GitHub's [private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository rather than in a public issue.