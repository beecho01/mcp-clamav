"""Runtime configuration, read from ``CLAMAV_MCP_*`` environment variables.

Every setting is validated at startup and the server refuses to start on an
unsafe or ambiguous combination (fail closed), for example an HTTP listener
with no authentication configured.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

ENV_PREFIX = "CLAMAV_MCP_"

MiB = 1024 * 1024

Transport = Literal["stdio", "http"]
AuthMode = Literal["none", "token", "oauth"]
LogFormat = Literal["json", "text"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Asymmetric algorithms only: symmetric (HS*) keys and "none" are never accepted.
ALLOWED_JWT_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)

_TOKEN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_HTTP_PATH_RE = re.compile(r"^/[A-Za-z0-9/_-]{0,63}$")
_SCOPE_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")  # RFC 6749 scope-token


class ConfigError(ValueError):
    """Raised when the configuration is invalid or unsafe."""


@dataclass(frozen=True, slots=True)
class OAuthSettings:
    issuer: str
    jwks_url: str
    resource_url: str
    required_scopes: tuple[str, ...]
    algorithms: tuple[str, ...]
    leeway_seconds: int


@dataclass(frozen=True, slots=True)
class Settings:
    transport: Transport = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    http_path: str = "/mcp"
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:*", "localhost:*", "[::1]:*")
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*")
    http_max_connections: int = 64
    forwarded_allow_ips: str | None = None

    clamd_host: str | None = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str | None = None
    clamd_connect_timeout: float = 5.0
    scan_timeout: float = 120.0

    max_inline_bytes: int = 10 * MiB
    max_file_bytes: int = 100 * MiB
    scan_root: Path | None = None

    max_concurrent_scans: int = 4
    queue_timeout: float = 15.0
    rate_limit_per_minute: int = 30
    rate_limit_burst: int = 10

    auth_mode: AuthMode = "none"
    # sha256(token) -> label. Only hashes are held, so a leaked config does not leak tokens.
    token_hashes: Mapping[bytes, str] = field(default_factory=dict)
    oauth: OAuthSettings | None = None

    log_level: LogLevel = "INFO"
    log_format: LogFormat = "json"

    @property
    def _max_base64_len(self) -> int:
        return -(-self.max_inline_bytes // 3) * 4

    @property
    def max_inline_base64_chars(self) -> int:
        """Longest accepted ``base64_data`` argument: room for MIME line breaks and a data: URL prefix."""
        b64 = self._max_base64_len
        return b64 + b64 // 38 + 256

    @property
    def max_http_body_bytes(self) -> int:
        """Largest JSON-RPC body accepted over HTTP: the base64 argument (with escaped line breaks) plus headroom."""
        b64 = self._max_base64_len
        return b64 + b64 // 19 + 64 * 1024


def _get(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(ENV_PREFIX + name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _parse_int(env: Mapping[str, str], name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = _get(env, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{ENV_PREFIX}{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{ENV_PREFIX}{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _parse_float(env: Mapping[str, str], name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = _get(env, name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{ENV_PREFIX}{name} must be a number, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{ENV_PREFIX}{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _parse_list(env: Mapping[str, str], name: str) -> tuple[str, ...] | None:
    raw = _get(env, name)
    if raw is None:
        return None
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _parse_choice(env: Mapping[str, str], name: str, choices: tuple[str, ...], default: str) -> str:
    raw = _get(env, name)
    if raw is None:
        return default
    value = raw.lower() if choices[0].islower() else raw.upper()
    if value not in choices:
        raise ConfigError(f"{ENV_PREFIX}{name} must be one of {', '.join(choices)}, got {raw!r}")
    return value


def _parse_size(env: Mapping[str, str], name: str, default: int, *, maximum: int) -> int:
    """Parse a byte size such as ``10485760``, ``512K``, ``10M`` or ``1G``."""
    raw = _get(env, name)
    if raw is None:
        return default
    match = re.fullmatch(r"(\d+)\s*([KMG]?)(?:i?B)?", raw, flags=re.IGNORECASE)
    if not match:
        raise ConfigError(f"{ENV_PREFIX}{name} must be a size like 10M or 1048576, got {raw!r}")
    multiplier = {"": 1, "K": 1024, "M": MiB, "G": 1024 * MiB}[match.group(2).upper()]
    value = int(match.group(1)) * multiplier
    if not 1 <= value <= maximum:
        raise ConfigError(f"{ENV_PREFIX}{name} must be between 1 byte and {maximum} bytes, got {value}")
    return value


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _require_secure_url(name: str, url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError(f"{ENV_PREFIX}{name} must be an absolute http(s) URL, got {url!r}")
    if parts.scheme == "http" and not _is_loopback_host(parts.hostname):
        raise ConfigError(f"{ENV_PREFIX}{name} must use https (http is only allowed for loopback), got {url!r}")
    if parts.username or parts.password:
        raise ConfigError(f"{ENV_PREFIX}{name} must not embed credentials")
    if parts.fragment:
        raise ConfigError(f"{ENV_PREFIX}{name} must not contain a fragment")
    return url


def _parse_token_hashes(env: Mapping[str, str]) -> dict[bytes, str]:
    entries: list[str] = list(_parse_list(env, "AUTH_TOKEN_HASHES") or ())
    hashes_file = _get(env, "AUTH_TOKEN_HASHES_FILE")
    if hashes_file:
        try:
            text = Path(hashes_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"Cannot read {ENV_PREFIX}AUTH_TOKEN_HASHES_FILE: {exc.strerror}") from exc
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            entries.extend(part.strip() for part in line.split(",") if part.strip())

    result: dict[bytes, str] = {}
    for index, entry in enumerate(entries, start=1):
        label, sep, digest = entry.rpartition(":")
        if not sep:
            label, digest = f"token-{index}", entry
        digest = digest.strip().lower()
        label = label.strip()
        if not _TOKEN_HASH_RE.fullmatch(digest):
            raise ConfigError(
                f"Token hash #{index} is not a hex SHA-256 digest. Generate tokens with `clamav-mcp gen-token`."
            )
        if not _LABEL_RE.fullmatch(label):
            raise ConfigError(f"Token label {label!r} must match {_LABEL_RE.pattern}")
        key = bytes.fromhex(digest)
        if key in result:
            raise ConfigError(f"Token hash #{index} is listed more than once")
        result[key] = label
    return result


def _parse_oauth(env: Mapping[str, str]) -> OAuthSettings:
    issuer = _get(env, "OAUTH_ISSUER")
    jwks_url = _get(env, "OAUTH_JWKS_URL")
    resource_url = _get(env, "OAUTH_RESOURCE_URL")
    missing = [
        ENV_PREFIX + name
        for name, value in (
            ("OAUTH_ISSUER", issuer),
            ("OAUTH_JWKS_URL", jwks_url),
            ("OAUTH_RESOURCE_URL", resource_url),
        )
        if value is None
    ]
    if missing:
        raise ConfigError(f"OAuth mode requires: {', '.join(missing)}")
    if not (issuer and jwks_url and resource_url):  # pragma: no cover - narrowed above
        raise ConfigError("OAuth settings incomplete")

    algorithms = _parse_list(env, "OAUTH_ALGORITHMS") or ("RS256", "ES256")
    bad = sorted(set(algorithms) - ALLOWED_JWT_ALGORITHMS)
    if bad:
        raise ConfigError(
            f"{ENV_PREFIX}OAUTH_ALGORITHMS contains unsupported values {bad}; "
            f"allowed: {', '.join(sorted(ALLOWED_JWT_ALGORITHMS))}"
        )
    scopes = _parse_list(env, "OAUTH_REQUIRED_SCOPES")
    scopes = ("clamav:scan",) if scopes is None else scopes
    for scope in scopes:
        if not _SCOPE_RE.fullmatch(scope):
            raise ConfigError(f"Invalid OAuth scope {scope!r}")

    return OAuthSettings(
        issuer=_require_secure_url("OAUTH_ISSUER", issuer),
        jwks_url=_require_secure_url("OAUTH_JWKS_URL", jwks_url),
        resource_url=_require_secure_url("OAUTH_RESOURCE_URL", resource_url),
        required_scopes=tuple(scopes),
        algorithms=tuple(algorithms),
        leeway_seconds=_parse_int(env, "OAUTH_LEEWAY_SECONDS", 30, minimum=0, maximum=300),
    )


def load_settings(
    env: Mapping[str, str] | None = None,
    *,
    transport: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> Settings:
    """Build validated settings from the environment, with optional CLI overrides."""
    env = os.environ if env is None else env

    resolved_transport = transport or _parse_choice(env, "TRANSPORT", ("stdio", "http"), "stdio")
    if resolved_transport not in ("stdio", "http"):
        raise ConfigError(f"Unknown transport {resolved_transport!r}")

    http_path = _get(env, "HTTP_PATH") or "/mcp"
    if not _HTTP_PATH_RE.fullmatch(http_path) or http_path in ("/healthz", "/readyz"):
        raise ConfigError(f"{ENV_PREFIX}HTTP_PATH must look like /mcp, got {http_path!r}")

    clamd_socket = _get(env, "CLAMD_SOCKET")
    clamd_host = None if clamd_socket else (_get(env, "CLAMD_HOST") or "127.0.0.1")

    scan_root: Path | None = None
    scan_root_raw = _get(env, "SCAN_ROOT")
    if scan_root_raw:
        try:
            scan_root = Path(scan_root_raw).resolve(strict=True)
        except OSError as exc:
            raise ConfigError(f"{ENV_PREFIX}SCAN_ROOT {scan_root_raw!r} does not exist") from exc
        if not scan_root.is_dir():
            raise ConfigError(f"{ENV_PREFIX}SCAN_ROOT {scan_root_raw!r} is not a directory")
        if scan_root == Path(scan_root.anchor):
            raise ConfigError(f"{ENV_PREFIX}SCAN_ROOT must not be the filesystem root")

    token_hashes = _parse_token_hashes(env)
    oauth_configured = _get(env, "OAUTH_ISSUER") is not None
    explicit_mode = _get(env, "AUTH_MODE")
    if explicit_mode is None:
        auth_mode = "oauth" if oauth_configured else ("token" if token_hashes else "none")
    else:
        auth_mode = _parse_choice(env, "AUTH_MODE", ("none", "token", "oauth"), "none")

    oauth: OAuthSettings | None = None
    if resolved_transport == "http":
        if auth_mode == "token" and not token_hashes:
            raise ConfigError(
                f"Token auth requires {ENV_PREFIX}AUTH_TOKEN_HASHES or {ENV_PREFIX}AUTH_TOKEN_HASHES_FILE"
            )
        if auth_mode == "oauth":
            oauth = _parse_oauth(env)
        if auth_mode == "none" and explicit_mode is None:
            raise ConfigError(
                "The HTTP transport requires authentication. Configure bearer tokens "
                f"({ENV_PREFIX}AUTH_TOKEN_HASHES, see `clamav-mcp gen-token`) or OAuth "
                f"({ENV_PREFIX}OAUTH_*). To run without authentication on a trusted loopback-only "
                f"deployment, set {ENV_PREFIX}AUTH_MODE=none explicitly."
            )
    else:
        # stdio: the client owns the process; the spec says not to use HTTP auth here.
        auth_mode = "none"
        token_hashes = {}

    allowed_hosts = _parse_list(env, "ALLOWED_HOSTS")
    allowed_origins = _parse_list(env, "ALLOWED_ORIGINS")
    for value in (*(allowed_hosts or ()), *(allowed_origins or ())):
        if value == "*" or any(ch.isspace() for ch in value):
            raise ConfigError(f"Wildcard or malformed host/origin entry {value!r} is not allowed")

    defaults = Settings()
    max_inline = _parse_size(env, "MAX_INLINE_BYTES", defaults.max_inline_bytes, maximum=64 * MiB)
    max_file = _parse_size(env, "MAX_FILE_BYTES", defaults.max_file_bytes, maximum=4096 * MiB)

    return Settings(
        transport=resolved_transport,  # type: ignore[arg-type]
        host=host or _get(env, "HOST") or defaults.host,
        port=port or _parse_int(env, "PORT", defaults.port, minimum=1, maximum=65535),
        http_path=http_path,
        allowed_hosts=allowed_hosts if allowed_hosts is not None else defaults.allowed_hosts,
        allowed_origins=allowed_origins if allowed_origins is not None else defaults.allowed_origins,
        http_max_connections=_parse_int(env, "HTTP_MAX_CONNECTIONS", 64, minimum=1, maximum=10_000),
        forwarded_allow_ips=_get(env, "FORWARDED_ALLOW_IPS"),
        clamd_host=clamd_host,
        clamd_port=_parse_int(env, "CLAMD_PORT", 3310, minimum=1, maximum=65535),
        clamd_socket=clamd_socket,
        clamd_connect_timeout=_parse_float(env, "CLAMD_CONNECT_TIMEOUT", 5.0, minimum=0.1, maximum=60),
        scan_timeout=_parse_float(env, "SCAN_TIMEOUT", 120.0, minimum=1, maximum=3600),
        max_inline_bytes=max_inline,
        max_file_bytes=max_file,
        scan_root=scan_root,
        max_concurrent_scans=_parse_int(env, "MAX_CONCURRENT_SCANS", 4, minimum=1, maximum=256),
        queue_timeout=_parse_float(env, "QUEUE_TIMEOUT", 15.0, minimum=0, maximum=600),
        rate_limit_per_minute=_parse_int(env, "RATE_LIMIT_PER_MINUTE", 30, minimum=1, maximum=100_000),
        rate_limit_burst=_parse_int(env, "RATE_LIMIT_BURST", 10, minimum=1, maximum=100_000),
        auth_mode=auth_mode,  # type: ignore[arg-type]
        token_hashes=token_hashes,
        oauth=oauth,
        log_level=_parse_choice(env, "LOG_LEVEL", ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"), "INFO"),  # type: ignore[arg-type]
        log_format=_parse_choice(env, "LOG_FORMAT", ("json", "text"), "json"),  # type: ignore[arg-type]
    )
