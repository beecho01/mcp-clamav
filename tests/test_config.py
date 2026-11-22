from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from clamav_mcp.config import ConfigError, MiB, load_settings

HASH = hashlib.sha256(b"token").hexdigest()


def env(**values: str) -> dict[str, str]:
    return {f"CLAMAV_MCP_{key}": value for key, value in values.items()}


def test_defaults_are_stdio_and_loopback() -> None:
    settings = load_settings({})
    assert settings.transport == "stdio"
    assert settings.host == "127.0.0.1"
    assert settings.auth_mode == "none"
    assert settings.max_inline_bytes == 10 * MiB
    assert settings.scan_root is None


def test_http_without_auth_refuses_to_start() -> None:
    with pytest.raises(ConfigError, match="requires authentication"):
        load_settings(env(TRANSPORT="http"))


def test_http_with_explicit_auth_none_is_allowed() -> None:
    settings = load_settings(env(TRANSPORT="http", AUTH_MODE="none"))
    assert settings.auth_mode == "none"


def test_token_hashes_with_labels() -> None:
    other = hashlib.sha256(b"other").hexdigest()
    settings = load_settings(env(TRANSPORT="http", AUTH_TOKEN_HASHES=f"cursor:{HASH}, {other.upper()}"))
    assert settings.auth_mode == "token"
    assert settings.token_hashes == {bytes.fromhex(HASH): "cursor", bytes.fromhex(other): "token-2"}


def test_token_hashes_file(tmp_path: Path) -> None:
    hashes = tmp_path / "hashes"
    hashes.write_text(f"# comment\nlaptop:{HASH}  # trailing comment\n\n", encoding="utf-8")
    settings = load_settings(env(TRANSPORT="http", AUTH_TOKEN_HASHES_FILE=str(hashes)))
    assert settings.token_hashes == {bytes.fromhex(HASH): "laptop"}


@pytest.mark.parametrize("value", ["not-a-hash", "abc", f"bad label:{HASH}", f"{HASH},{HASH}"])
def test_bad_token_hashes_rejected(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env(TRANSPORT="http", AUTH_TOKEN_HASHES=value))


def test_stdio_ignores_http_auth_settings() -> None:
    settings = load_settings(env(AUTH_TOKEN_HASHES=HASH))
    assert settings.auth_mode == "none"
    assert settings.token_hashes == {}


def _oauth_env(**overrides: str) -> dict[str, str]:
    values = {
        "TRANSPORT": "http",
        "OAUTH_ISSUER": "https://auth.example.com/realms/main",
        "OAUTH_JWKS_URL": "https://auth.example.com/realms/main/certs",
        "OAUTH_RESOURCE_URL": "https://mcp.example.com/mcp",
    }
    values.update(overrides)
    return env(**values)


def test_oauth_settings() -> None:
    settings = load_settings(_oauth_env())
    assert settings.auth_mode == "oauth"
    assert settings.oauth is not None
    assert settings.oauth.required_scopes == ("clamav:scan",)
    assert settings.oauth.algorithms == ("RS256", "ES256")


def test_oauth_requires_https() -> None:
    with pytest.raises(ConfigError, match="https"):
        load_settings(_oauth_env(OAUTH_JWKS_URL="http://auth.example.com/certs"))


def test_oauth_allows_http_on_loopback() -> None:
    settings = load_settings(_oauth_env(OAUTH_RESOURCE_URL="http://localhost:8000/mcp"))
    assert settings.oauth is not None


@pytest.mark.parametrize("alg", ["HS256", "none"])
def test_oauth_rejects_symmetric_and_none_algorithms(alg: str) -> None:
    with pytest.raises(ConfigError, match="unsupported"):
        load_settings(_oauth_env(OAUTH_ALGORITHMS=alg))


def test_oauth_missing_values() -> None:
    with pytest.raises(ConfigError, match="OAUTH_JWKS_URL"):
        load_settings(env(TRANSPORT="http", OAUTH_ISSUER="https://auth.example.com"))


@pytest.mark.parametrize(
    ("raw", "expected"), [("1048576", MiB), ("512K", 512 * 1024), ("20M", 20 * MiB), ("1MiB", MiB)]
)
def test_size_parsing(raw: str, expected: int) -> None:
    assert load_settings(env(MAX_INLINE_BYTES=raw)).max_inline_bytes == expected


@pytest.mark.parametrize("raw", ["0", "-1", "lots", "65M"])
def test_size_parsing_rejects_bad_values(raw: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env(MAX_INLINE_BYTES=raw))


def test_wildcard_origin_rejected() -> None:
    with pytest.raises(ConfigError, match="Wildcard"):
        load_settings(env(ALLOWED_ORIGINS="*"))


def test_scan_root_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        load_settings(env(SCAN_ROOT=str(tmp_path / "missing")))
    settings = load_settings(env(SCAN_ROOT=str(tmp_path)))
    assert settings.scan_root == tmp_path.resolve()


def test_scan_root_cannot_be_filesystem_root() -> None:
    with pytest.raises(ConfigError, match="filesystem root"):
        load_settings(env(SCAN_ROOT=Path.cwd().anchor))


def test_http_body_limit_covers_base64_payload() -> None:
    settings = load_settings({})
    assert settings.max_http_body_bytes > settings.max_inline_base64_chars > settings.max_inline_bytes * 4 // 3
