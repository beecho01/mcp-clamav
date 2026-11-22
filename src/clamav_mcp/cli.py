"""Command-line entry point: ``clamav-mcp [serve|gen-token|check|healthcheck]``."""

from __future__ import annotations

import argparse
import logging
import sys
import urllib.error
import urllib.request

import anyio

from clamav_mcp import __version__
from clamav_mcp.auth import generate_token
from clamav_mcp.clamd import ClamdClient
from clamav_mcp.config import ConfigError, Settings, load_settings
from clamav_mcp.logs import configure_logging

logger = logging.getLogger("clamav_mcp")


def _clamd_client(settings: Settings) -> ClamdClient:
    return ClamdClient(
        host=settings.clamd_host,
        port=settings.clamd_port,
        unix_socket=settings.clamd_socket,
        connect_timeout=settings.clamd_connect_timeout,
    )


def _serve(args: argparse.Namespace) -> int:
    try:
        settings = load_settings(transport=args.transport, host=args.host, port=args.port)
    except ConfigError as exc:
        print(f"clamav-mcp: configuration error: {exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level, settings.log_format)

    from clamav_mcp.server import build_server  # imported late so config errors print fast

    clamd = _clamd_client(settings)
    mcp = build_server(settings, clamd)
    logger.info(
        "clamav-mcp %s starting",
        __version__,
        extra={"event": {"transport": settings.transport, "clamd": clamd.endpoint}},
    )
    if settings.transport == "stdio":
        anyio.run(mcp.run_stdio_async)
    else:
        from clamav_mcp.http import run_http

        run_http(settings, mcp)
    return 0


def _gen_token(args: argparse.Namespace) -> int:
    token, digest = generate_token()
    label = args.label
    print("Give this bearer token to the MCP client (shown once, store it in a secret manager):")
    print(f"  {token}")
    print()
    print("Add this entry to CLAMAV_MCP_AUTH_TOKEN_HASHES (comma-separated) on the server:")
    print(f"  {label}:{digest}" if label else f"  {digest}")
    return 0


def _check(_: argparse.Namespace) -> int:
    try:
        settings = load_settings(transport="stdio")
    except ConfigError as exc:
        print(f"clamav-mcp: configuration error: {exc}", file=sys.stderr)
        return 2
    clamd = _clamd_client(settings)

    async def run() -> int:
        if not await clamd.ping():
            print(f"clamd at {clamd.endpoint}: unreachable", file=sys.stderr)
            return 1
        info = await clamd.version()
        print(f"clamd at {clamd.endpoint}: ClamAV {info.engine_version}, database {info.database_version}")
        return 0

    return anyio.run(run)


def _healthcheck(args: argparse.Namespace) -> int:
    """Container HEALTHCHECK without curl/wget in the image. Probes loopback only."""
    url = f"http://127.0.0.1:{args.port}{args.path}"
    try:
        with urllib.request.urlopen(url, timeout=args.timeout) as response:  # fixed loopback URL
            return 0 if response.status == 200 else 1
    except (urllib.error.URLError, OSError):
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clamav-mcp", description="ClamAV malware-scanning MCP server.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Run the MCP server (default).")
    serve.add_argument("--transport", choices=("stdio", "http"), help="Overrides CLAMAV_MCP_TRANSPORT.")
    serve.add_argument("--host", help="HTTP bind address. Overrides CLAMAV_MCP_HOST.")
    serve.add_argument("--port", type=int, help="HTTP port. Overrides CLAMAV_MCP_PORT.")
    serve.set_defaults(func=_serve)

    gen = sub.add_parser("gen-token", help="Generate a bearer token and the hash to configure on the server.")
    gen.add_argument("--label", help="Name for the token's owner, shown in audit logs (e.g. cursor-laptop).")
    gen.set_defaults(func=_gen_token)

    check = sub.add_parser("check", help="Check that clamd is reachable and print its version.")
    check.set_defaults(func=_check)

    health = sub.add_parser("healthcheck", help="Probe the local HTTP server (for container health checks).")
    health.add_argument("--port", type=int, default=8000)
    health.add_argument("--path", default="/healthz", choices=("/healthz", "/readyz"))
    health.add_argument("--timeout", type=float, default=3.0)
    health.set_defaults(func=_healthcheck)
    return parser


_COMMANDS = frozenset({"serve", "gen-token", "check", "healthcheck"})


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    # `clamav-mcp --transport http` is shorthand for `clamav-mcp serve --transport http`.
    if not args_list or (args_list[0] not in _COMMANDS and args_list[0] not in ("-h", "--help", "--version")):
        args_list.insert(0, "serve")
    args = build_parser().parse_args(args_list)
    return int(args.func(args))
