"""MCP server definition: a fixed, read-only tool set over the Scanner.

Tool names, descriptions and schemas are static and decided at startup; the
tool list never changes at runtime (no ``listChanged``), so there is nothing
for a "rug pull" to swap in later.
"""

# No `from __future__ import annotations` here: tool signatures use Annotated metadata
# built from runtime settings, which the SDK must be able to evaluate.

import logging
import time
from typing import Annotated, Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.caching import CacheHint
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import Field
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from clamav_mcp import __version__
from clamav_mcp.auth import JWTTokenVerifier
from clamav_mcp.clamd import ClamdClient
from clamav_mcp.config import Settings
from clamav_mcp.models import ScannerInfo, ScanResult
from clamav_mcp.scanner import Scanner, ScanRejectedError

logger = logging.getLogger(__name__)

SERVER_NAME = "clamav-mcp"

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


def _human_size(n: int) -> str:
    for unit, size in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= size:
            return f"{n / size:.3g} {unit}"
    return f"{n} bytes"


def _principal(settings: Settings) -> str:
    """Identity used for rate limiting and audit logs; derived from the verified token, never from arguments."""
    token = get_access_token()
    if token is None:
        return "stdio" if settings.transport == "stdio" else "anonymous"
    if not token.subject or token.subject == token.client_id:
        return token.client_id
    return f"{token.client_id}/{token.subject}"


def build_server(settings: Settings, clamd: ClamdClient, scanner: Scanner | None = None) -> MCPServer[Any]:
    scanner = scanner or Scanner(settings, clamd)

    auth: AuthSettings | None = None
    token_verifier: JWTTokenVerifier | None = None
    if settings.transport == "http" and settings.auth_mode == "oauth":
        if settings.oauth is None:
            raise ValueError("OAuth mode requires OAuth settings")
        token_verifier = JWTTokenVerifier(settings.oauth)
        auth = AuthSettings(
            issuer_url=settings.oauth.issuer,  # type: ignore[arg-type]
            resource_server_url=settings.oauth.resource_url,  # type: ignore[arg-type]
            required_scopes=list(settings.oauth.required_scopes) or None,
            validate_token_resource=True,
        )

    mcp: MCPServer[Any] = MCPServer(
        name=SERVER_NAME,
        title="ClamAV Scanner",
        description="Scans files for malware with the ClamAV engine.",
        version=__version__,
        token_verifier=token_verifier,
        auth=auth,
        log_level=settings.log_level,
        # The tool list is static and never pushed; no long-lived listen streams to hold open.
        subscriptions=False,
        cache_hints={"tools/list": CacheHint(ttl_ms=3_600_000, scope="private")},
    )

    max_inline = _human_size(settings.max_inline_bytes)

    async def scan_file(
        base64_data: Annotated[
            str,
            Field(
                description=f"The file's bytes, base64-encoded. At most {max_inline} after decoding.",
                min_length=1,
                max_length=settings.max_inline_base64_chars,
            ),
        ],
        filename: Annotated[
            str | None,
            Field(description="Optional original filename. Used only as a label in the result.", max_length=1024),
        ] = None,
    ) -> ScanResult:
        try:
            return await scanner.scan_base64(base64_data, filename, principal=_principal(settings))
        except ScanRejectedError as exc:
            raise ToolError(str(exc)) from exc

    mcp.add_tool(
        scan_file,
        name="scan_file",
        title="Scan file content",
        description=(
            f"Scan a file for malware with ClamAV. Send the file content base64-encoded (at most {max_inline} "
            "after decoding). Returns a verdict (clean, infected or inconclusive), the names of any matching "
            "signatures and the file's SHA-256. The content is scanned in memory and is never stored or returned. "
            "A clean verdict means no known signature matched; it does not prove a file is safe."
        ),
        annotations=READ_ONLY,
        structured_output=True,
    )

    if settings.scan_root is not None:
        max_file = _human_size(settings.max_file_bytes)

        async def scan_path(
            path: Annotated[
                str,
                Field(
                    description="Path of the file to scan, relative to the server's scan directory.",
                    min_length=1,
                    max_length=4096,
                ),
            ],
        ) -> ScanResult:
            try:
                return await scanner.scan_path(path, principal=_principal(settings))
            except ScanRejectedError as exc:
                raise ToolError(str(exc)) from exc

        mcp.add_tool(
            scan_path,
            name="scan_path",
            title="Scan a file in the scan directory",
            description=(
                "Scan one file from the directory the server operator shared for scanning (mounted read-only). "
                f"Paths are relative to that directory; files outside it cannot be read. At most {max_file}. "
                "Returns the same result as scan_file. The file content is never returned."
            ),
            annotations=READ_ONLY,
            structured_output=True,
        )

    async def get_scanner_info() -> ScannerInfo:
        try:
            return await scanner.info(principal=_principal(settings))
        except ScanRejectedError as exc:
            raise ToolError(str(exc)) from exc

    mcp.add_tool(
        get_scanner_info,
        name="get_scanner_info",
        title="Scanner status",
        description=(
            "Report whether the ClamAV daemon is reachable, its engine and signature database versions, how old "
            "the signatures are, and the size limits for scanning."
        ),
        annotations=READ_ONLY,
        structured_output=True,
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> PlainTextResponse:
        """Liveness: the process is serving HTTP."""
        return PlainTextResponse("ok")

    ready_cache: dict[str, float | bool] = {}

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(_: Request) -> PlainTextResponse:
        """Readiness: clamd answers PING. Cached briefly so the probe cannot be used to flood clamd."""
        now = time.monotonic()
        if now - float(ready_cache.get("at", 0.0)) > 5.0:
            ready_cache["ok"] = await clamd.ping()
            ready_cache["at"] = now
        ok = bool(ready_cache.get("ok"))
        return PlainTextResponse("ready" if ok else "clamd unavailable", status_code=200 if ok else 503)

    return mcp
