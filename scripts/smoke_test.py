"""End-to-end check of a running deployment: auth, protections, and real ClamAV verdicts.

    MCP_URL=http://127.0.0.1:8000/mcp MCP_TOKEN=cmcp_... python scripts/smoke_test.py

Exits non-zero on the first failed expectation. Uses the EICAR test string, which every
antivirus engine detects by design; it is assembled in memory and never written to disk.
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


def check(condition: bool, label: str) -> None:
    print(("PASS " if condition else "FAIL ") + label)
    if not condition:
        sys.exit(1)


async def main() -> None:
    url = os.environ.get("MCP_URL", "http://127.0.0.1:8000/mcp")
    token = os.environ["MCP_TOKEN"]
    json_headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    probe = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

    async with httpx2.AsyncClient(timeout=30) as raw:
        response = await raw.post(url, content=probe, headers=json_headers)
        check(response.status_code == 401, "request without a token is rejected (401)")
        response = await raw.post(url, content=probe, headers={**json_headers, "Authorization": "Bearer cmcp_nope"})
        check(response.status_code == 401, "request with a wrong token is rejected (401)")
        response = await raw.post(
            url,
            content=probe,
            headers={**json_headers, "Authorization": f"Bearer {token}", "Origin": "https://evil.example"},
        )
        check(response.status_code == 403, "cross-site Origin is rejected (403, DNS-rebinding protection)")
        response = await raw.get(url, headers={"Authorization": f"Bearer {token}"})
        check(response.status_code == 405, "GET on the MCP endpoint is refused (405, no session streams)")

    for mode in ("auto", "legacy"):
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=60) as http:
            async with Client(streamable_http_client(url, http_client=http), mode=mode) as client:  # type: ignore[arg-type]
                label = f"[{mode}, protocol {client.protocol_version}]"
                tools = sorted(tool.name for tool in (await client.list_tools()).tools)
                check({"scan_file", "get_scanner_info"} <= set(tools), f"{label} tools listed: {tools}")

                info = (await client.call_tool("get_scanner_info", {})).structured_content
                check(
                    info["available"],
                    f"{label} clamd reachable: ClamAV {info['engine_version']}, "
                    f"db {info['database_version']} ({info['database_age_hours']} h old)",
                )

                clean = await client.call_tool(
                    "scan_file", {"base64_data": base64.b64encode(b"just some text").decode(), "filename": "a.txt"}
                )
                check(clean.structured_content["verdict"] == "clean", f"{label} harmless file is clean")

                infected = await client.call_tool("scan_file", {"base64_data": base64.b64encode(EICAR).decode()})
                data = infected.structured_content
                check(data["verdict"] == "infected", f"{label} EICAR detected as {data['signatures']}")

                bad = await client.call_tool("scan_file", {"base64_data": "%%% not base64 %%%"})
                check(bool(bad.is_error), f"{label} invalid input is a tool error, not a crash")


if __name__ == "__main__":
    asyncio.run(main())
