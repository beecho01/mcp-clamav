from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from clamav_mcp.clamd import (
    ClamdClient,
    ClamdProtocolError,
    ClamdStreamTooLargeError,
    ClamdUnavailableError,
    parse_scan_reply,
    parse_version,
)
from tests.conftest import EICAR, FakeClamdState, free_port

pytestmark = pytest.mark.anyio


def test_parse_version() -> None:
    info = parse_version("ClamAV 1.5.5/28191/Sun Nov 22 06:27:13 2026")
    assert info.engine_version == "1.5.5"
    assert info.database_version == 28191
    assert info.database_date == datetime(2026, 11, 22, 6, 27, 13, tzinfo=UTC)


def test_parse_version_with_padded_day_and_without_database() -> None:
    assert parse_version("ClamAV 1.4.7/27000/Thu Nov  5 06:27:13 2026").database_date is not None
    info = parse_version("ClamAV 1.5.5")
    assert (info.database_version, info.database_date) == (None, None)
    with pytest.raises(ClamdProtocolError):
        parse_version("garbage")


@pytest.mark.parametrize(
    ("reply", "status", "signatures"),
    [
        ("stream: OK", "clean", ()),
        ("stream: Win.Test.EICAR_HDB-1 FOUND", "infected", ("Win.Test.EICAR_HDB-1",)),
        (
            "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND",
            "inconclusive",
            ("Heuristics.Limits.Exceeded.MaxScanSize",),
        ),
        ("stream: A FOUND\nstream: Heuristics.Limits.Exceeded.MaxFiles FOUND", "infected", ("A",)),
    ],
)
def test_parse_scan_reply(reply: str, status: str, signatures: tuple[str, ...]) -> None:
    verdict = parse_scan_reply(reply)
    assert verdict.status == status
    assert verdict.signatures == signatures


def test_parse_scan_reply_errors() -> None:
    with pytest.raises(ClamdStreamTooLargeError):
        parse_scan_reply("INSTREAM size limit exceeded. ERROR")
    with pytest.raises(ClamdProtocolError):
        parse_scan_reply("Can't allocate memory ERROR")
    with pytest.raises(ClamdProtocolError):
        parse_scan_reply("")
    with pytest.raises(ClamdProtocolError):
        parse_scan_reply("something unexpected")


async def _once(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def test_client_ping_version_and_scans(clamd_client: ClamdClient, fake_clamd: tuple[FakeClamdState, int]) -> None:
    state, _ = fake_clamd
    assert await clamd_client.ping()
    assert (await clamd_client.version()).database_version == 28191

    assert (await clamd_client.instream(_once(b"hello"))).status == "clean"
    infected = await clamd_client.instream(_once(b"prefix" + EICAR))
    assert infected.status == "infected"
    assert infected.signatures == ("Eicar-Test-Signature",)

    big = bytes(200_000)  # spans several 64 KiB INSTREAM chunks
    assert (await clamd_client.instream(_once(big))).status == "clean"
    assert state.received[-1] == big


async def test_client_reports_stream_too_large(
    clamd_client: ClamdClient, fake_clamd: tuple[FakeClamdState, int]
) -> None:
    fake_clamd[0].stream_max = 1000
    with pytest.raises(ClamdStreamTooLargeError):
        await clamd_client.instream(_once(bytes(5000)))


async def test_client_reports_daemon_errors(clamd_client: ClamdClient) -> None:
    with pytest.raises(ClamdProtocolError):
        await clamd_client.instream(_once(b"TRIGGER-ERROR"))


async def test_unreachable_daemon() -> None:
    client = ClamdClient(host="127.0.0.1", port=free_port(), connect_timeout=1)
    assert not await client.ping()
    with pytest.raises(ClamdUnavailableError):
        await client.instream(_once(b"x"))


def test_client_requires_exactly_one_endpoint() -> None:
    with pytest.raises(ValueError):
        ClamdClient()
    with pytest.raises(ValueError):
        ClamdClient(host="a", unix_socket="/tmp/s")
