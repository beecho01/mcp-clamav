"""Minimal asynchronous client for the clamd daemon protocol.

Files are streamed with ``INSTREAM``, so nothing is ever written to disk and no
subprocess or shell is involved. All replies are size-capped and every
operation is bounded by a timeout.

Protocol reference: https://docs.clamav.net/manual/Usage/Scanning.html#clamd
"""

from __future__ import annotations

import re
import struct
from collections.abc import AsyncIterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import anyio
from anyio.abc import ByteStream

MAX_REPLY_BYTES = 64 * 1024
CHUNK_SIZE = 64 * 1024

_FOUND_RE = re.compile(r"^(?:stream|[^:]*):\s*(?P<sig>.+?)\s+FOUND$")
_VERSION_RE = re.compile(r"^ClamAV (?P<engine>[^/\s]+)(?:/(?P<db>\d+)(?:/(?P<date>.+))?)?$")

LIMITS_PREFIX = "Heuristics.Limits.Exceeded"


class ClamdError(Exception):
    """Base error for clamd interactions. Messages are for logs, not for clients."""


class ClamdUnavailableError(ClamdError):
    """clamd could not be reached."""


class ClamdProtocolError(ClamdError):
    """clamd returned something unexpected or reported an error."""


class ClamdStreamTooLargeError(ClamdError):
    """clamd rejected the stream for exceeding StreamMaxLength."""


@dataclass(frozen=True, slots=True)
class ClamdVerdict:
    status: Literal["clean", "infected", "inconclusive"]
    signatures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EngineInfo:
    engine_version: str
    database_version: int | None
    database_date: datetime | None


def parse_version(reply: str) -> EngineInfo:
    match = _VERSION_RE.match(reply.strip())
    if not match:
        raise ClamdProtocolError(f"unexpected VERSION reply {reply[:120]!r}")
    db = match.group("db")
    date_text = match.group("date")
    db_date: datetime | None = None
    if date_text:
        try:
            # clamd prints ctime() format in the daemon's timezone (UTC in the official image).
            db_date = datetime.strptime(date_text.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
        except ValueError:
            db_date = None
    return EngineInfo(
        engine_version=match.group("engine"),
        database_version=int(db) if db else None,
        database_date=db_date,
    )


def parse_scan_reply(reply: str) -> ClamdVerdict:
    lines = [line.strip() for line in reply.replace("\0", "\n").splitlines() if line.strip()]
    if not lines:
        raise ClamdProtocolError("empty scan reply")

    signatures: list[str] = []
    clean = False
    for line in lines:
        if line.endswith(" FOUND"):
            match = _FOUND_RE.match(line)
            if not match:
                raise ClamdProtocolError(f"malformed FOUND reply {line[:200]!r}")
            signatures.append(match.group("sig"))
        elif line.endswith(": OK"):
            clean = True
        elif "size limit exceeded" in line.lower():
            raise ClamdStreamTooLargeError(line[:200])
        elif line.endswith("ERROR"):
            raise ClamdProtocolError(f"clamd reported an error: {line[:200]!r}")
        else:
            raise ClamdProtocolError(f"unexpected scan reply {line[:200]!r}")

    if signatures:
        real = [sig for sig in signatures if not sig.startswith(LIMITS_PREFIX)]
        if real:
            return ClamdVerdict("infected", tuple(real))
        # Only scan-limit heuristics fired: the file was not fully inspected.
        return ClamdVerdict("inconclusive", tuple(signatures))
    if clean:
        return ClamdVerdict("clean", ())
    raise ClamdProtocolError("scan reply had neither OK nor FOUND")  # pragma: no cover - defensive


class ClamdClient:
    """Talks to clamd over TCP or a Unix socket."""

    def __init__(
        self,
        *,
        host: str | None = None,
        port: int = 3310,
        unix_socket: str | None = None,
        connect_timeout: float = 5.0,
        command_timeout: float = 10.0,
    ) -> None:
        if (host is None) == (unix_socket is None):
            raise ValueError("exactly one of host or unix_socket is required")
        self._host = host
        self._port = port
        self._unix_socket = unix_socket
        self._connect_timeout = connect_timeout
        self._command_timeout = command_timeout

    @property
    def endpoint(self) -> str:
        return f"unix:{self._unix_socket}" if self._unix_socket else f"tcp:{self._host}:{self._port}"

    async def _connect(self) -> ByteStream:
        try:
            with anyio.fail_after(self._connect_timeout):
                if self._unix_socket:
                    return await anyio.connect_unix(self._unix_socket)
                return await anyio.connect_tcp(str(self._host), self._port)
        except TimeoutError as exc:
            raise ClamdUnavailableError(f"timed out connecting to clamd at {self.endpoint}") from exc
        except OSError as exc:
            raise ClamdUnavailableError(f"cannot connect to clamd at {self.endpoint}: {exc}") from exc

    @staticmethod
    async def _read_reply(stream: ByteStream) -> str:
        buf = bytearray()
        while b"\0" not in buf:
            try:
                data = await stream.receive(4096)
            except (anyio.EndOfStream, anyio.BrokenResourceError, ConnectionError):
                break
            buf.extend(data)
            if len(buf) > MAX_REPLY_BYTES:
                raise ClamdProtocolError("clamd reply exceeded size limit")
        return bytes(buf).split(b"\0", 1)[0].decode("utf-8", errors="replace")

    async def _command(self, command: bytes) -> str:
        stream = await self._connect()
        async with stream:
            try:
                with anyio.fail_after(self._command_timeout):
                    await stream.send(b"z" + command + b"\0")
                    return await self._read_reply(stream)
            except TimeoutError as exc:
                raise ClamdUnavailableError(f"clamd did not answer {command.decode()} in time") from exc
            except (anyio.BrokenResourceError, OSError) as exc:
                raise ClamdUnavailableError(f"connection to clamd failed: {exc}") from exc

    async def ping(self) -> bool:
        try:
            return await self._command(b"PING") == "PONG"
        except ClamdError:
            return False

    async def version(self) -> EngineInfo:
        return parse_version(await self._command(b"VERSION"))

    async def instream(self, chunks: AsyncIterable[bytes | memoryview]) -> ClamdVerdict:
        """Stream data to clamd and return its verdict. The caller enforces size limits and timeouts."""
        stream = await self._connect()
        async with stream:
            send_failed = False
            try:
                await stream.send(b"zINSTREAM\0")
                async for chunk in chunks:
                    view = memoryview(chunk)
                    for offset in range(0, len(view), CHUNK_SIZE):
                        piece = view[offset : offset + CHUNK_SIZE]
                        await stream.send(struct.pack("!I", len(piece)))
                        await stream.send(bytes(piece))
                await stream.send(struct.pack("!I", 0))
            except (anyio.BrokenResourceError, ConnectionError, OSError):
                # clamd closes the socket early when StreamMaxLength is exceeded;
                # its explanation is still waiting to be read.
                send_failed = True
            reply = await self._read_reply(stream)
            if not reply:
                if send_failed:
                    raise ClamdUnavailableError("clamd closed the connection during INSTREAM")
                raise ClamdProtocolError("clamd closed the connection without a reply")
            return parse_scan_reply(reply)
