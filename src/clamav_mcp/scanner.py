"""Scan orchestration: input validation, limits, clamd streaming and result shaping.

Nothing here touches the filesystem except ``scan_path``, which only reads
regular files that resolve inside the configured, read-only scan root.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import re
import stat
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path

import anyio

from clamav_mcp.clamd import (
    ClamdClient,
    ClamdError,
    ClamdStreamTooLargeError,
    ClamdUnavailableError,
    ClamdVerdict,
    EngineInfo,
)
from clamav_mcp.config import Settings
from clamav_mcp.logs import audit
from clamav_mcp.models import ScannerInfo, ScanResult
from clamav_mcp.ratelimit import RateLimiter
from clamav_mcp.sanitize import clean_signature, clean_text

logger = logging.getLogger(__name__)

READ_SIZE = 128 * 1024
ENGINE_INFO_TTL = 60.0
STALE_AFTER_HOURS = 48.0
MAX_NAME_LEN = 255

_DATA_URL_RE = re.compile(r"^data:[A-Za-z0-9.+/-]*(?:;[A-Za-z0-9.+-]+=[A-Za-z0-9.+-]+)*;base64,", re.IGNORECASE)
_WHITESPACE = str.maketrans("", "", " \t\r\n")

PATH_REJECTED = (
    "Path must name an existing regular file inside the scan root (relative paths are resolved against the scan root)."
)


class ScanRejectedError(Exception):
    """A failure whose message is safe to show to the client and the model."""


def decode_base64(text: str, *, max_bytes: int) -> bytes:
    """Decode standard or URL-safe base64, tolerating MIME line breaks, missing padding and a data: URL prefix."""
    if text[:5].lower() == "data:":
        text = _DATA_URL_RE.sub("", text, count=1)
    compact = text.translate(_WHITESPACE).rstrip("=")
    if not compact:
        raise ScanRejectedError("base64_data is empty.")
    if not compact.isascii():
        raise ScanRejectedError("base64_data is not valid base64.")
    urlsafe = "-" in compact or "_" in compact
    if urlsafe and ("+" in compact or "/" in compact):
        raise ScanRejectedError("base64_data mixes the standard and URL-safe base64 alphabets.")
    estimated = len(compact) * 3 // 4
    if estimated > max_bytes:
        raise ScanRejectedError(f"The decoded file would be {estimated} bytes; the limit is {max_bytes} bytes.")
    padded = compact + "=" * (-len(compact) % 4)
    try:
        data = base64.b64decode(padded, altchars=b"-_" if urlsafe else None, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ScanRejectedError("base64_data is not valid base64.") from exc
    if not data:
        raise ScanRejectedError("base64_data decodes to an empty file.")
    return data


def open_in_root(root: Path, user_path: str) -> tuple[int, int, str]:
    """Open ``user_path`` read-only if it resolves to a regular file inside ``root``.

    Returns ``(fd, size, label)``. Symlinks are followed only when their target
    stays inside the root; the final open uses O_NOFOLLOW and the type check is
    done on the opened descriptor (fstat), not the name, to avoid TOCTOU races.
    """
    if not user_path or len(user_path) > 4096 or "\x00" in user_path:
        raise ScanRejectedError(PATH_REJECTED)
    candidate = Path(user_path.replace("\\", "/"))
    target = candidate if candidate.is_absolute() else root / candidate
    try:
        resolved = target.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScanRejectedError(PATH_REJECTED) from exc
    if resolved != root and not resolved.is_relative_to(root):
        raise ScanRejectedError(PATH_REJECTED)

    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_NOCTTY", "O_BINARY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(resolved, flags)
    except OSError as exc:
        raise ScanRejectedError(PATH_REJECTED) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ScanRejectedError(PATH_REJECTED)
    except BaseException:
        os.close(fd)
        raise
    return fd, info.st_size, resolved.relative_to(root).as_posix()


def _detail(verdict: ClamdVerdict) -> str:
    if verdict.status == "infected":
        return "Malware detected: " + ", ".join(clean_signature(sig) for sig in verdict.signatures) + "."
    if verdict.status == "inconclusive":
        return "The file could not be fully scanned (scan limits were exceeded); treat it as untrusted."
    return "No known threats found by ClamAV."


class Scanner:
    def __init__(
        self,
        settings: Settings,
        clamd: ClamdClient,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._clamd = clamd
        self._clock = clock
        self._limiter = RateLimiter(
            rate_per_minute=settings.rate_limit_per_minute, burst=settings.rate_limit_burst, clock=clock
        )
        self._capacity = anyio.CapacityLimiter(settings.max_concurrent_scans)
        self._engine: tuple[float, EngineInfo] | None = None

    # -- shared plumbing -------------------------------------------------------------------------

    def _check_rate(self, principal: str) -> None:
        retry_after = self._limiter.acquire(principal)
        if retry_after > 0:
            audit("scan rejected", outcome="rate_limited", principal=principal)
            raise ScanRejectedError(f"Rate limit exceeded; retry in {max(1, round(retry_after))} seconds.")

    async def engine_info(self) -> EngineInfo | None:
        now = self._clock()
        if self._engine is not None and now - self._engine[0] < ENGINE_INFO_TTL:
            return self._engine[1]
        try:
            info = await self._clamd.version()
        except ClamdError as exc:
            logger.warning("Could not read clamd version: %s", exc)
            return self._engine[1] if self._engine else None
        self._engine = (now, info)
        return info

    async def _run_scan(
        self,
        chunks: AsyncIterator[bytes],
        *,
        principal: str,
        source: str,
        name: str | None,
        size: Callable[[], int],
        digest: Callable[[], str],
    ) -> ScanResult:
        settings = self._settings
        started = self._clock()
        try:
            with anyio.fail_after(settings.queue_timeout):
                await self._capacity.acquire()
        except TimeoutError as exc:
            audit("scan rejected", outcome="busy", principal=principal, source=source)
            raise ScanRejectedError("The scanner is busy; retry shortly.") from exc

        try:
            with anyio.fail_after(settings.scan_timeout):
                verdict = await self._clamd.instream(chunks)
        except TimeoutError as exc:
            audit("scan failed", outcome="timeout", principal=principal, source=source)
            raise ScanRejectedError(f"The scan timed out after {settings.scan_timeout:g} seconds.") from exc
        except ClamdStreamTooLargeError:
            # Our own limit is above clamd's StreamMaxLength: report honestly instead of failing.
            verdict = ClamdVerdict("inconclusive", ("Heuristics.Limits.Exceeded.StreamMaxLength",))
        except ClamdUnavailableError as exc:
            logger.error("clamd unavailable: %s", exc)
            audit("scan failed", outcome="unavailable", principal=principal, source=source)
            raise ScanRejectedError("The ClamAV daemon is unavailable; try again later.") from exc
        except ClamdError as exc:
            logger.error("clamd error: %s", exc)
            audit("scan failed", outcome="error", principal=principal, source=source)
            raise ScanRejectedError("The scan failed: the ClamAV daemon reported an error.") from exc
        finally:
            self._capacity.release()

        engine = await self.engine_info()
        duration_ms = int((self._clock() - started) * 1000)
        signatures = [clean_signature(sig) for sig in verdict.signatures]
        result = ScanResult(
            verdict=verdict.status,
            infected=verdict.status == "infected",
            signatures=signatures,
            source=source,  # type: ignore[arg-type]
            name=name,
            size_bytes=size(),
            sha256=digest(),
            engine_version=engine.engine_version if engine else None,
            database_version=engine.database_version if engine else None,
            scanned_at=datetime.now(UTC),
            duration_ms=duration_ms,
            detail=_detail(verdict),
        )
        audit(
            "scan completed",
            outcome=result.verdict,
            principal=principal,
            source=source,
            name=name,
            size_bytes=result.size_bytes,
            sha256=result.sha256,
            signatures=signatures,
            duration_ms=duration_ms,
        )
        return result

    # -- tools -----------------------------------------------------------------------------------

    async def scan_base64(self, base64_data: str, filename: str | None, *, principal: str) -> ScanResult:
        self._check_rate(principal)
        max_bytes = self._settings.max_inline_bytes

        def _decode() -> tuple[bytes, str]:
            data = decode_base64(base64_data, max_bytes=max_bytes)
            return data, hashlib.sha256(data).hexdigest()

        data, sha256 = await anyio.to_thread.run_sync(_decode)
        if len(data) > max_bytes:
            raise ScanRejectedError(f"The decoded file is {len(data)} bytes; the limit is {max_bytes} bytes.")
        label = (clean_text(filename, max_len=MAX_NAME_LEN) or None) if filename else None

        async def chunks() -> AsyncIterator[bytes]:
            yield data

        return await self._run_scan(
            chunks(),
            principal=principal,
            source="inline",
            name=label,
            size=lambda: len(data),
            digest=lambda: sha256,
        )

    async def scan_path(self, path: str, *, principal: str) -> ScanResult:
        root = self._settings.scan_root
        if root is None:  # pragma: no cover - the tool is not registered without a scan root
            raise ScanRejectedError("Path scanning is disabled on this server.")
        self._check_rate(principal)
        max_bytes = self._settings.max_file_bytes

        fd, size, rel = await anyio.to_thread.run_sync(open_in_root, root, path)
        try:
            if size > max_bytes:
                raise ScanRejectedError(f"The file is {size} bytes; the limit is {max_bytes} bytes.")
            hasher = hashlib.sha256()
            total = 0

            async def chunks() -> AsyncIterator[bytes]:
                nonlocal total
                while True:
                    chunk = await anyio.to_thread.run_sync(os.read, fd, READ_SIZE)
                    if not chunk:
                        return
                    total += len(chunk)
                    if total > max_bytes:
                        raise ScanRejectedError(f"The file grew past the {max_bytes}-byte limit while reading.")
                    hasher.update(chunk)
                    yield chunk

            return await self._run_scan(
                chunks(),
                principal=principal,
                source="path",
                name=clean_text(rel, max_len=1024),
                size=lambda: total,
                digest=hasher.hexdigest,
            )
        finally:
            os.close(fd)

    async def info(self, *, principal: str) -> ScannerInfo:
        self._check_rate(principal)  # each call pings clamd, so it shares the scan budget
        settings = self._settings
        engine = await self.engine_info()
        age_hours: float | None = None
        if engine and engine.database_date:
            age_hours = round((datetime.now(UTC) - engine.database_date).total_seconds() / 3600, 1)
        return ScannerInfo(
            available=engine is not None and await self._clamd.ping(),
            engine_version=engine.engine_version if engine else None,
            database_version=engine.database_version if engine else None,
            database_date=engine.database_date if engine else None,
            database_age_hours=age_hours,
            database_stale=None if age_hours is None else age_hours > STALE_AFTER_HOURS,
            max_inline_bytes=settings.max_inline_bytes,
            path_scanning_enabled=settings.scan_root is not None,
            max_file_bytes=settings.max_file_bytes if settings.scan_root is not None else None,
        )
