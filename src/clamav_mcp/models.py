"""Structured tool results. Their JSON Schemas are published as each tool's ``outputSchema``."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["clean", "infected", "inconclusive"]


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict = Field(
        description=(
            "clean: no known signature matched. infected: malware or a policy signature matched. "
            "inconclusive: the file could not be fully scanned (for example, archive limits were "
            "exceeded); treat it as untrusted."
        )
    )
    infected: bool = Field(description="True only when verdict is 'infected'.")
    signatures: list[str] = Field(description="Names of the ClamAV signatures that matched, if any.")
    source: Literal["inline", "path"] = Field(
        description="Whether the file was sent inline or read from the scan root."
    )
    name: str | None = Field(description="Sanitised filename label or path relative to the scan root.")
    size_bytes: int = Field(ge=0, description="Number of bytes scanned.")
    sha256: str = Field(description="SHA-256 of the scanned bytes, hex encoded.")
    engine_version: str | None = Field(description="ClamAV engine version.")
    database_version: int | None = Field(description="ClamAV signature database version.")
    scanned_at: datetime = Field(description="When the scan finished (UTC).")
    duration_ms: int = Field(ge=0, description="Time spent scanning, in milliseconds.")
    detail: str = Field(description="One-sentence human-readable summary.")


class ScannerInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    available: bool = Field(description="Whether the ClamAV daemon answered.")
    engine_version: str | None
    database_version: int | None
    database_date: datetime | None = Field(description="Build time of the newest signature database (UTC).")
    database_age_hours: float | None
    database_stale: bool | None = Field(description="True when the signatures are more than 48 hours old.")
    max_inline_bytes: int = Field(description="Largest file accepted by scan_file, after base64 decoding.")
    path_scanning_enabled: bool
    max_file_bytes: int | None = Field(description="Largest file accepted by scan_path, when enabled.")
