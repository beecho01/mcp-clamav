"""Output sanitisation for every string that leaves the server.

Tool results are fed to a language model and often rendered in a terminal, so
caller-supplied labels and engine output are scrubbed of control characters,
ANSI/OSC escape sequences, bidirectional overrides and zero-width characters
(Trojan Source / hidden-instruction tricks), and length-capped.
"""

from __future__ import annotations

import re
import unicodedata

# CSI (ESC [ ... final), OSC (ESC ] ... BEL or ST) and other two-byte ESC sequences.
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]")

# Cc control, Cf format (bidi overrides, zero-width), Cs surrogate, Co private use,
# Cn unassigned, Zl/Zp line/paragraph separators.
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

# ClamAV signature names: Platform.Category.Name-Id, YARA rules, "Heuristics.*" and so on.
_SIGNATURE_DISALLOWED = re.compile(r"[^A-Za-z0-9._:+/@-]")

MAX_SIGNATURE_LEN = 200


def clean_text(value: str, *, max_len: int) -> str:
    """Return a single-line, printable version of ``value`` capped at ``max_len`` characters."""
    value = _ANSI_RE.sub("", value)
    out: list[str] = []
    for ch in unicodedata.normalize("NFC", value):
        if ch.isspace():  # line breaks, tabs and Unicode spaces become plain word separators
            out.append(" ")
        elif unicodedata.category(ch) not in _DROP_CATEGORIES:
            out.append(ch)
    text = " ".join("".join(out).split())
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def clean_signature(name: str) -> str:
    """Restrict a signature name to the characters ClamAV uses."""
    cleaned = _SIGNATURE_DISALLOWED.sub("_", name.strip())
    return cleaned[:MAX_SIGNATURE_LEN] or "unknown"
