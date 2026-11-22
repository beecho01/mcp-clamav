"""Hardened MCP server that scans files for malware with ClamAV."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("clamav-mcp")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
