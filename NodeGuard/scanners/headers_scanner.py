from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

from . import sarif
from .base import BaseScanner, Finding, TargetValidationError
from .registry import register_scanner

_SCRIPT = pathlib.Path(__file__).parent / "tools" / "http_headers.py"

# host[:port][/path], optionally scheme-prefixed — same shape gobuster accepts,
# since this tool also scans a web URL rather than a bare host.
_URL_TARGET = re.compile(
    r"(?:https?://)?"
    r"[A-Za-z0-9][A-Za-z0-9.-]*"
    r"(?::(?P<port>\d{1,5}))?"
    r"(?:/[A-Za-z0-9._~%/-]*)?"
)


@register_scanner("headers")
class HttpHeadersScanner(BaseScanner):
    """Custom SARIF scanner: fetches a URL and flags missing HTTP security
    response headers.

    Unlike nmap/gobuster it wraps no third-party binary — it runs a small
    bundled Python script that emits SARIF on stdout, which the shared `sarif`
    parser normalizes into Findings. That makes it the end-to-end proof of the
    catalog's SARIF path (and Denis's first real tool, start to finish).
    """

    binary_name = sys.executable

    def is_available(self) -> bool:
        # In-process Python via `requests`, so availability is "can we import
        # requests?", not "is there a binary on PATH".
        return importlib.util.find_spec("requests") is not None

    def validate_target(self, target: str) -> str:
        target = target.strip()
        match = _URL_TARGET.fullmatch(target)
        if len(target) > 255 or match is None:
            raise TargetValidationError(f"refusing to scan target: {target!r}")
        port = match.group("port")
        if port is not None and not 1 <= int(port) <= 65535:
            raise TargetValidationError(f"port out of range: {target!r}")
        return target

    def build_command(self, target: str, options: dict | None = None) -> list[str]:
        url = target if target.startswith("http") else f"http://{target}"
        return [sys.executable, str(_SCRIPT), url]

    def parse_output(self, raw_output: str) -> list[Finding]:
        return sarif.parse(raw_output).findings
