from __future__ import annotations

import importlib.util
import pathlib
import sys

from . import sarif
from .base import Finding, UrlTargetScanner
from .registry import register_scanner

_SCRIPT = pathlib.Path(__file__).parent / "tools" / "http_headers.py"


@register_scanner("headers")
class HttpHeadersScanner(UrlTargetScanner):
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

    def build_command(self, target: str, options: dict | None = None) -> list[str]:
        return [sys.executable, str(_SCRIPT), self.url(target)]

    def parse_output(self, raw_output: str) -> list[Finding]:
        return sarif.parse(raw_output).findings
