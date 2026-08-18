from __future__ import annotations

import sys

from .base import BaseScanner, Finding, Severity
from .registry import register_scanner


@register_scanner("demo")
class DemoScanner(BaseScanner):
    """Not a real security tool — proves the registry/async/parsing wiring
    end-to-end without depending on nmap/gobuster being installed. Copy this
    file's shape when adding a real scanner.
    """

    binary_name = sys.executable

    def build_command(self, target: str) -> list[str]:
        return [sys.executable, "-c", f"print('demo scan of {target} ok')"]

    def parse_output(self, raw_output: str) -> list[Finding]:
        return [
            Finding(
                rule_id="demo-ok",
                message=raw_output.strip(),
                severity=Severity.INFO,
                raw=raw_output,
            )
        ]
