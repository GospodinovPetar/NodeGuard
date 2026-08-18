from __future__ import annotations

import pathlib
import re

from .base import BaseScanner, Finding, Severity
from .registry import register_scanner

WORDLIST_PATH = pathlib.Path(__file__).parent / "wordlists" / "common.txt"

# gobuster dir -q output, one hit per line:
#   /admin                (Status: 200) [Size: 1234]
_RESULT_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)")


@register_scanner("gobuster")
class GobusterScanner(BaseScanner):
    """Directory brute-forcing via gobuster's `dir` mode."""

    binary_name = "gobuster"

    def build_command(self, target: str, options: dict | None = None) -> list[str]:
        options = options or {}
        wordlist_path = options.get("wordlist_path", str(WORDLIST_PATH))
        url = target if target.startswith("http") else f"http://{target}"
        return [
            "gobuster",
            "dir",
            "-u",
            url,
            "-w",
            wordlist_path,
            "-q",
            "-t",
            "10",
        ]

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        for line in raw_output.splitlines():
            match = _RESULT_RE.match(line.strip())
            if not match:
                continue
            path, status = match.group(1), int(match.group(2))
            # Sprint 2 refines this into a proper severity ruleset; for now
            # a reachable (200) path is more notable than a redirect/denial.
            severity = Severity.LOW if status == 200 else Severity.INFO
            findings.append(
                Finding(
                    rule_id=f"gobuster-{status}",
                    message=f"{path} (Status: {status})",
                    severity=severity,
                    raw=line,
                )
            )
        return findings
