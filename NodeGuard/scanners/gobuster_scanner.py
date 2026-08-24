from __future__ import annotations

import pathlib
import re

from . import severity_rules
from .base import Finding, UrlTargetScanner
from .registry import register_scanner

WORDLIST_PATH = pathlib.Path(__file__).parent / "wordlists" / "common.txt"

# gobuster dir -q output, one hit per line:
#   /admin                (Status: 200) [Size: 1234]
_RESULT_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)")


@register_scanner("gobuster")
class GobusterScanner(UrlTargetScanner):
    """Directory brute-forcing via gobuster's `dir` mode."""

    binary_name = "gobuster"
    # No profile_options: the only knob today is wordlist_path, which becomes
    # a filesystem path in argv and is set per-scan from a validated upload.
    # A profile must not be able to point it at an arbitrary file.

    def build_command(self, target: str, options: dict | None = None) -> list[str]:
        options = options or {}
        wordlist_path = options.get("wordlist_path", str(WORDLIST_PATH))
        url = self.url(target)
        return [
            self.binary_name,
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
            rule = severity_rules.discovered_path(path, status)
            findings.append(rule.finding(f"{path} (Status: {status})", raw=line))
        return findings
