from __future__ import annotations

import pathlib
import re

from . import severity_rules
from .base import BaseScanner, Finding, TargetValidationError
from .registry import register_scanner

WORDLIST_PATH = pathlib.Path(__file__).parent / "wordlists" / "common.txt"

# host[:port][/path], optionally scheme-prefixed. Deliberately narrower than
# a general URL: no userinfo (credentials would be stored on Target.value and
# rendered in the scan list), no query string, and http/https only — nothing
# should be able to hand gobuster a file:// or gopher:// URL.
_URL_TARGET = re.compile(
    r"(?:https?://)?"
    r"[A-Za-z0-9][A-Za-z0-9.-]*"
    r"(?::(?P<port>\d{1,5}))?"
    r"(?:/[A-Za-z0-9._~%/-]*)?"
)

# gobuster dir -q output, one hit per line:
#   /admin                (Status: 200) [Size: 1234]
_RESULT_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)")


@register_scanner("gobuster")
class GobusterScanner(BaseScanner):
    """Directory brute-forcing via gobuster's `dir` mode."""

    binary_name = "gobuster"
    # No profile_options: the only knob today is wordlist_path, which becomes
    # a filesystem path in argv and is set per-scan from a validated upload.
    # A profile must not be able to point it at an arbitrary file.

    def validate_target(self, target: str) -> str:
        """Accept a host *or* an http(s) URL — gobuster scans a web root.

        The base rule only allows host/IP/CIDR, which rejected every target
        carrying a scheme, port or path even though build_command() knows how
        to prefix a scheme and the trigger form advertises `http://host`.
        Keeps the base rule's real job: nothing may lead with '-', and no
        whitespace or shell metacharacters, so a target still can't smuggle
        an argument into gobuster's argv.
        """
        target = target.strip()
        match = _URL_TARGET.fullmatch(target)
        if len(target) > 255 or match is None:
            raise TargetValidationError(f"refusing to scan target: {target!r}")

        port = match.group("port")
        if port is not None and not 1 <= int(port) <= 65535:
            raise TargetValidationError(f"port out of range: {target!r}")

        return target

    def build_command(self, target: str, options: dict | None = None) -> list[str]:
        options = options or {}
        wordlist_path = options.get("wordlist_path", str(WORDLIST_PATH))
        url = target if target.startswith("http") else f"http://{target}"
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
