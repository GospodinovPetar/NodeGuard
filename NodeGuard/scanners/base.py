from __future__ import annotations

import abc
import dataclasses
import enum
import re
import shutil


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclasses.dataclass
class Finding:
    """SARIF-shaped result: every scanner normalizes to this, regardless of tool."""

    rule_id: str
    message: str
    severity: Severity
    raw: str = ""


class TargetValidationError(ValueError):
    """Target was rejected before it could reach a tool's argv."""


_HOST_OR_CIDR = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*(?:/(?:3[0-2]|[12]?[0-9]))?")


class BaseScanner(abc.ABC):
    """Subclass + register with @register_scanner to add a new tool.

    Only build_command/parse_output are tool-specific; execution, async
    dispatch, and storage are handled once by scanners/tasks.py.
    """

    name: str
    binary_name: str

    # Option keys a SecurityProfile is allowed to set. Empty by default so a
    # scanner has to opt in explicitly: build_command() reads options into
    # argv, and some keys are meant to be filled at runtime from validated
    # input (gobuster's wordlist_path comes from an uploaded file), never
    # from stored profile config.
    profile_options: frozenset[str] = frozenset()

    @abc.abstractmethod
    def build_command(self, target: str, options: dict | None = None) -> list[str]:
        """Return the argv list to pass to subprocess.run for this target.

        `options` is scanner-specific (e.g. nmap flag toggles, a gobuster
        wordlist path) and always optional — every scanner must produce a
        sane command with `options=None`.
        """

    @abc.abstractmethod
    def parse_output(self, raw_output: str) -> list[Finding]:
        """Turn raw stdout into normalized Finding objects."""

    def is_available(self) -> bool:
        return shutil.which(self.binary_name) is not None

    def validate_target(self, target: str) -> str:
        """Reject anything that isn't a hostname/IPv4/CIDR.

        argv lists stop *shell* injection but not *argument* injection: a
        target of "-oN /etc/crontab" would otherwise be read by nmap as a
        flag. Override in scanners whose targets aren't hosts (e.g. gobuster
        takes a URL), but keep the leading character non-punctuation.
        """
        target = target.strip()
        if len(target) > 255 or not _HOST_OR_CIDR.fullmatch(target):
            raise TargetValidationError(f"refusing to scan target: {target!r}")
        return target
