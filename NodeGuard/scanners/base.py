from __future__ import annotations

import abc
import dataclasses
import enum
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


class BaseScanner(abc.ABC):
    """Subclass + register with @register_scanner to add a new tool.

    Only build_command/parse_output are tool-specific; execution, async
    dispatch, and storage are handled once by scanners/tasks.py.
    """

    name: str
    binary_name: str

    @abc.abstractmethod
    def build_command(self, target: str) -> list[str]:
        """Return the argv list to pass to subprocess.run for this target."""

    @abc.abstractmethod
    def parse_output(self, raw_output: str) -> list[Finding]:
        """Turn raw stdout into normalized Finding objects."""

    def is_available(self) -> bool:
        return shutil.which(self.binary_name) is not None
