from __future__ import annotations

import abc
import dataclasses
import enum
import re
import shutil


class Severity(enum.Enum):
    """Members are declared most→least serious; `rank` depends on that order."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 = most serious.

        Aggregating a target's severity means taking a max over findings, so
        the ordering has to live with the enum instead of being re-declared
        as a list wherever someone needs to sort.
        """
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> Severity | None:
        """Findings store severity as a plain string, so reading one back
        out of the DB needs a total function — unknown values sort last
        rather than raising."""
        try:
            return cls(str(value).lower())
        except ValueError:
            return None

    @classmethod
    def worst(cls, values) -> Severity | None:
        """Most serious severity among `values` (strings or members)."""
        parsed = (v if isinstance(v, cls) else cls.parse(v) for v in values)
        return min(
            (p for p in parsed if p is not None),
            key=_SEVERITY_RANK.__getitem__,
            default=None,
        )


_SEVERITY_RANK = {member: index for index, member in enumerate(Severity)}


@dataclasses.dataclass
class Finding:
    """SARIF-shaped result: every scanner normalizes to this, regardless of tool."""

    rule_id: str
    message: str
    severity: Severity
    raw: str = ""


class TargetValidationError(ValueError):
    """Target was rejected before it could reach a tool's argv."""


# Leading character is never punctuation, so a target can't pose as a flag.
_HOST = r"[A-Za-z0-9][A-Za-z0-9.-]*"

_HOST_OR_CIDR = re.compile(_HOST + r"(?:/(?:3[0-2]|[12]?[0-9]))?")

# host[:port][/path], optionally scheme-prefixed. Deliberately narrower than
# a general URL: no userinfo (credentials would be stored on Target.value and
# rendered in the scan list), no query string, and http/https only — nothing
# should be able to hand a scanner a file:// or gopher:// URL.
_URL_TARGET = re.compile(
    r"(?:https?://)?" + _HOST + r"(?::(?P<port>\d{1,5}))?" + r"(?:/[A-Za-z0-9._~%/-]*)?"
)


class BaseScanner(abc.ABC):
    """Subclass + register with @register_scanner to add a new tool.

    Only build_command/parse_output are tool-specific; execution, async
    dispatch, and storage are handled once by scanners/tasks.py.
    """

    name: str
    binary_name: str

    # Shape a target must fullmatch. Declared rather than hardcoded in
    # validate_target() so a scanner whose targets aren't bare hosts swaps the
    # pattern instead of restating the length cap and the error alongside it.
    target_pattern = _HOST_OR_CIDR

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
        """Reject anything that doesn't fullmatch `target_pattern`.

        argv lists stop *shell* injection but not *argument* injection: a
        target of "-oN /etc/crontab" would otherwise be read by nmap as a
        flag. Scanners whose targets aren't bare hosts widen the rule by
        setting `target_pattern` (see UrlTargetScanner).
        """
        target = target.strip()
        if len(target) > 255 or not self.target_pattern.fullmatch(target):
            raise TargetValidationError(f"refusing to scan target: {target!r}")
        return target


class UrlTargetScanner(BaseScanner):
    """Base for scanners that hit a web root rather than a bare host.

    The base host/CIDR rule rejects every target carrying a scheme, port or
    path, so a URL scanner has to widen it — and then has to re-add a scheme
    before handing the target to its tool. Inheriting from here wires both
    halves together, instead of each scanner remembering to do them itself.
    """

    target_pattern = _URL_TARGET

    def validate_target(self, target: str) -> str:
        target = super().validate_target(target)

        port = _URL_TARGET.fullmatch(target).group("port")
        if port is not None and not 1 <= int(port) <= 65535:
            raise TargetValidationError(f"port out of range: {target!r}")

        return target

    def url(self, target: str) -> str:
        """Scheme-prefix a validated target for the tool's argv.

        Matches the scheme, not the letters: a host like `httpbin.org` starts
        with "http" without carrying a scheme, and would otherwise reach the
        tool bare.
        """
        return (
            target if target.startswith(("http://", "https://")) else f"http://{target}"
        )
