from __future__ import annotations

import dataclasses

from .base import Finding, Severity


@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: Severity

    def finding(self, message: str, raw: str = "") -> Finding:
        return Finding(
            rule_id=self.rule_id, message=message, severity=self.severity, raw=raw
        )


_CLEARTEXT_SERVICES = {
    "telnet": Severity.HIGH,
    "rlogin": Severity.HIGH,
    "rsh": Severity.HIGH,
    "rexec": Severity.HIGH,
    "vnc": Severity.HIGH,
    "ftp": Severity.MEDIUM,
}

_EXPOSED_INFRA_SERVICES = {
    "microsoft-ds": Severity.MEDIUM,
    "netbios-ssn": Severity.MEDIUM,
    "ms-wbt-server": Severity.MEDIUM,
    "mysql": Severity.MEDIUM,
    "postgresql": Severity.MEDIUM,
    "mongodb": Severity.MEDIUM,
    "redis": Severity.MEDIUM,
}

_RISKY_SERVICES = {**_CLEARTEXT_SERVICES, **_EXPOSED_INFRA_SERVICES}

_SECRET_PATHS = {
    ".env",
    ".htpasswd",
    "credentials",
    "id_rsa",
    "secrets",
}

_DISCLOSURE_PATHS = {
    ".git",
    ".svn",
    "backup",
    "dump",
    "phpinfo.php",
    "server-status",
    "web.config",
}

_ADMIN_PATHS = {
    "admin",
    "administrator",
    "console",
    "dashboard",
    "manager",
    "phpmyadmin",
    "wp-admin",
}


def open_port(service: str) -> Rule:
    severity = _RISKY_SERVICES.get(service.lower())
    if severity is None:
        return Rule("nmap/open-port", Severity.INFO)
    return Rule("nmap/insecure-service", severity)


def discovered_path(path: str, status_code: int) -> Rule:
    if not 200 <= status_code < 300:
        return Rule(f"gobuster/path-{status_code}", Severity.INFO)

    name = _path_key(path)
    if name in _SECRET_PATHS:
        return Rule("gobuster/exposed-secret", Severity.CRITICAL)
    if name in _DISCLOSURE_PATHS:
        return Rule("gobuster/information-disclosure", Severity.HIGH)
    if name in _ADMIN_PATHS:
        return Rule("gobuster/exposed-admin-interface", Severity.MEDIUM)
    return Rule("gobuster/discovered-path", Severity.LOW)


def _path_key(path: str) -> str:
    return path.strip().lstrip("/").split("/")[0].lower()
