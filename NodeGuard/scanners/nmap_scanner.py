from __future__ import annotations

import xml.etree.ElementTree as ET

from .base import BaseScanner, Finding, Severity
from .registry import register_scanner

# An open port is not a vulnerability by itself, so the baseline is INFO.
# These services are called out because they carry credentials in cleartext
# or are routinely exposed by accident.
_RISKY_SERVICES = {
    "telnet": Severity.HIGH,
    "rlogin": Severity.HIGH,
    "rsh": Severity.HIGH,
    "rexec": Severity.HIGH,
    "vnc": Severity.HIGH,
    "ftp": Severity.MEDIUM,
    "microsoft-ds": Severity.MEDIUM,
    "netbios-ssn": Severity.MEDIUM,
    "ms-wbt-server": Severity.MEDIUM,
    "mysql": Severity.MEDIUM,
    "postgresql": Severity.MEDIUM,
    "mongodb": Severity.MEDIUM,
    "redis": Severity.MEDIUM,
}


@register_scanner("nmap")
class NmapScanner(BaseScanner):
    """Reference implementation of the BaseScanner contract.

    Emits XML on stdout (-oX -) so parse_output stays a pure function of a
    string, which means it can be tested against recorded output without
    nmap installed and without touching the network.
    """

    binary_name = "nmap"

    def build_command(self, target: str) -> list[str]:
        return [self.binary_name, "-sV", "-oX", "-", target]

    def parse_output(self, raw_output: str) -> list[Finding]:
        root = ET.fromstring(raw_output)
        findings: list[Finding] = []

        for host in root.iterfind("host"):
            address = self._address(host)
            for port in host.iterfind("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                findings.append(self._finding(address, port))

        return findings

    @staticmethod
    def _address(host: ET.Element) -> str:
        hostname = host.find("hostnames/hostname")
        if hostname is not None and hostname.get("name"):
            return hostname.get("name", "")
        address = host.find("address")
        return address.get("addr", "unknown") if address is not None else "unknown"

    @staticmethod
    def _finding(address: str, port: ET.Element) -> Finding:
        portid = port.get("portid", "?")
        protocol = port.get("protocol", "tcp")
        service_el = port.find("service")
        service = (
            service_el.get("name", "unknown") if service_el is not None else "unknown"
        )
        product = " ".join(
            filter(
                None,
                [
                    service_el.get("product") if service_el is not None else None,
                    service_el.get("version") if service_el is not None else None,
                ],
            )
        )

        severity = _RISKY_SERVICES.get(service, Severity.INFO)
        rule_id = (
            "nmap/insecure-service"
            if severity is not Severity.INFO
            else "nmap/open-port"
        )
        message = f"{address}:{portid}/{protocol} open — {service}"
        if product:
            message = f"{message} ({product})"

        return Finding(
            rule_id=rule_id,
            message=message,
            severity=severity,
            raw=ET.tostring(port, encoding="unicode").strip(),
        )
