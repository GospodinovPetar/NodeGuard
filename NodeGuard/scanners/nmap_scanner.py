from __future__ import annotations

import xml.etree.ElementTree as ET

from . import severity_rules
from .base import BaseScanner, Finding
from .registry import register_scanner


@register_scanner("nmap")
class NmapScanner(BaseScanner):
    """Reference implementation of the BaseScanner contract.

    Emits XML on stdout (-oX -) so parse_output stays a pure function of a
    string, which means it can be tested against recorded output without
    nmap installed and without touching the network.
    """

    binary_name = "nmap"
    profile_options = frozenset({"service_detection", "aggressive"})

    def build_command(self, target: str, options: dict | None = None) -> list[str]:
        options = options or {}
        flags = []
        if options.get("service_detection", True):
            flags.append("-sV")
        if options.get("aggressive"):
            flags.append("-A")
        return [self.binary_name, *flags, "-oX", "-", target]

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

        rule = severity_rules.open_port(service)
        message = f"{address}:{portid}/{protocol} open — {service}"
        if product:
            message = f"{message} ({product})"

        return Finding(
            rule_id=rule.rule_id,
            message=message,
            severity=rule.severity,
            raw=ET.tostring(port, encoding="unicode").strip(),
        )
