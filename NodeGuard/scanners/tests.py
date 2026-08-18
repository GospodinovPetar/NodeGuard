import shutil
import subprocess
import unittest
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from .base import Severity, TargetValidationError
from .models import Scan
from .nmap_scanner import NmapScanner
from .registry import get_scanner, list_scanners, tool_status
from .tasks import run_scan

FIXTURES = Path(__file__).parent / "fixtures"


class RegistryTests(TestCase):
    def test_demo_scanner_is_registered(self):
        self.assertIn("demo", list_scanners())

    def test_demo_scanner_is_available(self):
        self.assertTrue(get_scanner("demo").is_available())

    def test_nmap_scanner_is_registered(self):
        self.assertIn("nmap", list_scanners())

    def test_tool_status_reports_every_registered_tool(self):
        statuses = {status.name: status for status in tool_status()}

        self.assertEqual(set(statuses), set(list_scanners()))
        self.assertTrue(statuses["demo"].available)
        self.assertEqual(statuses["nmap"].binary_name, "nmap")

    def test_tool_status_available_follows_path_lookup(self):
        # nmap may or may not be installed on this machine, so assert the
        # relationship rather than the outcome.
        for status in tool_status():
            self.assertEqual(status.available, status.path is not None)


class TargetValidationTests(SimpleTestCase):
    def setUp(self):
        self.scanner = NmapScanner()

    def test_accepts_hostnames_ips_and_cidr(self):
        for target in ["127.0.0.1", "localhost", "scanme.nmap.org", "10.0.0.0/24"]:
            with self.subTest(target=target):
                self.assertEqual(self.scanner.validate_target(target), target)

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(self.scanner.validate_target("  127.0.0.1 "), "127.0.0.1")

    def test_rejects_argument_injection(self):
        # argv lists block shell injection; these would be read by nmap as flags.
        for target in ["-oN /etc/crontab", "--script=http-shellshock", "-"]:
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    self.scanner.validate_target(target)

    def test_rejects_shell_metacharacters_and_spaces(self):
        for target in ["127.0.0.1; rm -rf /", "$(whoami)", "a b", "`id`", ""]:
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    self.scanner.validate_target(target)

    def test_rejects_overlong_target(self):
        with self.assertRaises(TargetValidationError):
            self.scanner.validate_target("a" * 256)


class NmapCommandTests(SimpleTestCase):
    def test_command_requests_xml_on_stdout_with_target_last(self):
        command = NmapScanner().build_command("127.0.0.1")

        self.assertEqual(command, ["nmap", "-sV", "-oX", "-", "127.0.0.1"])


class NmapParseTests(SimpleTestCase):
    def setUp(self):
        raw = (FIXTURES / "nmap_localhost.xml").read_text(encoding="utf-8")
        self.findings = NmapScanner().parse_output(raw)

    def test_reports_only_open_ports(self):
        # 443 is closed and 3306 is filtered — neither should surface.
        self.assertEqual(len(self.findings), 3)
        self.assertNotIn("443", " ".join(f.message for f in self.findings))
        self.assertNotIn("3306", " ".join(f.message for f in self.findings))

    def test_uses_hostname_and_service_banner_in_message(self):
        ssh = self.findings[0]

        self.assertEqual(
            ssh.message, "localhost:22/tcp open — ssh (OpenSSH 8.9p1 Ubuntu 3ubuntu0.4)"
        )
        self.assertEqual(ssh.rule_id, "nmap/open-port")
        self.assertEqual(ssh.severity, Severity.INFO)

    def test_flags_cleartext_service_as_insecure(self):
        telnet = self.findings[1]

        self.assertEqual(telnet.rule_id, "nmap/insecure-service")
        self.assertEqual(telnet.severity, Severity.HIGH)

    def test_keeps_raw_xml_for_the_port(self):
        self.assertIn('portid="22"', self.findings[0].raw)

    def test_empty_scan_produces_no_findings(self):
        raw = '<?xml version="1.0"?><nmaprun><runstats/></nmaprun>'

        self.assertEqual(NmapScanner().parse_output(raw), [])


@unittest.skipUnless(
    shutil.which("nmap"), "nmap not installed — runs in the Docker image"
)
class NmapLiveTests(SimpleTestCase):
    """Drives the real binary against localhost only.

    The fixture tests pin our parsing rules; this one catches nmap itself
    changing its XML schema out from under them.
    """

    def test_parses_real_nmap_output(self):
        scanner = NmapScanner()
        command = scanner.build_command(scanner.validate_target("127.0.0.1"))

        result = subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=False
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("<nmaprun", result.stdout)
        for finding in scanner.parse_output(result.stdout):
            self.assertTrue(finding.message)
            self.assertIsInstance(finding.severity, Severity)


class RunScanTests(TestCase):
    def test_run_scan_produces_a_finding(self):
        scan = Scan.objects.create(target="127.0.0.1", scanner_name="demo")

        run_scan(scan.id)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.DONE)
        self.assertEqual(scan.findings.count(), 1)
        self.assertEqual(scan.findings.first().severity, "info")

    def test_run_scan_rejects_a_malicious_target_without_running_the_tool(self):
        scan = Scan.objects.create(target="127.0.0.1 -oN /tmp/pwn", scanner_name="demo")

        run_scan(scan.id)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.FAILED)
        self.assertIn("refusing to scan target", scan.error)
        self.assertEqual(scan.findings.count(), 0)
