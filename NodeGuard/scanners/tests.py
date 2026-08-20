import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.urls import reverse

from .base import Severity, TargetValidationError
from .gobuster_scanner import WORDLIST_PATH, GobusterScanner
from .models import Scan, SecurityProfile, Target
from .nmap_scanner import NmapScanner
from .registry import get_scanner, list_scanners, tool_status
from .tasks import run_scan
from .views import MAX_WORDLIST_BYTES, _collect_scan_options

FIXTURES = Path(__file__).parent / "fixtures"


class RegistryTests(TestCase):
    def test_demo_scanner_is_registered(self):
        self.assertIn("demo", list_scanners())

    def test_gobuster_scanner_is_registered(self):
        self.assertIn("gobuster", list_scanners())

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

    def test_no_options_behaves_like_default(self):
        self.assertEqual(
            NmapScanner().build_command("127.0.0.1", None),
            NmapScanner().build_command("127.0.0.1"),
        )

    def test_aggressive_option_adds_dash_a(self):
        command = NmapScanner().build_command("127.0.0.1", {"aggressive": True})

        self.assertEqual(command, ["nmap", "-sV", "-A", "-oX", "-", "127.0.0.1"])

    def test_service_detection_can_be_disabled(self):
        command = NmapScanner().build_command("127.0.0.1", {"service_detection": False})

        self.assertEqual(command, ["nmap", "-oX", "-", "127.0.0.1"])


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


class TargetModelTests(TestCase):
    def test_str_is_the_value(self):
        target = Target.objects.create(value="127.0.0.1")
        self.assertEqual(str(target), "127.0.0.1")

    def test_value_is_unique(self):
        Target.objects.create(value="127.0.0.1")
        with self.assertRaises(Exception):
            Target.objects.create(value="127.0.0.1")


class GobusterScannerTests(TestCase):
    def setUp(self):
        self.scanner = GobusterScanner()

    def test_build_command_prefixes_scheme(self):
        command = self.scanner.build_command("example.com")
        self.assertIn("http://example.com", command)

    def test_build_command_keeps_existing_scheme(self):
        command = self.scanner.build_command("https://example.com")
        self.assertIn("https://example.com", command)

    def test_build_command_uses_bundled_wordlist_by_default(self):
        command = self.scanner.build_command("example.com")
        self.assertIn(str(WORDLIST_PATH), command)

    def test_build_command_uses_custom_wordlist_when_given(self):
        command = self.scanner.build_command(
            "example.com", {"wordlist_path": "/tmp/custom.txt"}
        )

        self.assertIn("/tmp/custom.txt", command)
        self.assertNotIn(str(WORDLIST_PATH), command)

    def test_parse_output_extracts_findings(self):
        raw = (
            "/admin                (Status: 200) [Size: 1234]\n"
            "/login                (Status: 301) [Size: 0]\n"
            "not a result line\n"
        )
        findings = self.scanner.parse_output(raw)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity.value, "low")
        self.assertEqual(findings[1].severity.value, "info")


class RunScanTests(TestCase):
    def test_run_scan_produces_a_finding(self):
        target = Target.objects.create(value="127.0.0.1")
        scan = Scan.objects.create(target=target, scanner_name="demo")

        run_scan(scan.id)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.DONE)
        self.assertEqual(scan.findings.count(), 1)
        self.assertEqual(scan.findings.first().severity, "info")

    def test_run_scan_rejects_a_malicious_target_without_running_the_tool(self):
        target = Target.objects.create(value="127.0.0.1 -oN /tmp/pwn")
        scan = Scan.objects.create(target=target, scanner_name="demo")

        run_scan(scan.id)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.FAILED)
        self.assertIn("refusing to scan target", scan.error)
        self.assertEqual(scan.findings.count(), 0)


class TriggerScanViewTests(TestCase):
    def test_valid_submission_creates_scan(self):
        response = self.client.post(
            reverse("scanners:trigger"), {"target": "127.0.0.1", "scanner": "demo"}
        )

        self.assertRedirects(response, reverse("scanners:list"))
        self.assertEqual(Scan.objects.count(), 1)
        self.assertEqual(Scan.objects.first().target.value, "127.0.0.1")

    def test_missing_target_creates_no_scan(self):
        self.client.post(reverse("scanners:trigger"), {"target": "", "scanner": "demo"})

        self.assertEqual(Scan.objects.count(), 0)

    def test_unregistered_scanner_creates_no_scan(self):
        response = self.client.post(
            reverse("scanners:trigger"),
            {"target": "example.com", "scanner": "not-a-real-scanner"},
        )

        self.assertEqual(Scan.objects.count(), 0)
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any("Непознат scanner" in str(m) for m in messages))

    def test_uninstalled_scanner_creates_no_scan(self):
        # Which real tools are installed varies by machine (bare host vs. the
        # Docker image with nmap/gobuster baked in), so this stubs
        # is_available() instead of relying on gobuster actually being
        # missing — that assumption broke the moment it got baked into the
        # image and made this test flaky by environment.
        fake_scanner = mock.Mock(is_available=mock.Mock(return_value=False))
        with mock.patch(
            "scanners.views.list_scanners", return_value={"gobuster": fake_scanner}
        ):
            response = self.client.post(
                reverse("scanners:trigger"),
                {"target": "example.com", "scanner": "gobuster"},
            )

        self.assertEqual(Scan.objects.count(), 0)
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any("не е инсталиран" in str(m) for m in messages))

    def test_gobuster_wordlist_upload_is_saved_on_the_scan(self):
        # is_available() is stubbed and run_scan is a no-op: this test is
        # about the view saving the upload correctly, not about a real
        # gobuster binary being on PATH or hitting the network.
        fake_scanner = mock.Mock(is_available=mock.Mock(return_value=True))
        upload = SimpleUploadedFile(
            "custom.txt", b"admin\nlogin\n", content_type="text/plain"
        )

        with (
            mock.patch(
                "scanners.views.list_scanners",
                return_value={"gobuster": fake_scanner},
            ),
            mock.patch("scanners.views.run_scan"),
        ):
            response = self.client.post(
                reverse("scanners:trigger"),
                {"target": "example.com", "scanner": "gobuster", "wordlist": upload},
            )

        self.assertRedirects(response, reverse("scanners:list"))
        scan = Scan.objects.get()
        self.assertTrue(scan.wordlist.name.endswith("custom.txt"))
        scan.wordlist.delete(save=False)

    def test_gobuster_rejected_wordlist_creates_no_scan(self):
        fake_scanner = mock.Mock(is_available=mock.Mock(return_value=True))
        upload = SimpleUploadedFile("custom.csv", b"admin\n", content_type="text/csv")

        with mock.patch(
            "scanners.views.list_scanners", return_value={"gobuster": fake_scanner}
        ):
            response = self.client.post(
                reverse("scanners:trigger"),
                {"target": "example.com", "scanner": "gobuster", "wordlist": upload},
            )

        self.assertEqual(Scan.objects.count(), 0)
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any(".txt" in str(m) for m in messages))


class CollectScanOptionsTests(SimpleTestCase):
    """Unit-tests the trigger view's option parsing directly, so nmap/
    gobuster-specific behavior doesn't depend on those tools actually being
    installed (bare host vs. Docker image) the way TriggerScanViewTests'
    end-to-end cases have to work around.
    """

    def setUp(self):
        self.factory = RequestFactory()

    def test_nmap_reads_checkbox_flags(self):
        request = self.factory.post("/trigger/", {"nmap_a": "on"})

        options, wordlist, error = _collect_scan_options(request, "nmap")

        self.assertEqual(options, {"service_detection": False, "aggressive": True})
        self.assertIsNone(wordlist)
        self.assertIsNone(error)

    def test_nmap_defaults_to_false_when_no_checkboxes_submitted(self):
        request = self.factory.post("/trigger/", {})

        options, _, _ = _collect_scan_options(request, "nmap")

        self.assertEqual(options, {"service_detection": False, "aggressive": False})

    def test_gobuster_without_upload_uses_bundled_wordlist(self):
        request = self.factory.post("/trigger/", {})

        options, wordlist, error = _collect_scan_options(request, "gobuster")

        self.assertEqual((options, wordlist, error), ({}, None, None))

    def test_gobuster_accepts_txt_upload_under_size_limit(self):
        upload = SimpleUploadedFile(
            "custom.txt", b"admin\nlogin\n", content_type="text/plain"
        )
        request = self.factory.post("/trigger/", {"wordlist": upload})

        options, wordlist, error = _collect_scan_options(request, "gobuster")

        self.assertEqual(options, {})
        self.assertEqual(wordlist.name, "custom.txt")
        self.assertIsNone(error)

    def test_gobuster_rejects_non_txt_extension(self):
        upload = SimpleUploadedFile("custom.csv", b"admin\n", content_type="text/csv")
        request = self.factory.post("/trigger/", {"wordlist": upload})

        options, wordlist, error = _collect_scan_options(request, "gobuster")

        self.assertIsNone(options)
        self.assertIsNone(wordlist)
        self.assertIn(".txt", error)

    def test_gobuster_rejects_oversized_upload(self):
        upload = SimpleUploadedFile(
            "big.txt", b"x" * (MAX_WORDLIST_BYTES + 1), content_type="text/plain"
        )
        request = self.factory.post("/trigger/", {"wordlist": upload})

        options, wordlist, error = _collect_scan_options(request, "gobuster")

        self.assertIsNone(options)
        self.assertIsNone(wordlist)
        self.assertIn("голям", error)

    def test_unknown_scanner_gets_empty_options(self):
        request = self.factory.post("/trigger/", {})

        result = _collect_scan_options(request, "demo")

        self.assertEqual(result, ({}, None, None))


class CatalogIndexViewTests(TestCase):
    def test_lists_every_registered_scanner_with_availability(self):
        response = self.client.get(reverse("catalog:index"))
        statuses = tool_status()

        self.assertEqual(response.status_code, 200)
        for status in statuses:
            self.assertContains(response, status.name)
        # demo's binary is sys.executable, so it's always installed — the
        # count in the header should reflect that regardless of host.
        available = sum(1 for s in statuses if s.available)
        self.assertContains(response, f"{available}/{len(statuses)} available")
        self.assertContains(response, "installed")


class SecurityProfileTests(TestCase):
    def test_builtin_profiles_are_seeded_by_migration(self):
        slugs = set(SecurityProfile.objects.values_list("slug", flat=True))

        self.assertIn("quick-scan", slugs)
        self.assertIn("deep-web-scan", slugs)

    def test_builtin_profiles_reference_registered_scanners(self):
        for profile in SecurityProfile.objects.all():
            with self.subTest(profile=profile.slug):
                self.assertIn(profile.scanner_name, list_scanners())
                profile.full_clean()

    def test_quick_scan_carries_nmap_flags(self):
        profile = SecurityProfile.objects.get(slug="quick-scan")

        self.assertEqual(profile.scanner_name, "nmap")
        self.assertEqual(
            NmapScanner().build_command("127.0.0.1", profile.options),
            ["nmap", "-sV", "-oX", "-", "127.0.0.1"],
        )

    def test_slug_is_derived_from_name_when_blank(self):
        profile = SecurityProfile.objects.create(name="My Scan", scanner_name="demo")

        self.assertEqual(profile.slug, "my-scan")

    def test_create_scan_copies_options_onto_the_scan(self):
        target = Target.objects.create(value="127.0.0.1")
        profile = SecurityProfile.objects.get(slug="quick-scan")

        scan = profile.create_scan(target)

        self.assertEqual(scan.scanner_name, "nmap")
        self.assertEqual(scan.options, profile.options)
        # A copy, so later edits to the profile don't rewrite scan history.
        self.assertIsNot(scan.options, profile.options)

    def test_unregistered_scanner_is_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            SecurityProfile.objects.create(name="Bogus", scanner_name="not-a-scanner")

        self.assertIn("scanner_name", ctx.exception.message_dict)

    def test_option_key_the_scanner_did_not_opt_into_is_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            SecurityProfile.objects.create(
                name="Sneaky", scanner_name="nmap", options={"made_up": True}
            )

        self.assertIn("options", ctx.exception.message_dict)

    def test_profile_cannot_point_gobuster_at_an_arbitrary_file(self):
        # build_command() drops wordlist_path straight into argv, so a stored
        # profile must not be able to set it — otherwise a profile could make
        # gobuster read /etc/passwd and surface matching lines as findings.
        with self.assertRaises(ValidationError) as ctx:
            SecurityProfile.objects.create(
                name="Exfil",
                scanner_name="gobuster",
                options={"wordlist_path": "/etc/passwd"},
            )

        self.assertIn("options", ctx.exception.message_dict)

    def test_non_dict_options_are_rejected(self):
        with self.assertRaises(ValidationError):
            SecurityProfile.objects.create(
                name="Listy", scanner_name="nmap", options=["-A"]
            )

    def test_is_available_follows_the_underlying_scanner(self):
        profile = SecurityProfile.objects.create(name="Demo run", scanner_name="demo")

        self.assertTrue(profile.is_available())
