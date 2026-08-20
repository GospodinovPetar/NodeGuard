import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import (
    RequestFactory,
    SimpleTestCase,
    TestCase,
    override_settings,
)
from django.urls import reverse

from . import severity_rules
from .base import Severity, TargetValidationError
from .gobuster_scanner import WORDLIST_PATH, GobusterScanner
from .models import Finding, Scan, SecurityProfile, Target
from .nmap_scanner import NmapScanner
from .registry import available_scanners, get_scanner, list_scanners, tool_status
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
            "/images               (Status: 200) [Size: 1234]\n"
            "/login                (Status: 301) [Size: 0]\n"
            "not a result line\n"
        )
        findings = self.scanner.parse_output(raw)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].message, "/images (Status: 200)")
        self.assertEqual(
            findings[0].raw, "/images               (Status: 200) [Size: 1234]"
        )
        self.assertEqual(findings[1].message, "/login (Status: 301)")

    def test_parse_output_classifies_through_the_shared_ruleset(self):
        raw = "/.env (Status: 200)\n/images (Status: 200)\n"

        findings = self.scanner.parse_output(raw)

        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].rule_id, "gobuster/exposed-secret")
        self.assertEqual(findings[1].severity, Severity.LOW)
        self.assertEqual(findings[1].rule_id, "gobuster/discovered-path")


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


class SeverityOrderingTests(SimpleTestCase):
    def test_rank_orders_critical_before_info(self):
        self.assertLess(Severity.CRITICAL.rank, Severity.INFO.rank)
        ranks = [s.rank for s in Severity]
        self.assertEqual(ranks, sorted(ranks))

    def test_parse_is_total_for_unknown_values(self):
        self.assertEqual(Severity.parse("HIGH"), Severity.HIGH)
        self.assertIsNone(Severity.parse("bogus"))

    def test_worst_picks_the_most_serious(self):
        self.assertEqual(Severity.worst(["info", "high", "low"]), Severity.HIGH)

    def test_worst_ignores_unknown_and_empty(self):
        self.assertEqual(Severity.worst(["bogus", "low"]), Severity.LOW)
        self.assertIsNone(Severity.worst([]))
        self.assertIsNone(Severity.worst(["bogus"]))


class TargetAggregationTests(TestCase):
    def setUp(self):
        self.target = Target.objects.create(value="10.0.0.5")

    def _scan(self, scanner_name, severities, status=Scan.Status.DONE):
        scan = Scan.objects.create(
            target=self.target, scanner_name=scanner_name, status=status
        )
        for severity in severities:
            Finding.objects.create(
                scan=scan, rule_id="r", message="m", severity=severity
            )
        return scan

    def test_no_scans_means_no_severity(self):
        self.assertIsNone(self.target.current_severity())
        self.assertEqual(self.target.latest_scans(), [])

    def test_severity_is_the_worst_current_finding(self):
        self._scan("nmap", ["info", "high", "low"])

        self.assertEqual(self.target.current_severity(), "high")

    def test_rescanning_clears_a_fixed_finding(self):
        # The whole point of scoping to latest_scans(): fix telnet, rescan,
        # and the target must stop reporting high.
        self._scan("nmap", ["high"])
        self._scan("nmap", ["info"])

        self.assertEqual(self.target.current_severity(), "info")
        self.assertEqual(len(self.target.latest_scans()), 1)

    def test_keeps_newest_result_from_each_scanner(self):
        # A later nmap run must not discard gobuster's separate findings.
        self._scan("gobuster", ["medium"])
        self._scan("nmap", ["info"])

        scanners = {s.scanner_name for s in self.target.latest_scans()}
        self.assertEqual(scanners, {"nmap", "gobuster"})
        self.assertEqual(self.target.current_severity(), "medium")

    def test_unfinished_scans_do_not_count(self):
        self._scan("nmap", ["critical"], status=Scan.Status.FAILED)
        self._scan("nmap", ["low"])

        self.assertEqual(self.target.current_severity(), "low")


class TargetDetailViewTests(TestCase):
    def test_shows_current_severity_and_marks_superseded_scans(self):
        target = Target.objects.create(value="10.0.0.9")
        old = Scan.objects.create(
            target=target, scanner_name="nmap", status=Scan.Status.DONE
        )
        Finding.objects.create(
            scan=old, rule_id="old", message="telnet open", severity="high"
        )
        new = Scan.objects.create(
            target=target, scanner_name="nmap", status=Scan.Status.DONE
        )
        Finding.objects.create(
            scan=new, rule_id="new", message="ssh only", severity="info"
        )

        response = self.client.get(reverse("scanners:target_detail", args=[target.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["current_severity"], "info")
        self.assertEqual(response.context["current_scan_ids"], {new.id})
        self.assertContains(response, "superseded")
        # The fixed finding stays visible as history, just not as current.
        self.assertContains(response, "telnet open")

    def test_unknown_target_is_404(self):
        response = self.client.get(reverse("scanners:target_detail", args=[9999]))

        self.assertEqual(response.status_code, 404)


class DashboardTargetsTests(TestCase):
    def test_targets_are_listed_worst_first(self):
        for value, severity in [("a.test", "low"), ("b.test", "critical")]:
            target = Target.objects.create(value=value)
            scan = Scan.objects.create(
                target=target, scanner_name="nmap", status=Scan.Status.DONE
            )
            Finding.objects.create(
                scan=scan, rule_id="r", message="m", severity=severity
            )
        Target.objects.create(value="unscanned.test")

        response = self.client.get(reverse("dashboard:index"))
        rows = response.context["targets"]

        self.assertEqual(
            [r["target"].value for r in rows],
            ["b.test", "a.test", "unscanned.test"],
        )
        self.assertIsNone(rows[-1]["severity"])

    def test_severity_breakdown_excludes_superseded_findings(self):
        # Dashboard must not report a High that no target actually has.
        target = Target.objects.create(value="fixed.test")
        old = Scan.objects.create(
            target=target, scanner_name="nmap", status=Scan.Status.DONE
        )
        Finding.objects.create(scan=old, rule_id="r", message="m", severity="high")
        new = Scan.objects.create(
            target=target, scanner_name="nmap", status=Scan.Status.DONE
        )
        Finding.objects.create(scan=new, rule_id="r", message="m", severity="info")

        response = self.client.get(reverse("dashboard:index"))
        counts = dict(response.context["severity_counts"])

        self.assertEqual(counts["high"], 0)
        self.assertEqual(counts["info"], 1)
        self.assertEqual(response.context["current_findings_count"], 1)


class SeverityRulesOpenPortTests(SimpleTestCase):
    def test_plain_service_is_informational(self):
        rule = severity_rules.open_port("ssh")

        self.assertEqual(rule.severity, Severity.INFO)
        self.assertEqual(rule.rule_id, "nmap/open-port")

    def test_cleartext_credential_services_are_high(self):
        for service in ["telnet", "rlogin", "rsh", "rexec", "vnc"]:
            with self.subTest(service=service):
                rule = severity_rules.open_port(service)

                self.assertEqual(rule.severity, Severity.HIGH)
                self.assertEqual(rule.rule_id, "nmap/insecure-service")

    def test_exposed_datastores_are_medium(self):
        for service in ["mysql", "postgresql", "mongodb", "redis", "microsoft-ds"]:
            with self.subTest(service=service):
                self.assertEqual(
                    severity_rules.open_port(service).severity, Severity.MEDIUM
                )

    def test_service_matching_ignores_case(self):
        self.assertEqual(severity_rules.open_port("TELNET").severity, Severity.HIGH)


class SeverityRulesDiscoveredPathTests(SimpleTestCase):
    def test_readable_secret_material_is_critical(self):
        for path in ["/.env", "/id_rsa", "/.htpasswd", "/credentials"]:
            with self.subTest(path=path):
                rule = severity_rules.discovered_path(path, 200)

                self.assertEqual(rule.severity, Severity.CRITICAL)
                self.assertEqual(rule.rule_id, "gobuster/exposed-secret")

    def test_source_and_diagnostics_exposure_is_high(self):
        for path in ["/.git", "/backup", "/phpinfo.php", "/server-status"]:
            with self.subTest(path=path):
                rule = severity_rules.discovered_path(path, 200)

                self.assertEqual(rule.severity, Severity.HIGH)
                self.assertEqual(rule.rule_id, "gobuster/information-disclosure")

    def test_admin_interfaces_are_medium(self):
        for path in ["/admin", "/wp-admin", "/phpmyadmin", "/console"]:
            with self.subTest(path=path):
                rule = severity_rules.discovered_path(path, 200)

                self.assertEqual(rule.severity, Severity.MEDIUM)
                self.assertEqual(rule.rule_id, "gobuster/exposed-admin-interface")

    def test_any_other_served_path_is_low(self):
        rule = severity_rules.discovered_path("/images", 200)

        self.assertEqual(rule.severity, Severity.LOW)
        self.assertEqual(rule.rule_id, "gobuster/discovered-path")

    def test_protected_secret_is_not_escalated(self):
        for status in [301, 302, 401, 403]:
            with self.subTest(status=status):
                rule = severity_rules.discovered_path("/.env", status)

                self.assertEqual(rule.severity, Severity.INFO)
                self.assertEqual(rule.rule_id, f"gobuster/path-{status}")

    def test_path_matching_survives_gobuster_output_shapes(self):
        for path in ["admin", "/admin", "/ADMIN", "/admin/", "  /admin  "]:
            with self.subTest(path=path):
                self.assertEqual(
                    severity_rules.discovered_path(path, 200).severity,
                    Severity.MEDIUM,
                )


class ModelStringRepresentationTests(TestCase):
    def test_scan_names_scanner_target_and_status(self):
        target = Target.objects.create(value="example.test")
        scan = Scan.objects.create(target=target, scanner_name="nmap")

        self.assertEqual(str(scan), "nmap -> example.test (pending)")

    def test_finding_leads_with_its_severity(self):
        target = Target.objects.create(value="example.test")
        scan = Scan.objects.create(target=target, scanner_name="nmap")
        finding = Finding.objects.create(
            scan=scan, rule_id="nmap/open-port", message="m", severity="info"
        )

        self.assertEqual(str(finding), "[info] nmap/open-port")

    def test_security_profile_is_its_name(self):
        profile = SecurityProfile.objects.create(
            name="Smoke Test Preset", scanner_name="demo"
        )

        self.assertEqual(str(profile), "Smoke Test Preset")


class AvailableScannersTests(SimpleTestCase):
    def test_lists_only_installed_tools(self):
        available = available_scanners()

        self.assertIn("demo", available)
        self.assertEqual(
            set(available),
            {status.name for status in tool_status() if status.available},
        )


class NmapAddressFallbackTests(SimpleTestCase):
    def test_falls_back_to_the_ip_when_there_is_no_hostname(self):
        raw = """<?xml version="1.0"?><nmaprun>
          <host><address addr="203.0.113.5" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="22">
              <state state="open"/><service name="ssh"/>
            </port></ports>
          </host></nmaprun>"""

        findings = NmapScanner().parse_output(raw)

        self.assertIn("203.0.113.5:22/tcp", findings[0].message)

    def test_falls_back_to_unknown_when_there_is_no_address_either(self):
        raw = """<?xml version="1.0"?><nmaprun>
          <host><ports><port protocol="tcp" portid="22">
              <state state="open"/><service name="ssh"/>
          </port></ports></host></nmaprun>"""

        findings = NmapScanner().parse_output(raw)

        self.assertIn("unknown:22/tcp", findings[0].message)


class ScanRowsPartialTests(TestCase):
    def test_renders_the_rows_partial_without_the_page_chrome(self):
        target = Target.objects.create(value="example.test")
        Scan.objects.create(target=target, scanner_name="nmap")

        response = self.client.get(reverse("scanners:rows"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "example.test")
        self.assertNotContains(response, "<nav")


class RunScanWordlistTests(TestCase):
    def setUp(self):
        media_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, media_root, ignore_errors=True)
        override = override_settings(MEDIA_ROOT=media_root)
        override.enable()
        self.addCleanup(override.disable)

    def test_uploaded_wordlist_is_passed_to_the_scanner_as_an_option(self):
        target = Target.objects.create(value="127.0.0.1")
        scan = Scan.objects.create(
            target=target,
            scanner_name="demo",
            wordlist=SimpleUploadedFile("custom.txt", b"admin\nlogin\n"),
        )

        scanner = get_scanner("demo")
        with mock.patch("scanners.tasks.get_scanner", return_value=scanner):
            with mock.patch.object(
                scanner, "build_command", wraps=scanner.build_command
            ) as spy:
                run_scan(scan.id)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.DONE)
        _, options = spy.call_args.args
        self.assertEqual(options["wordlist_path"], scan.wordlist.path)
