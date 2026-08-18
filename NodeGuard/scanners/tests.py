from django.test import TestCase

from .models import Scan
from .registry import get_scanner, list_scanners
from .tasks import run_scan


class RegistryTests(TestCase):
    def test_demo_scanner_is_registered(self):
        self.assertIn("demo", list_scanners())

    def test_demo_scanner_is_available(self):
        self.assertTrue(get_scanner("demo").is_available())


class RunScanTests(TestCase):
    def test_run_scan_produces_a_finding(self):
        scan = Scan.objects.create(target="127.0.0.1", scanner_name="demo")

        run_scan(scan.id)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.DONE)
        self.assertEqual(scan.findings.count(), 1)
        self.assertEqual(scan.findings.first().severity, "info")
