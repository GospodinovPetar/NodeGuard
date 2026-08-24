from django.test import TestCase
from django.urls import reverse

from catalog.models import ToolState
from scanners.models import Scan


class ToolStateModelTests(TestCase):
    def test_a_tool_with_no_row_is_enabled(self):
        self.assertEqual(ToolState.disabled_names(), set())

    def test_disabled_names_lists_only_switched_off_tools(self):
        ToolState.objects.create(name="nmap", enabled=False)
        ToolState.objects.create(name="demo", enabled=True)

        self.assertEqual(ToolState.disabled_names(), {"nmap"})

    def test_str_shows_state(self):
        self.assertEqual(str(ToolState(name="nmap", enabled=False)), "nmap (off)")


class CatalogToggleViewTests(TestCase):
    def test_index_renders_toggle_and_enabled_count(self):
        response = self.client.get(reverse("catalog:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "on ·")  # enabled-count header
        self.assertContains(response, reverse("catalog:toggle", args=["demo"]))

    def test_toggle_requires_post(self):
        response = self.client.get(reverse("catalog:toggle", args=["demo"]))
        self.assertEqual(response.status_code, 405)

    def test_toggle_disables_then_reenables(self):
        self.client.post(reverse("catalog:toggle", args=["demo"]))
        self.assertIn("demo", ToolState.disabled_names())

        self.client.post(reverse("catalog:toggle", args=["demo"]))
        self.assertNotIn("demo", ToolState.disabled_names())

    def test_toggle_rejects_unknown_tool(self):
        self.client.post(reverse("catalog:toggle", args=["bogus"]))
        self.assertEqual(ToolState.objects.count(), 0)


class ToggleReflectionTests(TestCase):
    """The whole point of persisting server-side: the dashboard and scan form
    honour the catalog choice."""

    def test_disabled_tool_is_marked_on_the_dashboard(self):
        ToolState.objects.create(name="demo", enabled=False)

        response = self.client.get(reverse("dashboard:index"))

        marked = {t.name for t in response.context["tools"] if t.disabled}
        self.assertEqual(marked, {"demo"})
        self.assertContains(response, "disabled")

    def test_disabled_tool_drops_from_the_scan_form(self):
        ToolState.objects.create(name="demo", enabled=False)

        response = self.client.get(reverse("scanners:list"))

        names = [tool.name for tool in response.context["tools"]]
        self.assertNotIn("demo", names)

    def test_trigger_rejects_a_disabled_scanner(self):
        ToolState.objects.create(name="demo", enabled=False)

        response = self.client.post(
            reverse("scanners:trigger"), {"target": "127.0.0.1", "scanner": "demo"}
        )

        self.assertEqual(Scan.objects.count(), 0)
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any("изключен в каталога" in str(m) for m in messages))

    def test_trigger_rejects_a_profile_whose_scanner_is_disabled(self):
        ToolState.objects.create(name="nmap", enabled=False)

        response = self.client.post(
            reverse("scanners:trigger"),
            {"target": "example.com", "profile": "quick-scan"},
        )

        self.assertEqual(Scan.objects.count(), 0)
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any("изключен в каталога" in str(m) for m in messages))
