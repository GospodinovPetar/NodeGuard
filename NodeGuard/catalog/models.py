from django.db import models


class ToolState(models.Model):
    """Catalog on/off switch for a registered scanner.

    A tool with no row is enabled by default, so the catalog only stores the
    exceptions (tools a user has switched off). Persisting this server-side —
    rather than in the browser — is what lets the dashboard and the scan form
    reflect the choice. Availability (whether the binary is installed) is a
    separate, runtime concern handled by tool_status().
    """

    name = models.CharField(max_length=100, unique=True)
    enabled = models.BooleanField(default=True)

    def __str__(self) -> str:
        return f"{self.name} ({'on' if self.enabled else 'off'})"

    @classmethod
    def disabled_names(cls) -> set[str]:
        return set(cls.objects.filter(enabled=False).values_list("name", flat=True))
