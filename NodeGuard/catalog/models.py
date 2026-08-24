import dataclasses

from django.db import models

from scanners.registry import tool_status


@dataclasses.dataclass(frozen=True)
class CatalogTool:
    """A registered scanner as every screen shows it: what it is, whether its
    binary is installed, and whether the catalog has it switched on.

    Registration, availability and catalog state come from three different
    places; joining them here means the dashboard, the catalog and the scan
    form read one shape instead of each re-deriving their own.
    """

    name: str
    binary_name: str
    path: str | None
    available: bool
    disabled: bool

    @property
    def enabled(self) -> bool:
        return not self.disabled


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

    @classmethod
    def catalog_tools(cls) -> list[CatalogTool]:
        """Every registered scanner, joined to its install state and on/off state."""
        disabled = cls.disabled_names()
        return [
            CatalogTool(
                name=status.name,
                binary_name=status.binary_name,
                path=status.path,
                available=status.available,
                disabled=status.name in disabled,
            )
            for status in tool_status()
        ]
