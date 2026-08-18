from django.apps import AppConfig


class ScannersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanners"

    def ready(self):
        from . import demo_scanner, nmap_scanner  # noqa: F401  register via decorator
