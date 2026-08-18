from django.apps import AppConfig


class ScannersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanners"

    def ready(self):
        from . import demo_scanner  # noqa: F401  registers via decorator
