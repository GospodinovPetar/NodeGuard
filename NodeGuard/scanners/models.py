from functools import cached_property

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.text import slugify

from .base import Severity
from .registry import list_scanners


class Target(models.Model):
    value = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.value

    @cached_property
    def scans_newest_first(self) -> list["Scan"]:
        return sorted(
            self.scans.all(), key=lambda s: (s.created_at, s.id), reverse=True
        )

    @cached_property
    def latest_scans(self) -> list["Scan"]:
        newest: dict[str, Scan] = {}
        for scan in self.scans_newest_first:
            if scan.status == Scan.Status.DONE:
                newest.setdefault(scan.scanner_name, scan)
        return list(newest.values())

    @cached_property
    def current_findings(self) -> list["Finding"]:
        return [f for scan in self.latest_scans for f in scan.findings.all()]

    @cached_property
    def current_severity(self) -> str | None:
        worst = Severity.worst(f.severity for f in self.current_findings)
        return worst.value if worst else None


class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"

    target = models.ForeignKey(Target, related_name="scans", on_delete=models.CASCADE)
    scanner_name = models.CharField(max_length=100)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )
    # Scan-type flags (e.g. nmap -sV/-A) chosen in the trigger form. Stored
    # here rather than passed straight into build_command() because the
    # huey worker only receives scan_id — it has to reconstruct `options`
    # from the row when the task actually runs.
    options = models.JSONField(default=dict, blank=True)
    wordlist = models.FileField(upload_to="wordlists/", blank=True, null=True)
    error = models.TextField(blank=True)
    # Indexed: the scan list polls newest-first every 2s from every open tab.
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.scanner_name} -> {self.target} ({self.status})"


class SecurityProfile(models.Model):
    """A named scanner + options bundle, so the user picks "Quick Scan"
    instead of remembering which flags that means.
    """

    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True, blank=True)
    description = models.TextField(blank=True)
    scanner_name = models.CharField(max_length=100)
    options = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        scanners = list_scanners()
        scanner = scanners.get(self.scanner_name)
        if scanner is None:
            raise ValidationError(
                {"scanner_name": f"'{self.scanner_name}' не е регистриран scanner."}
            )

        if not isinstance(self.options, dict):
            raise ValidationError({"options": "options трябва да е JSON обект."})

        # build_command() puts option values into argv, so a profile may only
        # carry keys the scanner has explicitly opted in to. Without this, a
        # profile could set gobuster's wordlist_path to any file on disk and
        # have its contents brute-forced back out as findings.
        unknown = set(self.options) - set(scanner.profile_options)
        if unknown:
            allowed = ", ".join(sorted(scanner.profile_options)) or "(няма)"
            raise ValidationError(
                {
                    "options": (
                        f"'{self.scanner_name}' не приема {sorted(unknown)} "
                        f"като profile options. Позволени: {allowed}."
                    )
                }
            )

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        # Profiles are configuration that later becomes a subprocess argv, so
        # an invalid one must never reach the DB — including when created
        # programmatically, where Django would otherwise skip clean().
        self.full_clean()
        super().save(*args, **kwargs)

    def is_available(self) -> bool:
        scanner = list_scanners().get(self.scanner_name)
        return scanner is not None and scanner.is_available()

    def create_scan(self, target: "Target") -> "Scan":
        """Materialize this preset into a runnable Scan row."""
        return Scan.objects.create(
            target=target,
            scanner_name=self.scanner_name,
            options=dict(self.options),
        )


class Finding(models.Model):
    scan = models.ForeignKey(Scan, related_name="findings", on_delete=models.CASCADE)
    rule_id = models.CharField(max_length=100)
    message = models.TextField()
    severity = models.CharField(max_length=20)
    raw = models.TextField(blank=True)

    def __str__(self) -> str:
        return f"[{self.severity}] {self.rule_id}"

    @classmethod
    def store(cls, scan, findings) -> None:
        """Persist parsed `base.Finding` dataclasses against a Scan.

        Both entry points — a scanner run (tasks.run_scan) and a SARIF upload
        — produce the same dataclasses, so the enum→string conversion lives
        here rather than being rewritten at each call site.
        """
        cls.objects.bulk_create(
            cls(
                scan=scan,
                rule_id=f.rule_id,
                message=f.message,
                severity=f.severity.value,
                raw=f.raw,
            )
            for f in findings
        )
