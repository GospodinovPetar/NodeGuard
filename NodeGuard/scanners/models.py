from django.db import models


class Target(models.Model):
    value = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.value


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
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.scanner_name} -> {self.target} ({self.status})"


class Finding(models.Model):
    scan = models.ForeignKey(Scan, related_name="findings", on_delete=models.CASCADE)
    rule_id = models.CharField(max_length=100)
    message = models.TextField()
    severity = models.CharField(max_length=20)
    raw = models.TextField(blank=True)

    def __str__(self) -> str:
        return f"[{self.severity}] {self.rule_id}"
