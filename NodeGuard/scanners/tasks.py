from __future__ import annotations

import subprocess

from django.utils import timezone
from huey.contrib.djhuey import db_task

from .models import Finding, Scan
from .registry import get_scanner


@db_task()
def run_scan(scan_id: int) -> None:
    scan = Scan.objects.get(pk=scan_id)
    scanner = get_scanner(scan.scanner_name)

    scan.status = Scan.Status.RUNNING
    scan.save(update_fields=["status"])

    try:
        command = scanner.build_command(scanner.validate_target(scan.target))
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=600, check=False
        )
        findings = scanner.parse_output(result.stdout)
        Finding.objects.bulk_create(
            Finding(
                scan=scan,
                rule_id=f.rule_id,
                message=f.message,
                severity=f.severity.value,
                raw=f.raw,
            )
            for f in findings
        )
        scan.status = Scan.Status.DONE
    except Exception as exc:  # noqa: BLE001 — surface any failure on the Scan row
        scan.status = Scan.Status.FAILED
        scan.error = str(exc)
    finally:
        scan.finished_at = timezone.now()
        scan.save()
