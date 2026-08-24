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
        options = dict(scan.options or {})
        if scan.wordlist:
            options["wordlist_path"] = scan.wordlist.path
        command = scanner.build_command(
            scanner.validate_target(scan.target.value), options
        )
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
        if result.returncode == 0:
            scan.status = Scan.Status.DONE
        else:
            # A tool that refuses to run writes to stderr and exits non-zero
            # while stdout stays empty — e.g. gobuster bailing out when the
            # server answers 200 for every path. Trusting stdout alone stored
            # that as DONE with no findings, which reads as "target is clean"
            # rather than "the scan never happened". Findings parsed so far
            # are kept as evidence, but the run is not treated as a result:
            # FAILED scans are excluded from Target.latest_scans(), so a
            # broken run can't supersede an earlier good one.
            scan.status = Scan.Status.FAILED
            reason = (
                result.stderr.strip()
                or f"{scan.scanner_name} exited with code {result.returncode}"
            )
            scan.error = reason[:2000]
    except Exception as exc:  # noqa: BLE001 — surface any failure on the Scan row
        scan.status = Scan.Status.FAILED
        scan.error = str(exc)
    finally:
        scan.finished_at = timezone.now()
        scan.save()
