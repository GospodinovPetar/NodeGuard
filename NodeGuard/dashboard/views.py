from collections import Counter

from django.db.models import Count
from django.shortcuts import render

from scanners.base import Severity
from scanners.models import Scan, Target
from scanners.registry import tool_status

_STATUSES = ["pending", "running", "done", "failed"]


def index(request):
    status_counts = dict(
        Scan.objects.values_list("status")
        .annotate(n=Count("id"))
        .values_list("status", "n")
    )

    rows = _targets_by_risk()
    # Counted over *current* findings only, matching the per-target severity
    # column. Counting every Finding row ever would let a fixed issue keep
    # inflating the breakdown forever, so the same page would report a High
    # that no target actually has.
    severity_counts = Counter(
        f.severity for row in rows for f in row["current_findings"]
    )

    statuses = tool_status()
    context = {
        "total_targets": Target.objects.count(),
        "total_scans": Scan.objects.count(),
        "current_findings_count": sum(severity_counts.values()),
        "status_counts": [(s, status_counts.get(s, 0)) for s in _STATUSES],
        "severity_counts": [
            (s.value, severity_counts.get(s.value, 0)) for s in Severity
        ],
        "tools": statuses,
        "tools_available": sum(1 for s in statuses if s.available),
        "targets": rows,
    }
    return render(request, "dashboard/index.html", context)


def _targets_by_risk():
    """Targets worst-first, so the riskiest asset leads the dashboard instead
    of whatever happened to be scanned most recently."""
    rows = []
    for target in Target.objects.prefetch_related("scans__findings"):
        current_findings = target.current_findings()
        rows.append(
            {
                "target": target,
                "severity": target.current_severity(),
                "current_findings": current_findings,
                "scan_count": target.scans.count(),
                "last_scan": target.scans.order_by("-created_at").first(),
            }
        )

    # Clean/unscanned targets have no severity — they sort after anything
    # carrying an actual finding.
    def sort_key(row):
        severity = Severity.parse(row["severity"]) if row["severity"] else None
        return (severity.rank if severity else len(Severity), row["target"].value)

    return sorted(rows, key=sort_key)
