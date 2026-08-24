from collections import Counter
from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import render
from django.utils import timezone

from catalog.models import ToolState
from scanners.base import Severity
from scanners.models import Scan, Target
from scanners.registry import tool_status

TREND_DAYS = 14


def index(request):
    status_counts = Counter(Scan.objects.values_list("status", flat=True))
    rows = _targets_by_risk()
    severity_counts = Counter(
        f.severity for row in rows for f in row["target"].current_findings
    )

    statuses = tool_status()
    context = {
        "total_targets": len(rows),
        "total_scans": sum(status_counts.values()),
        "current_findings_count": sum(severity_counts.values()),
        "running_count": status_counts.get(Scan.Status.RUNNING, 0),
        "status_counts": [(s, status_counts.get(s, 0)) for s in Scan.Status.values],
        "severity_counts": [
            (s.value, severity_counts.get(s.value, 0)) for s in Severity
        ],
        "scan_trend": _scan_trend(),
        "tools": statuses,
        "tools_available": sum(1 for s in statuses if s.available),
        "disabled_tools": ToolState.disabled_names(),
        "targets": rows,
    }
    return render(request, "dashboard/index.html", context)


def _scan_trend(days: int = TREND_DAYS):
    """Scans-per-day over the last `days`, as a gap-free series so the line
    chart renders continuous dates even on days with zero scans."""
    start = timezone.localdate() - timedelta(days=days - 1)
    per_day = dict(
        Scan.objects.filter(created_at__date__gte=start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(n=Count("id"))
        .values_list("day", "n")
    )
    series = []
    for i in range(days):
        day = start + timedelta(days=i)
        series.append({"date": day.strftime("%b %d"), "count": per_day.get(day, 0)})
    return series


def _targets_by_risk():
    targets = Target.objects.prefetch_related("scans__findings").annotate(
        scan_count=Count("scans", distinct=True)
    )
    rows = [
        {
            "target": target,
            "severity": target.current_severity,
            "scan_count": target.scan_count,
            "last_scan": next(iter(target.scans_newest_first), None),
        }
        for target in targets
    ]

    def sort_key(row):
        severity = Severity.parse(row["severity"]) if row["severity"] else None
        return (severity.rank if severity else len(Severity), row["target"].value)

    return sorted(rows, key=sort_key)
