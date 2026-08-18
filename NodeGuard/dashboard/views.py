from django.db.models import Count
from django.shortcuts import render

from scanners.models import Finding, Scan
from scanners.registry import tool_status

# Severities ordered most→least serious, so the dashboard breakdown always
# renders in a stable, meaningful order.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_STATUSES = ["pending", "running", "done", "failed"]


def index(request):
    status_counts = dict(
        Scan.objects.values_list("status")
        .annotate(n=Count("id"))
        .values_list("status", "n")
    )
    severity_counts = dict(
        Finding.objects.values_list("severity")
        .annotate(n=Count("id"))
        .values_list("severity", "n")
    )

    statuses = tool_status()
    context = {
        "total_scans": Scan.objects.count(),
        "total_findings": Finding.objects.count(),
        "status_counts": [(s, status_counts.get(s, 0)) for s in _STATUSES],
        "severity_counts": [(s, severity_counts.get(s, 0)) for s in _SEVERITY_ORDER],
        "tools": statuses,
        "tools_available": sum(1 for s in statuses if s.available),
        "recent_scans": (
            Scan.objects.select_related("target")
            .prefetch_related("findings")
            .order_by("-created_at")[:5]
        ),
    }
    return render(request, "dashboard/index.html", context)
