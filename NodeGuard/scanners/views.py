from django.shortcuts import redirect, render

from .models import Scan
from .tasks import run_scan


def scan_list(request):
    return render(request, "scanners/scan_list.html", {"scans": _recent_scans()})


def scan_rows(request):
    return render(request, "scanners/_scan_rows.html", {"scans": _recent_scans()})


def trigger_demo_scan(request):
    if request.method == "POST":
        scan = Scan.objects.create(target="127.0.0.1", scanner_name="demo")
        run_scan(scan.id)
    return redirect("scanners:list")


def _recent_scans():
    return Scan.objects.order_by("-created_at").prefetch_related("findings")[:20]
