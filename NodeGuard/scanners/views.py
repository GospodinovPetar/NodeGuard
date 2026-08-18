from django.contrib import messages
from django.shortcuts import redirect, render

from .models import Scan, Target
from .registry import list_scanners
from .tasks import run_scan


def scan_list(request):
    context = {"scans": _recent_scans(), "scanners": list_scanners()}
    return render(request, "scanners/scan_list.html", context)


def scan_rows(request):
    return render(request, "scanners/_scan_rows.html", {"scans": _recent_scans()})


def trigger_scan(request):
    if request.method == "POST":
        target_value = request.POST.get("target", "").strip()
        scanner_name = request.POST.get("scanner", "").strip()
        scanners = list_scanners()

        if not target_value:
            messages.error(request, "Target е задължителен.")
        elif scanner_name not in scanners:
            messages.error(request, "Непознат scanner.")
        elif not scanners[scanner_name].is_available():
            messages.error(request, f"'{scanner_name}' не е инсталиран на тази машина.")
        else:
            target, _ = Target.objects.get_or_create(value=target_value)
            scan = Scan.objects.create(target=target, scanner_name=scanner_name)
            run_scan(scan.id)

    return redirect("scanners:list")


def _recent_scans():
    return (
        Scan.objects.select_related("target")
        .prefetch_related("findings")
        .order_by("-created_at")[:20]
    )
