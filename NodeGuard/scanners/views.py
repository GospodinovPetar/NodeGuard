from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from .models import Scan, Target
from .registry import list_scanners, tool_status
from .tasks import run_scan

MAX_WORDLIST_BYTES = 2 * 1024 * 1024


class ScanOptionError(ValueError):
    pass


def scan_list(request):
    context = {"scans": _recent_scans(), "tools": tool_status()}
    return render(request, "scanners/scan_list.html", context)


def scan_rows(request):
    return render(request, "scanners/_scan_rows.html", {"scans": _recent_scans()})


def trigger_scan(request):
    if request.method == "POST":
        error = _start_scan(request)
        if error:
            messages.error(request, error)
    return redirect("scanners:list")


def _start_scan(request) -> str | None:
    target_value = request.POST.get("target", "").strip()
    scanner_name = request.POST.get("scanner", "").strip()
    scanners = list_scanners()

    if not target_value:
        return "Target е задължителен."
    if scanner_name not in scanners:
        return "Непознат scanner."
    if not scanners[scanner_name].is_available():
        return f"'{scanner_name}' не е инсталиран на тази машина."

    try:
        options, wordlist = _collect_scan_options(request, scanner_name)
    except ScanOptionError as exc:
        return str(exc)

    target, _ = Target.objects.get_or_create(value=target_value)
    scan = Scan.objects.create(
        target=target,
        scanner_name=scanner_name,
        options=options,
        wordlist=wordlist,
    )
    run_scan(scan.id)
    return None


def target_detail(request, pk):
    target = get_object_or_404(
        Target.objects.prefetch_related("scans__findings"), pk=pk
    )
    context = {
        "target": target,
        "current_severity": target.current_severity,
        "current_findings": target.current_findings,
        "current_scan_ids": {scan.id for scan in target.latest_scans},
        "scans": target.scans_newest_first,
    }
    return render(request, "scanners/target_detail.html", context)


def _collect_scan_options(request, scanner_name):
    if scanner_name == "nmap":
        options = {
            "service_detection": "nmap_sv" in request.POST,
            "aggressive": "nmap_a" in request.POST,
        }
        return options, None

    if scanner_name == "gobuster":
        wordlist = request.FILES.get("wordlist")
        if wordlist is None:
            return {}, None
        if not wordlist.name.lower().endswith(".txt"):
            raise ScanOptionError("Wordlist-ът трябва да е .txt файл.")
        if wordlist.size > MAX_WORDLIST_BYTES:
            raise ScanOptionError("Wordlist-ът е твърде голям (макс. 2 MB).")
        return {}, wordlist

    return {}, None


def _recent_scans():
    return (
        Scan.objects.select_related("target")
        .prefetch_related("findings")
        .order_by("-created_at")[:20]
    )
