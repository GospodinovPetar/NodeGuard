from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from .models import Scan, Target
from .registry import list_scanners
from .tasks import run_scan

MAX_WORDLIST_BYTES = 2 * 1024 * 1024  # user-uploaded gobuster wordlists


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
            options, wordlist, error = _collect_scan_options(request, scanner_name)
            if error:
                messages.error(request, error)
            else:
                target, _ = Target.objects.get_or_create(value=target_value)
                scan = Scan.objects.create(
                    target=target,
                    scanner_name=scanner_name,
                    options=options,
                    wordlist=wordlist,
                )
                run_scan(scan.id)

    return redirect("scanners:list")


def target_detail(request, pk):
    """Everything known about one asset: its current risk, plus the full
    scan history behind that verdict."""
    target = get_object_or_404(
        Target.objects.prefetch_related("scans__findings"), pk=pk
    )
    current_scan_ids = {scan.id for scan in target.latest_scans()}

    context = {
        "target": target,
        "current_severity": target.current_severity(),
        "current_findings": target.current_findings(),
        "current_scan_ids": current_scan_ids,
        "scans": target.scans.order_by("-created_at"),
    }
    return render(request, "scanners/target_detail.html", context)


def _collect_scan_options(request, scanner_name):
    """Returns (options dict, wordlist file-or-None, error message-or-None).

    Only the scanner actually selected gets to contribute options — a
    gobuster wordlist submitted while "nmap" is selected is silently
    ignored, not smuggled into the scan.
    """
    if scanner_name == "nmap":
        options = {
            "service_detection": "nmap_sv" in request.POST,
            "aggressive": "nmap_a" in request.POST,
        }
        return options, None, None

    if scanner_name == "gobuster":
        wordlist = request.FILES.get("wordlist")
        if wordlist is None:
            return {}, None, None
        if not wordlist.name.lower().endswith(".txt"):
            return None, None, "Wordlist-ът трябва да е .txt файл."
        if wordlist.size > MAX_WORDLIST_BYTES:
            return None, None, "Wordlist-ът е твърде голям (макс. 2 MB)."
        return {}, wordlist, None

    return {}, None, None


def _recent_scans():
    return (
        Scan.objects.select_related("target")
        .prefetch_related("findings")
        .order_by("-created_at")[:20]
    )
