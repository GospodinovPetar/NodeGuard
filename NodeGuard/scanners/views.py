from collections import Counter

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.text import slugify

from catalog.models import ToolState

from . import sarif
from .base import Severity
from .models import Finding, Scan, SecurityProfile, Target
from .registry import list_scanners
from .tasks import run_scan

MAX_WORDLIST_BYTES = 2 * 1024 * 1024
MAX_SARIF_BYTES = 5 * 1024 * 1024


class ScanOptionError(ValueError):
    pass


class MissingPDFBackend(RuntimeError):
    """weasyprint (or its native libraries) isn't available here — expected on
    bare Windows dev boxes; the Docker image ships the libs."""


def scan_list(request):
    # Catalog-disabled tools drop out of the picker entirely — the catalog is
    # where you turn them back on.
    tools = ToolState.catalog_tools()
    disabled = {t.name for t in tools if t.disabled}
    context = {
        "scans": _recent_scans(),
        "tools": [t for t in tools if not t.disabled],
        "profiles": SecurityProfile.objects.exclude(scanner_name__in=disabled),
    }
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
    if not target_value:
        return "Target е задължителен."

    profile_slug = request.POST.get("profile", "").strip()
    if profile_slug:
        return _start_profile_scan(target_value, profile_slug)
    return _start_custom_scan(request, target_value)


def _start_profile_scan(target_value: str, slug: str) -> str | None:
    profile = SecurityProfile.objects.filter(slug=slug).first()
    if profile is None:
        return "Непознат profile."
    if profile.scanner_name in ToolState.disabled_names():
        return f"'{profile.scanner_name}' е изключен в каталога."
    if not profile.is_available():
        return f"'{profile.scanner_name}' не е инсталиран на тази машина."

    target, _ = Target.objects.get_or_create(value=target_value)
    scan = profile.create_scan(target)
    run_scan(scan.id)
    return None


def _start_custom_scan(request, target_value: str) -> str | None:
    scanner_name = request.POST.get("scanner", "").strip()
    scanners = list_scanners()

    if scanner_name not in scanners:
        return "Непознат scanner."
    if scanner_name in ToolState.disabled_names():
        return f"'{scanner_name}' е изключен в каталога."
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


def target_report(request, pk):
    """Per-target PDF: current risk state plus the scan history behind it."""
    target = get_object_or_404(
        Target.objects.prefetch_related("scans__findings"), pk=pk
    )
    html = render_to_string(
        "scanners/report.html", _report_context(target), request=request
    )
    try:
        pdf = _render_pdf(html, base_url=request.build_absolute_uri("/"))
    except MissingPDFBackend:
        messages.error(
            request, "PDF export изисква weasyprint (наличен в Docker образа)."
        )
        return redirect("scanners:target_detail", pk=pk)

    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = (
        f'attachment; filename="{_report_filename(target)}"'
    )
    return response


def _report_context(target):
    findings = target.current_findings
    counts = Counter((f.severity or "").lower() for f in findings)
    grouped = [
        (sev.value, [f for f in findings if (f.severity or "").lower() == sev.value])
        for sev in Severity
    ]
    return {
        "target": target,
        "generated_at": timezone.now(),
        "current_severity": target.current_severity,
        "finding_count": len(findings),
        "severity_summary": [(sev.value, counts.get(sev.value, 0)) for sev in Severity],
        "grouped_findings": [(sev, items) for sev, items in grouped if items],
        "scans": target.scans_newest_first,
        "current_scan_ids": {scan.id for scan in target.latest_scans},
    }


def _report_filename(target) -> str:
    stamp = timezone.now().strftime("%Y%m%d")
    return f"nodeguard-{slugify(target.value) or 'target'}-{stamp}.pdf"


def _render_pdf(html: str, base_url: str) -> bytes:  # pragma: no cover
    # WeasyPrint loads native libs (Pango/HarfBuzz) at import time, absent on a
    # bare Windows box; kept behind this guard so the app and the test suite
    # never hard-depend on them. Real output is exercised in the Docker image.
    try:
        import weasyprint
    except (ImportError, OSError) as exc:
        raise MissingPDFBackend from exc
    return weasyprint.HTML(string=html, base_url=base_url).write_pdf()


def sarif_import(request):
    """Import findings from any SARIF-compatible tool's output, attached to a
    target — the upload side of the catalog's SARIF story (the HTTP-headers
    scanner is the emit side)."""
    if request.method == "POST":
        target, error = _import_sarif(request)
        if error:
            messages.error(request, error)
        else:
            messages.success(request, f"Imported SARIF results for {target.value}.")
            return redirect("scanners:target_detail", pk=target.pk)
    return render(request, "scanners/sarif_import.html")


def _import_sarif(request):
    target_value = request.POST.get("target", "").strip()
    upload = request.FILES.get("sarif")

    if not target_value:
        return None, "Target е задължителен."
    if len(target_value) > 255:
        return None, "Target е твърде дълъг."
    if upload is None:
        return None, "Изберете SARIF файл."
    if upload.size > MAX_SARIF_BYTES:
        return None, "SARIF файлът е твърде голям (макс. 5 MB)."
    if not upload.name.lower().endswith((".sarif", ".json")):
        return None, "Файлът трябва да е .sarif или .json."

    try:
        report = sarif.parse(upload.read().decode("utf-8"))
    except UnicodeDecodeError:
        return None, "Файлът не е валиден UTF-8 текст."
    except sarif.SarifParseError as exc:
        return None, f"Невалиден SARIF: {exc}"

    target, _ = Target.objects.get_or_create(value=target_value)
    scan = Scan.objects.create(
        target=target,
        scanner_name=report.tool_name[:100],
        status=Scan.Status.DONE,
        options={"source": "sarif-import"},
        finished_at=timezone.now(),
    )
    Finding.store(scan, report.findings)
    return target, None


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
