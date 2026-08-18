from __future__ import annotations

from django import template

register = template.Library()

# Tailwind classes for each severity, most→least serious. Kept here so the
# dashboard and the scan table render findings with one consistent palette.
_SEVERITY_CLASSES = {
    "critical": "bg-rose-950 text-rose-300 ring-1 ring-rose-800/60",
    "high": "bg-red-950 text-red-300 ring-1 ring-red-800/60",
    "medium": "bg-amber-950 text-amber-300 ring-1 ring-amber-800/60",
    "low": "bg-sky-950 text-sky-300 ring-1 ring-sky-800/60",
    "info": "bg-slate-800 text-slate-300 ring-1 ring-slate-700",
}

_STATUS_CLASSES = {
    "done": "bg-emerald-900 text-emerald-300",
    "failed": "bg-red-900 text-red-300",
    "running": "bg-amber-900 text-amber-300",
    "pending": "bg-slate-800 text-slate-300",
}


@register.filter
def severity_classes(value: str) -> str:
    """Badge classes for a Finding severity string."""
    return _SEVERITY_CLASSES.get(str(value).lower(), _SEVERITY_CLASSES["info"])


@register.filter
def status_classes(value: str) -> str:
    """Badge classes for a Scan status string."""
    return _STATUS_CLASSES.get(str(value).lower(), _STATUS_CLASSES["pending"])
