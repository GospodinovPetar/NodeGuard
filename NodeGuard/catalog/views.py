from django.shortcuts import render

from scanners.registry import tool_status


def index(request):
    """App-store style catalog: every registered tool + whether its binary
    is installed on this machine (shutil.which via tool_status())."""
    statuses = tool_status()
    context = {
        "statuses": statuses,
        "available_count": sum(1 for s in statuses if s.available),
        "total_count": len(statuses),
    }
    return render(request, "catalog/index.html", context)
