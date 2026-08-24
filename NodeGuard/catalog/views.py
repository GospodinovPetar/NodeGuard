from django.contrib import messages
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from scanners.registry import tool_status

from .models import ToolState


def index(request):
    """App-store style catalog: every registered tool, whether its binary is
    installed (tool_status()), and its on/off state (ToolState)."""
    disabled = ToolState.disabled_names()
    tools = [
        {
            "name": s.name,
            "binary_name": s.binary_name,
            "available": s.available,
            "path": s.path,
            "enabled": s.name not in disabled,
        }
        for s in tool_status()
    ]
    context = {
        "tools": tools,
        "available_count": sum(1 for t in tools if t["available"]),
        "enabled_count": sum(1 for t in tools if t["enabled"]),
        "total_count": len(tools),
    }
    return render(request, "catalog/index.html", context)


@require_POST
def toggle(request, name):
    """Flip a tool's on/off state. Persisted server-side so the dashboard and
    the scan form honour it — disabled tools drop out of the scan dropdown."""
    registered = {s.name for s in tool_status()}
    if name not in registered:
        messages.error(request, "Unknown tool.")
        return redirect("catalog:index")

    state, _ = ToolState.objects.get_or_create(name=name)
    state.enabled = not state.enabled
    state.save(update_fields=["enabled"])
    messages.success(request, f"'{name}' {'enabled' if state.enabled else 'disabled'}.")
    return redirect("catalog:index")
