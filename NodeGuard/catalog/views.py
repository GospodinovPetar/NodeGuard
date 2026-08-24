from django.contrib import messages
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from scanners.registry import is_registered

from .models import ToolState


def index(request):
    """App-store style catalog: every registered tool, whether its binary is
    installed, and its on/off state."""
    tools = ToolState.catalog_tools()
    context = {
        "tools": tools,
        "available_count": sum(1 for t in tools if t.available),
        "enabled_count": sum(1 for t in tools if t.enabled),
        "total_count": len(tools),
    }
    return render(request, "catalog/index.html", context)


@require_POST
def toggle(request, name):
    """Flip a tool's on/off state. Persisted server-side so the dashboard and
    the scan form honour it — disabled tools drop out of the scan dropdown."""
    if not is_registered(name):
        messages.error(request, "Unknown tool.")
        return redirect("catalog:index")

    state, _ = ToolState.objects.get_or_create(name=name)
    state.enabled = not state.enabled
    state.save(update_fields=["enabled"])
    messages.success(request, f"'{name}' {'enabled' if state.enabled else 'disabled'}.")
    return redirect("catalog:index")
