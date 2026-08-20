from django.urls import path

from . import views

app_name = "scanners"

urlpatterns = [
    path("", views.scan_list, name="list"),
    path("partial/", views.scan_rows, name="rows"),
    path("trigger/", views.trigger_scan, name="trigger"),
    path("targets/<int:pk>/", views.target_detail, name="target_detail"),
]
