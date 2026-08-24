from django.urls import path

from . import views

app_name = "catalog"

urlpatterns = [
    path("", views.index, name="index"),
    path("toggle/<str:name>/", views.toggle, name="toggle"),
]
