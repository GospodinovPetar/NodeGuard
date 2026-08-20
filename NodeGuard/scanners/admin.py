from django.contrib import admin

from .models import SecurityProfile


@admin.register(SecurityProfile)
class SecurityProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "scanner_name", "options", "is_available")
    prepopulated_fields = {"slug": ("name",)}
