from django.db import migrations

# Seeded rather than hardcoded in code so the team can edit/extend them in
# the admin without a deploy. update_or_create keeps a re-run idempotent
# while leaving any extra profiles someone added alone.
BUILTIN_PROFILES = [
    {
        "slug": "quick-scan",
        "name": "Quick Scan",
        "description": (
            "Бърз преглед на отворени портове и версии на услугите (nmap -sV)."
        ),
        "scanner_name": "nmap",
        "options": {"service_detection": True, "aggressive": False},
    },
    {
        "slug": "deep-web-scan",
        "name": "Deep Web Scan",
        "description": (
            "Directory brute-force срещу HTTP target с bundled wordlist "
            "(gobuster dir). Качен .txt wordlist се подава per-scan, не тук."
        ),
        "scanner_name": "gobuster",
        "options": {},
    },
]


def create_builtin_profiles(apps, schema_editor):
    SecurityProfile = apps.get_model("scanners", "SecurityProfile")
    for profile in BUILTIN_PROFILES:
        SecurityProfile.objects.update_or_create(
            slug=profile["slug"],
            defaults={k: v for k, v in profile.items() if k != "slug"},
        )


def delete_builtin_profiles(apps, schema_editor):
    SecurityProfile = apps.get_model("scanners", "SecurityProfile")
    SecurityProfile.objects.filter(
        slug__in=[p["slug"] for p in BUILTIN_PROFILES]
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("scanners", "0004_securityprofile"),
    ]

    operations = [
        migrations.RunPython(create_builtin_profiles, delete_builtin_profiles),
    ]
