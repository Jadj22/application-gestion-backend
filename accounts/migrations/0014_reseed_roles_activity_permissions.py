"""Re-seed Sprint 7 : rôles + permission activity.view (RM-20).

Les business existants n'ont pas activity.view sur leurs rôles : on repart
de la config actuelle (idempotent).
"""

from django.db import migrations


def reseed_roles(apps, schema_editor):
    from accounts.rbac import seed_default_roles

    Business = apps.get_model("accounts", "Business")
    for business in Business.objects.all():
        seed_default_roles(business)


def reverse_reseed(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0013_activitylog_notification"),
    ]

    operations = [
        migrations.RunPython(reseed_roles, reverse_reseed),
    ]