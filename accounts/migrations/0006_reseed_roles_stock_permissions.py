"""Re-seed des rôles avec les permissions du Sprint 3 (stock & traçabilité).

Les business existants n'ont pas stock.view / stock.mouvement sur leurs
rôles système : on repart de la config actuelle (idempotent).
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
        ("accounts", "0005_stockmovement"),
    ]

    operations = [
        migrations.RunPython(reseed_roles, reverse_reseed),
    ]