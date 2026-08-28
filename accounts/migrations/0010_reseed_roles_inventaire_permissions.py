"""Re-seed des rôles avec les permissions du Sprint 5 (stock.inventaire).

Les business existants n'ont pas stock.inventaire sur leurs rôles système :
on repart de la config actuelle (idempotent).
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
        ("accounts", "0009_inventory_inventorycount_stockadjustment"),
    ]

    operations = [
        migrations.RunPython(reseed_roles, reverse_reseed),
    ]