"""Re-seed des rôles avec les nouvelles permissions du Sprint 2 (catalogue).

Les business créés avant le Sprint 2 n'ont pas les permissions catalogue
(catalog.view, item.edit, catalog.manage) sur leurs rôles système.
Cette migration recrée le lien rôles <-> permissions via la config actuelle.
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
        ("accounts", "0003_category_item_itemphoto_and_more"),
    ]

    operations = [
        migrations.RunPython(reseed_roles, reverse_reseed),
    ]