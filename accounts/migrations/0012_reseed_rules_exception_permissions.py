"""Re-seed Sprint 6 : rôles (+ stock.exception / business.rules) et règles
métier par défaut pour les business existants (RM-07).

Les business existants n'ont ni les nouvelles permissions sur leurs rôles
système, ni leurs BusinessRule : on repart de la config actuelle (idempotent).
"""

from django.db import migrations


def reseed(apps, schema_editor):
    from accounts.alertes import get_default_rule_payloads
    from accounts.rbac import seed_default_roles

    Business = apps.get_model("accounts", "Business")
    BusinessRule = apps.get_model("accounts", "BusinessRule")

    for business in Business.objects.all():
        seed_default_roles(business)
        for payload in get_default_rule_payloads():
            BusinessRule.objects.get_or_create(
                business=business,
                code=payload["code"],
                defaults={"mode": payload["mode"], "est_actif": True},
            )


def reverse_reseed(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0011_businessrule_alert_decisionlog_and_more"),
    ]

    operations = [
        migrations.RunPython(reseed, reverse_reseed),
    ]