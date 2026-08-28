"""Sprint 8 bis : contrôle de retour de réservation.

Quantités retournées / abîmées / perdues, observations et date de
retour effectif, renseignés à la terminaison d'une location (US-31+).
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0019_business_logo"),
    ]

    operations = [
        migrations.AddField(
            model_name="reservation",
            name="quantite_retournee",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="reservation",
            name="quantite_abimee",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="reservation",
            name="quantite_perdue",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="reservation",
            name="observations",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="reservation",
            name="retourne_le",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]