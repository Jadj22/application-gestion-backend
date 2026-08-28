"""Commande Django pour envoyer les rappels (Sprint 3).

Usage:
    python manage.py process_reminders

À exécuter périodiquement (toutes les minutes idéalement) via cron/Celery
pour envoyer les notifications de rappel.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import Reminder, BusinessMember, Notification


class Command(BaseCommand):
    help = "Envoie les rappels dont l'heure est arrivée"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Affiche les rappels à envoyer sans les envoyer",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        now = timezone.now()
        sent = 0
        errors = 0

        # Récupère tous les rappels non envoyés dont l'heure est passée
        reminders = Reminder.objects.filter(
            envoye=False,
            rappel_a__lte=now,
        ).select_related("business", "task", "item", "user")

        self.stdout.write(f"Traitement de {reminders.count()} rappel(s)...")

        for reminder in reminders:
            try:
                self.stdout.write(
                    f"  Rappel {reminder.id}: '{reminder.message}' -> {reminder.user.email}"
                )

                if dry_run:
                    self.stdout.write("    [DRY-RUN] Envoi simulé")
                else:
                    # Crée une notification pour l'utilisateur
                    Notification.objects.create(
                        business=reminder.business,
                        user=reminder.user,
                        code="REMINDER",
                        message=reminder.message,
                        item=reminder.item,
                    )

                    # Marque le rappel comme envoyé
                    reminder.envoye = True
                    reminder.save(update_fields=["envoye"])

                    sent += 1
                    self.stdout.write("    [OK] Notification créée")

                    # TODO: Envoyer une notification push via Firebase
                    # if reminder.user a un fcm_token:
                    #     send_push_notification(...)

            except Exception as e:
                errors += 1
                self.stderr.write(f"  [ERREUR] Rappel {reminder.id}: {e}")

        self.stdout.write(
            self.style.SUCCESS(
                f"\nTerminé: {sent} rappel(s) envoyé(s), {errors} erreur(s)"
            )
        )
