"""Commande Django pour traiter les tâches récurrentes (Sprint 3).

Usage:
    python manage.py process_recurring_tasks

À exécuter périodiquement via cron/Celery pour créer automatiquement
les tâches de maintenance planifiées.
"""

from datetime import date, timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import RecurringTask, Item
from accounts.maintenance import create_task
from accounts.activite import log_activity, notify_members, Act


class Command(BaseCommand):
    help = "Traite les tâches récurrentes et crée les tâches de maintenance planifiées"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Affiche les tâches à créer sans les créer",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        today = date.today()
        tasks_created = 0
        errors = 0

        # Récupère toutes les tâches récurrentes actives dont la prochaine
        # exécution est aujourd'hui ou dans le passé
        recurring_tasks = RecurringTask.objects.filter(
            est_actif=True,
            prochaine_execution__lte=today,
        ).select_related("business", "item", "category", "procedure")

        self.stdout.write(
            f"Traitement de {recurring_tasks.count()} tâche(s) récurrente(s)..."
        )

        for recurring in recurring_tasks:
            try:
                # Détermine les articles à traiter
                if recurring.item:
                    items = [recurring.item]
                elif recurring.category:
                    items = list(
                        Item.objects.filter(
                            business=recurring.business,
                            category=recurring.category,
                            statut=Item.Statut.ACTIF,
                        )
                    )
                else:
                    self.stderr.write(
                        f"  [SKIP] Récurrence {recurring.id}: ni article ni catégorie"
                    )
                    continue

                if not items:
                    self.stdout.write(
                        f"  [SKIP] Récurrence {recurring.id}: aucun article actif"
                    )
                    continue

                self.stdout.write(
                    f"  Récurrence {recurring.id}: {len(items)} article(s) "
                    f"avec procédure '{recurring.procedure.nom}'"
                )

                for item in items:
                    if dry_run:
                        self.stdout.write(
                            f"    [DRY-RUN] Création tâche pour {item.nom}"
                        )
                    else:
                        # Crée la tâche de maintenance
                        task = create_task(
                            business=recurring.business,
                            item=item,
                            acteur=recurring.created_by,
                            procedure=recurring.procedure,
                            motif=f"Tâche automatique ({recurring.frequence_jours}j)",
                        )
                        tasks_created += 1
                        self.stdout.write(
                            f"    [OK] Tâche {task.id} créée pour {item.nom}"
                        )

                # Met à jour la prochaine exécution
                if not dry_run:
                    recurring.prochaine_execution = today + timedelta(
                        days=recurring.frequence_jours
                    )
                    recurring.save(update_fields=["prochaine_execution"])
                    self.stdout.write(
                        f"    Prochaine exécution: {recurring.prochaine_execution}"
                    )

            except Exception as e:
                errors += 1
                self.stderr.write(f"  [ERREUR] Récurrence {recurring.id}: {e}")

        self.stdout.write(
            self.style.SUCCESS(
                f"\nTerminé: {tasks_created} tâche(s) créée(s), {errors} erreur(s)"
            )
        )
