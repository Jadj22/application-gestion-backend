"""Signaux Django pour les événements du module accounts.

Post-save hooks pour la création de données par défaut.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Business, Procedure, ProcedureStep


# --- Templates de procédures par défaut ---

DEFAULT_PROCEDURES = [
    {
        "nom": "Nettoyage standard",
        "description": "Procédure de nettoyage complète pour articles textiles",
        "steps": [
            {"nom": "Tri et vérification", "type": "OPERATION", "obligatoire": True, "description": "Vérifier l'état et trier par couleur/matière"},
            {"nom": "Pré-traitement", "type": "OPERATION", "obligatoire": True, "description": "Traiter les taches si nécessaire"},
            {"nom": "Lavage", "type": "OPERATION", "obligatoire": True, "description": "Lavage selon les instructions"},
            {"nom": "Séchage", "type": "OPERATION", "obligatoire": True, "description": "Séchage adapté au textile"},
            {"nom": "Contrôle qualité", "type": "CONTROLE", "obligatoire": True, "description": "Vérifier propreté et état"},
        ],
    },
    {
        "nom": "Repassage",
        "description": "Procédure de repassage et mise en forme",
        "steps": [
            {"nom": "Préparation", "type": "OPERATION", "obligatoire": True, "description": "Humidifier si nécessaire"},
            {"nom": "Repassage", "type": "OPERATION", "obligatoire": True, "description": "Repasser selon le type de tissu"},
            {"nom": "Pliage/Cintrage", "type": "OPERATION", "obligatoire": True, "description": "Plier ou mettre sur cintre"},
            {"nom": "Contrôle aspect", "type": "CONTROLE", "obligatoire": True, "description": "Vérifier l'absence de plis"},
        ],
    },
    {
        "nom": "Contrôle qualité",
        "description": "Vérification complète avant mise en stock",
        "steps": [
            {"nom": "Inspection visuelle", "type": "CONTROLE", "obligatoire": True, "description": "Vérifier l'état général"},
            {"nom": "Vérification propreté", "type": "CONTROLE", "obligatoire": True, "description": "Confirmer absence de taches"},
            {"nom": "Contrôle dimensions", "type": "CONTROLE", "obligatoire": True, "description": "Vérifier taille/forme"},
            {"nom": "Validation finale", "type": "CONTROLE", "obligatoire": True, "description": "Approuver pour mise en stock"},
        ],
    },
    {
        "nom": "Réparation",
        "description": "Procédure de réparation et remise en état",
        "steps": [
            {"nom": "Diagnostic", "type": "OPERATION", "obligatoire": True, "description": "Identifier les réparations nécessaires"},
            {"nom": "Réparation couture", "type": "OPERATION", "obligatoire": False, "description": "Réparer coutures/boutons"},
            {"nom": "Réparation tissu", "type": "OPERATION", "obligatoire": False, "description": "Repriser/rapiécer si nécessaire"},
            {"nom": "Test solidité", "type": "CONTROLE", "obligatoire": True, "description": "Vérifier la qualité des réparations"},
            {"nom": "Nettoyage final", "type": "OPERATION", "obligatoire": True, "description": "Nettoyer après réparation"},
        ],
    },
    {
        "nom": "Préparation location",
        "description": "Mise en condition avant remise au client",
        "steps": [
            {"nom": "Vérification disponibilité", "type": "CONTROLE", "obligatoire": True, "description": "Confirmer l'article en stock"},
            {"nom": "Inspection état", "type": "CONTROLE", "obligatoire": True, "description": "Vérifier l'état avant remise"},
            {"nom": "Nettoyage rapide", "type": "OPERATION", "obligatoire": True, "description": "Dépoussiérage/rafraîchissement"},
            {"nom": "Emballage", "type": "OPERATION", "obligatoire": True, "description": "Emballer pour transport"},
            {"nom": "Étiquetage", "type": "OPERATION", "obligatoire": True, "description": "Ajouter étiquette client/réservation"},
        ],
    },
    {
        "nom": "Retour client",
        "description": "Traitement des articles retournés",
        "steps": [
            {"nom": "Réception", "type": "OPERATION", "obligatoire": True, "description": "Recevoir et identifier l'article"},
            {"nom": "Inspection dommages", "type": "CONTROLE", "obligatoire": True, "description": "Vérifier présence de dommages"},
            {"nom": "Photo état", "type": "OPERATION", "obligatoire": False, "description": "Photographier l'état au retour"},
            {"nom": "Nettoyage complet", "type": "OPERATION", "obligatoire": True, "description": "Nettoyer avant remise en stock"},
            {"nom": "Remise en stock", "type": "OPERATION", "obligatoire": True, "description": "Ranger à son emplacement"},
        ],
    },
]


@receiver(post_save, sender=Business)
def create_default_procedures(sender, instance, created, **kwargs):
    """Crée les procédures par défaut lors de la création d'un business."""
    if not created:
        return

    for proc_data in DEFAULT_PROCEDURES:
        procedure = Procedure.objects.create(
            business=instance,
            nom=proc_data["nom"],
            description=proc_data["description"],
            est_actif=True,
            created_by=instance.created_by,
        )
        for idx, step_data in enumerate(proc_data["steps"]):
            ProcedureStep.objects.create(
                procedure=procedure,
                nom=step_data["nom"],
                type=step_data["type"],
                obligatoire=step_data["obligatoire"],
                description=step_data.get("description", ""),
                ordre=idx,
            )
