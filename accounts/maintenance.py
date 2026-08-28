"""Moteur entretien (Sprint 4, S 4-03 / S 4-04).

L'état réel d'un article (RM-08, RM-10, RM-11) est TOUJOURS dérivé de la
dernière tâche d'entretien, jamais stocké en dur :

    PRET           entretien non requis, ou dernière tâche menée à bien
    A_ENTRETENIR   requis et aucune tâche réalisée
    EN_ENTRETIEN   une tâche est en cours
    PARTIEL        dernière tâche clôturée en incomplète (RM-11 accepté)
    A_CONTROLER    travail terminé mais contrôle(s) de la procédure non faits

Créer une tâche ne rend pas l'article prêt (RM-10) : tant qu'elle n'est pas
TERMINEE (étapes obligatoires + contrôles faits), l'article n'est pas prêt.
"""

from django.db import transaction
from django.db.models import OuterRef, Subquery
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .activite import Act, log_activity, notify_members
from .models import Item, MaintenanceTask, Procedure, ProcedureStep, TaskStep
from .rbac import Perm


# --- Configuration effective (RM-08 : héritage catégorie -> article) -------


def entretien_requis(item):
    """Vrai si l'article exige un entretien (override article sinon catégorie)."""
    if item.entretien_requis is not None:
        return item.entretien_requis
    if item.category_id is not None:
        return bool(item.category.entretien_requis)
    return False


def default_procedure(item):
    """Procédure par défaut : override article, sinon celle de la catégorie."""
    procedure = item.procedure
    if procedure is None and item.category_id is not None:
        procedure = item.category.procedure
    return procedure


# --- État réel -------------------------------------------------------------

ETAT_LIBELLES = {
    "PRET": "Prêt",
    "A_ENTRETENIR": "À entretenir",
    "EN_ENTRETIEN": "En entretien",
    "PARTIEL": "Entretien partiel",
    "A_CONTROLER": "À contrôler",
}


def _etat_pour_tache(item, task):
    if task is None:
        return "A_ENTRETENIR"
    if task.statut == MaintenanceTask.Statut.EN_COURS:
        return "EN_ENTRETIEN"
    if task.statut == MaintenanceTask.Statut.PARTIELLE:
        return "PARTIEL"
    if task.steps.filter(type=ProcedureStep.Type.CONTROLE).exclude(
        statut=TaskStep.Statut.TERMINE
    ).exists():
        return "A_CONTROLER"
    return "PRET"


def etat_entretien(item, task=None):
    """État d'entretien effectif d'un article (RM-10, RM-11)."""
    if not entretien_requis(item):
        return {"code": "PRET", "libelle": ETAT_LIBELLES["PRET"]}
    if task is None:
        task = MaintenanceTask.objects.filter(
            business_id=item.business_id, item_id=item.id
        ).prefetch_related("steps").first()
    code = _etat_pour_tache(item, task)
    return {"code": code, "libelle": ETAT_LIBELLES[code]}


def etats_entretien(items):
    """États calculés en une requête pour une liste d'articles."""
    if not items:
        return {}
    ids = [i.id for i in items]
    latest = MaintenanceTask.objects.filter(
        item_id=OuterRef("pk"),
        business_id=OuterRef("business_id"),
    ).order_by("-created_at", "-id").values("id")[:1]

    tasks = list(
        MaintenanceTask.objects.filter(id__in=Subquery(latest))
        .prefetch_related("steps")
        .filter(item_id__in=ids)
    )
    task_by_item = {t.item_id: t for t in tasks}
    return {item.id: etat_entretien(item, task_by_item.get(item.id)) for item in items}


# --- Tâches ----------------------------------------------------------------


def _etape_terminee(step):
    return step.statut == TaskStep.Statut.TERMINE


def progress(task):
    """Avancement d'une tâche : total / faites / en cours / restantes."""
    steps = list(task.steps.all())
    return {
        "total": len(steps),
        "faites": sum(1 for s in steps if _etape_terminee(s)),
        "en_cours": sum(1 for s in steps if s.statut == TaskStep.Statut.EN_COURS),
        "restantes": sum(1 for s in steps if s.statut == TaskStep.Statut.EN_ATTENTE),
    }


def create_task(*, business, item, acteur, procedure=None, motif="", auto=False):
    """Crée une tâche en copiant les étapes de la procédure (RM-09, RM-10)."""
    procedure = procedure or default_procedure(item)
    if procedure is None:
        raise ValidationError(
            "Aucune procédure d'entretien : configurez la procédure de la "
            "catégorie ou de l'article, ou passez procedure_id."
        )
    if not procedure.est_actif:
        raise ValidationError("La procédure choisie est désactivée.")
    en_cours = MaintenanceTask.objects.filter(
        business=business, item=item, statut=MaintenanceTask.Statut.EN_COURS
    ).exists()
    if en_cours:
        message = "Une tâche est déjà en cours pour cet article."
        if auto:
            return None
        raise ValidationError(message)

    with transaction.atomic():
        task = MaintenanceTask.objects.create(
            business=business,
            item=item,
            procedure=procedure,
            procedure_nom=procedure.nom,
            motif=motif,
            created_by=acteur,
        )
        TaskStep.objects.bulk_create(
            [
                TaskStep(
                    task=task,
                    nom=step.nom,
                    ordre=step.ordre,
                    obligatoire=step.obligatoire,
                    type=step.type,
                )
                for step in procedure.steps.order_by("ordre", "nom")
            ]
        )
    log_activity(
        business=business,
        acteur=acteur,
        action=Act.TASK_CREATE,
        item=item,
        detail={"procedure": procedure.nom, "auto": auto, "motif": motif},
    )
    if auto:
        notify_members(
            business=business,
            code="TASK.AUTO",
            message=(
                f"Tâche d'entretien automatique créée sur « {item.nom} » "
                "(retour de location), procédure {procedure.nom}."
            ),
            item=item,
            permission_codename=Perm.ENTRETIEN_MANAGE,
            ignore_user=acteur,
        )
    return task


def auto_tache_retour(item, acteur):
    """Déclenche une tâche quand un article entretenu revient de location."""
    if not entretien_requis(item) or default_procedure(item) is None:
        return None
    try:
        return create_task(
            business=item.business,
            item=item,
            acteur=acteur,
            motif="Retour de location (automatique)",
            auto=True,
        )
    except ValidationError:
        return None


def update_step(step, statut, acteur):
    """Marque une étape en cours ou terminée (US-16).

    Une tâche clôturée fige ses étapes, SAUF les contrôles (type CONTROLE)
    qui peuvent encore être terminés après clôture : c'est le passage de
    l'état « à contrôler » (A_CONTROLER) vers « prêt » (PRET).
    """
    if step.task.statut != MaintenanceTask.Statut.EN_COURS:
        controle_en_retard = (
            step.type == ProcedureStep.Type.CONTROLE
            and statut == TaskStep.Statut.TERMINE
            and step.finished_at is None
        )
        if not controle_en_retard:
            raise ValidationError("La tâche est clôturée : ses étapes sont figées.")
    now = timezone.now()
    if statut == TaskStep.Statut.EN_COURS:
        if step.started_at is None:
            step.started_at = now
        step.done_by = acteur
        step.statut = TaskStep.Statut.EN_COURS
    else:
        step.finished_at = now
        if step.started_at is None:
            step.started_at = now
        step.done_by = acteur
        step.statut = TaskStep.Statut.TERMINE
    step.save()
    from .activite import log_activity

    log_activity(
        business=step.task.business,
        acteur=acteur,
        action=Act.TASK_STEP,
        item=step.task.item,
        cible=f"{step.nom} ({step.task.procedure_nom})",
        detail={"statut": statut, "tache": step.task_id},
    )
    return step


def cloturer_task(task, acteur=None, partielle=False):
    """Clôture une tâche (US-16) : TERMINEE ou PARTIELLE acceptée (RM-11).

    Sans `partielle`, la clôture exige toutes les étapes obligatoires.
    Avec `partielle=True`, l'entretien incomplet est accepté : l'article
    reste visible comme « entretien partiel ».
    """
    if task.statut != MaintenanceTask.Statut.EN_COURS:
        raise ValidationError("Cette tâche est déjà clôturée.")
    steps = list(task.steps.all())
    # Un contrôle n'est pas bloquant pour la clôture : il se termine après
    # (état A_CONTROLER -> PRET). Seules les opérations obligatoires comptent.
    manquantes = [
        s.nom
        for s in steps
        if s.obligatoire
        and s.type != ProcedureStep.Type.CONTROLE
        and not _etape_terminee(s)
    ]
    if partielle:
        task.statut = (
            MaintenanceTask.Statut.PARTIELLE if manquantes else MaintenanceTask.Statut.TERMINEE
        )
    else:
        if manquantes:
            raise ValidationError(
                f"Étapes obligatoires non terminées : {', '.join(manquantes)}. "
                "Clôturez en incomplète (partielle=true) pour accepter l'entretien partiel."
            )
        task.statut = MaintenanceTask.Statut.TERMINEE
    task.save()
    log_activity(
        business=task.business,
        acteur=acteur or task.created_by,
        action=Act.TASK_CLOTURE,
        item=task.item,
        cible=task.procedure_nom,
        detail={"statut": task.statut, "partielle": partielle},
    )
    return task
