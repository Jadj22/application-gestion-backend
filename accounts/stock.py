"""Moteur de stock (Sprint 3, S 3-03).

Le stock courant est TOUJOURS recalculé depuis l'historique immuable des
StockMovement (RM-02, RM-03) et des StockAdjustment (RM-13, Sprint 5).
Aucune table de stock courant redondante : une seule source de vérité,
aucun risque de dérive.

États (RM-04 — disponibilité distincte du total) :
    total       = entrées - pertes + ajustements   (quantité possédée)
    sorties     = sorties - retours                (actuellement chez un client)
    endommages  = dommages                         (présents mais inutilisables)
    perdus      = pertes                           (disparus, retirés du total)
    disponibles = total - sorties - endommages     (quantité utilisable)
"""

from django.db import transaction
from django.db.models import Sum
from rest_framework.exceptions import ValidationError

from .models import Item, StockAdjustment, StockMovement


def get_aggregates(business_id, item_ids=None):
    """Sommes par (item, type) en une seule requête groupée."""
    qs = StockMovement.objects.filter(business_id=business_id)
    if item_ids:
        qs = qs.filter(item_id__in=item_ids)
    rows = qs.values("item_id", "type").annotate(qty=Sum("quantite"))
    return {(r["item_id"], r["type"]): r["qty"] for r in rows}


def get_adjustments(business_id, item_ids=None):
    """Sommes des écarts ajustés par article (Sprint 5, RM-13)."""
    qs = StockAdjustment.objects.filter(business_id=business_id)
    if item_ids:
        qs = qs.filter(item_id__in=item_ids)
    rows = qs.values("item_id").annotate(total=Sum("ecart"))
    return {r["item_id"]: r["total"] for r in rows}


def snapshot(item, aggregates=None, adjustments=None):
    """Calcule les états du stock pour un article (théorique + ajustements)."""
    if aggregates is None:
        aggregates = get_aggregates(item.business_id, [item.id])
    if adjustments is None:
        adjustments = get_adjustments(item.business_id, [item.id])
    entree = aggregates.get((item.id, StockMovement.Type.ENTREE), 0)
    pertes = aggregates.get((item.id, StockMovement.Type.PERTE), 0)
    sorties = aggregates.get((item.id, StockMovement.Type.SORTIE), 0)
    retours = aggregates.get((item.id, StockMovement.Type.RETOUR), 0)
    dommages = aggregates.get((item.id, StockMovement.Type.DOMMAGE), 0)
    ajustes = adjustments.get(item.id, 0)

    total = entree - pertes + ajustes
    out = sorties - retours
    available = total - out - dommages
    return {
        "total": total,
        "disponibles": max(available, 0),
        "sorties": max(out, 0),
        "endommages": dommages,
        "perdus": pertes,
        "ajustements": ajustes,
    }


def validate_against_availability(type, quantite, state):
    """Vérifie la règle métier propre à chaque type de mouvement."""
    if type == StockMovement.Type.SORTIE:
        if quantite > state["disponibles"]:
            raise ValidationError(
                f"Stock disponible insuffisant : {state['disponibles']} disponible(s), "
                f"{quantite} demandé(s)."
            )
    elif type == StockMovement.Type.RETOUR:
        if quantite > state["sorties"]:
            raise ValidationError(
                f"Impossible de retourner {quantite} unité(s) : "
                f"{state['sorties']} actuellement sortie(s)."
            )
    elif type == StockMovement.Type.PERTE:
        if quantite > state["disponibles"]:
            raise ValidationError(
                f"Perte impossible : {quantite} unité(s), "
                f"{state['disponibles']} disponible(s)."
            )
    elif type == StockMovement.Type.DOMMAGE:
        if quantite > state["disponibles"]:
            raise ValidationError(
                f"Dommage impossible : {quantite} unité(s), "
                f"{state['disponibles']} disponible(s)."
            )


def create_movement(
    *, business, item, type, quantite, acteur, motif="", reference="", related_to=None
):
    """Crée un mouvement après validation métier, de façon atomique.

    Le verrou select_for_update sur l'article protège contre deux
    mouvements concurrents (ex. deux sorties simultanées).
    """
    with transaction.atomic():
        locked_item = Item.objects.select_for_update().get(pk=item.pk)
        aggregates = get_aggregates(business.id, [locked_item.id])
        adjustments = get_adjustments(business.id, [locked_item.id])
        state = snapshot(locked_item, aggregates, adjustments)
        validate_against_availability(type, quantite, state)

        movement = StockMovement.objects.create(
            business=business,
            item=locked_item,
            type=type,
            quantite=quantite,
            motif=motif,
            reference=reference,
            acteur=acteur,
            related_to=related_to,
        )
        aggregates[(locked_item.id, type)] = (
            aggregates.get((locked_item.id, type), 0) + quantite
        )
        if type == StockMovement.Type.RETOUR:
            from .maintenance import auto_tache_retour

            auto_tache_retour(locked_item, acteur)
        from .activite import Act, log_activity

        log_activity(
            business=business,
            acteur=acteur,
            action=f"STOCK.{type}",
            item=locked_item,
            detail={"quantite": quantite, "motif": motif, "reference": reference},
        )
        return movement, snapshot(locked_item, aggregates, adjustments)