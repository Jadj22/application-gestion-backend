"""Moteur disponibilité & fiabilité (Sprint 5, S 5-03 / S 5-04).

Cycle d'un inventaire (US-22 à US-26) :
    1. Lancer un inventaire (EN_COURS).
    2. Déclarer un comptage par article (RM-14 : déclaré = NON_VERIFIE par
       défaut ; RM-15 : ESTIME n'est jamais présenté comme certain).
    3. Clôturer : chaque écart non nul devient un StockAdjustment immuable
       (RM-13 : écart = événement, ancien contexte conservé).
    4. Le stock courant intègre la somme des ajustements (RM-04).

RM-12 : un article est « à vérifier » tant que son dernier comptage (sur
l'inventaire le plus récent) n'est pas CERTAIN.
"""

from django.db import transaction
from rest_framework.exceptions import ValidationError

from .models import Inventory, InventoryCount, Item, StockAdjustment


# --- Comptages -------------------------------------------------------------


def progress(inventory, total_items):
    """Avancement de l'inventaire : comptés / total."""
    done = inventory.counts.count()
    return {"comptes": done, "total": total_items}


def declare_count(*, inventory, item, quantite_comptee, fiabilite, acteur):
    """Déclare (ou remplace) le comptage d'un article (US-22, RM-14).

    Le stock théorique est capturé à la saisie : l'écart reste calculable
    même si du stock bouge ensuite (RM-13).
    """
    if inventory.statut != Inventory.Statut.EN_COURS:
        raise ValidationError("Cet inventaire est clôturé : plus de comptage possible.")
    if item.business_id != inventory.business_id:
        raise ValidationError("Article invalide pour ce business.")
    if quantite_comptee < 0:
        raise ValidationError("La quantité comptée ne peut pas être négative.")

    from .stock import snapshot

    state = snapshot(item)
    quantite_theorique = state["total"]

    with transaction.atomic():
        count, created = InventoryCount.objects.update_or_create(
            inventory=inventory,
            item=item,
            defaults={
                "quantite_theorique": quantite_theorique,
                "quantite_comptee": quantite_comptee,
                "fiabilite": fiabilite,
                "declared_by": acteur,
            },
        )
    from .activite import Act, log_activity

    log_activity(
        business=inventory.business,
        acteur=acteur,
        action=Act.INVENTORY_COUNT,
        item=item,
        cible=inventory.libelle or "Inventaire",
        detail={
            "comptee": quantite_comptee,
            "theorique": quantite_theorique,
            "fiabilite": fiabilite,
            "inventaire": str(inventory.id),
        },
    )
    return count, created


# --- Clôture ---------------------------------------------------------------


def cloturer_inventory(*, inventory, acteur):
    """Clôture l'inventaire : chaque écart non nul devient un ajustement."""
    if inventory.statut != Inventory.Statut.EN_COURS:
        raise ValidationError("Cet inventaire est déjà clôturé.")
    counts = list(inventory.counts.select_related("item"))
    if not counts:
        raise ValidationError("Aucun comptage enregistré : impossible de clôturer.")

    from django.utils import timezone

    with transaction.atomic():
        adjustments = []
        for count in counts:
            if count.ecart == 0:
                continue
            adjustments.append(
                StockAdjustment(
                    business=inventory.business,
                    item=count.item,
                    inventory=inventory,
                    quantite_theorique=count.quantite_theorique,
                    quantite_comptee=count.quantite_comptee,
                    ecart=count.ecart,
                    motif=f"Inventaire {inventory.libelle or ''}".strip()
                    or "Inventaire physique",
                    acteur=acteur,
                )
            )
        StockAdjustment.objects.bulk_create(adjustments)
        inventory.statut = Inventory.Statut.CLOTURE
        inventory.closed_at = timezone.now()
        inventory.save(update_fields=["statut", "closed_at"])
    summary = {
        "comptages": len(counts),
        "ecarts": sum(1 for c in counts if c.ecart != 0),
        "ajustements": len(adjustments),
    }
    from .activite import Act, log_activity, notify_members
    from .rbac import Perm

    log_activity(
        business=inventory.business,
        acteur=acteur,
        action=Act.INVENTORY_CLOTURE,
        cible=inventory.libelle or "Inventaire",
        detail=summary,
    )
    if summary["ecarts"]:
        notify_members(
            business=inventory.business,
            code="INVENTORY.ECARTS",
            message=(
                f"Inventaire clôturé : {summary['ecarts']} écart(s) corrigés "
                "par ajustement de stock à examiner."
            ),
            permission_codename=Perm.STOCK_VIEW,
            ignore_user=acteur,
        )
    return summary


# --- Ajustement manuel -----------------------------------------------------


def create_adjustment(*, business, item, quantite_comptee, acteur, motif="", reference=""):
    """Ajustement manuel : le physique corrige le théorique (US-24).

    L'écart (signé) est calculé par le système ; l'ancien contexte
    (théorique, compté) est conservé dans l'événement (RM-13).
    """
    if item.business_id != business.id:
        raise ValidationError("Article invalide pour ce business.")
    if quantite_comptee < 0:
        raise ValidationError("La quantité comptée ne peut pas être négative.")
    if not (motif or "").strip():
        raise ValidationError("Le motif est obligatoire pour un ajustement manuel.")

    from .stock import snapshot

    state = snapshot(item)
    quantite_theorique = state["total"]
    adjustment = StockAdjustment.objects.create(
        business=business,
        item=item,
        inventory=None,
        quantite_theorique=quantite_theorique,
        quantite_comptee=quantite_comptee,
        ecart=quantite_comptee - quantite_theorique,
        motif=motif,
        reference=reference,
        acteur=acteur,
    )
    from .activite import Act, log_activity

    log_activity(
        business=business,
        acteur=acteur,
        action=Act.ADJUSTMENT_CREATE,
        item=item,
        detail={"ecart": adjustment.ecart, "motif": motif, "reference": reference},
    )
    return adjustment


# --- RM-12 : donnée à vérifier ---------------------------------------------


def a_verifier(item):
    """Vrai si le dernier comptage de l'article n'est pas CERTAIN (RM-12).

    Une donnée déclarée (NON_VERIFIE, RM-14) ou estimée (ESTIME, RM-15)
    n'est jamais présentée comme certaine tant qu'un comptage CERTAIN
    n'a pas été enregistré.
    """
    latest_inventory = Inventory.objects.filter(
        business_id=item.business_id
    ).order_by("-created_at", "-id").first()
    if latest_inventory is None:
        return False
    count = InventoryCount.objects.filter(
        inventory=latest_inventory, item_id=item.id
    ).first()
    if count is None:
        return False
    return count.fiabilite != InventoryCount.Fiabilite.CERTAIN


def a_verifier_bulk(items):
    """Flags RM-12 calculés en une requête pour une liste d'articles."""
    if not items:
        return {}
    ids = [i.id for i in items]
    counts = (
        InventoryCount.objects.filter(item_id__in=ids)
        .select_related("inventory")
        .order_by("item_id", "-inventory__created_at", "-inventory__id")
    )
    latest_by_item = {}
    for count in counts:
        latest_by_item.setdefault(count.item_id, count)
    not_certain = {
        count.item_id
        for count in latest_by_item.values()
        if count.fiabilite != InventoryCount.Fiabilite.CERTAIN
    }
    return {item.id: item.id in not_certain for item in items}
