"""Suppression définitive d'un compte utilisateur.

Les données d'un business partagé avec d'autres membres sont conservées.
Les FK protégées (traçabilité) sont réassignées à un successeur, jamais
supprimées de façon à casser l'historique d'un autre utilisateur.
"""

from django.db import transaction

from .models import (
    ActivityLog,
    Business,
    DecisionLog,
    Reservation,
    StockAdjustment,
    StockMovement,
)
from .rbac import RoleNom


def delete_user_account(user):
    """Supprime ``user`` et les données qui n'appartiennent qu'à lui.

    - Business dont l'utilisateur est le seul membre : supprimé (CASCADE).
    - Business partagés : conservés ; ``created_by`` / ``acteur`` /
      ``reserve_par`` sont réassignés à un membre restant
      (OWNER > ADMIN > autre).
    - Memberships et notifications : CASCADE à la suppression de l'utilisateur.
    """
    with transaction.atomic():
        memberships = list(
            user.memberships.select_related("business", "role").all()
        )
        handled_ids = set()
        for membership in memberships:
            business = membership.business
            handled_ids.add(business.id)
            _release_or_delete_business(user, business)

        for business in list(user.created_businesses.exclude(id__in=handled_ids)):
            _release_or_delete_business(user, business)

        user.delete()


def _release_or_delete_business(user, business):
    others = list(
        business.memberships.exclude(user=user).select_related("user", "role")
    )
    if not others:
        business.delete()
        return
    successor = _pick_successor(others)
    _reassign_protected_fks(user, successor, business)


def _pick_successor(memberships):
    def rank(membership):
        nom = membership.role.nom if membership.role else ""
        if nom == RoleNom.OWNER:
            return 0
        if nom == RoleNom.ADMIN:
            return 1
        return 2

    return min(memberships, key=rank).user


def _reassign_protected_fks(user, successor, business: Business):
    if business.created_by_id == user.id:
        business.created_by = successor
        business.save(update_fields=["created_by"])

    StockMovement.objects.filter(business=business, acteur=user).update(
        acteur=successor
    )
    StockAdjustment.objects.filter(business=business, acteur=user).update(
        acteur=successor
    )
    DecisionLog.objects.filter(business=business, acteur=user).update(
        acteur=successor
    )
    ActivityLog.objects.filter(business=business, acteur=user).update(
        acteur=successor
    )
    Reservation.objects.filter(business=business, reserve_par=user).update(
        reserve_par=successor
    )
