"""Moteur activité & notifications (Sprint 7, S 7-03 / S 7-08).

RM-20 : tout événement métier génère une entrée immuable dans le flux
d'activité du business (qui, quoi, quand — et sur quel article le cas
échéant). Les décisions et anomalies importantes génèrent aussi des
notifications par membre (US-28), isolées par business (RM-01, RM-21).
"""

import uuid as _uuid

from .models import ActivityLog, BusinessMember, Notification, User


def _json_safe(value):
    """Convertit récursivement les UUID en str (JSON ne les sérialise pas)."""
    if isinstance(value, _uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


class Act:
    """Vocabulaire des actions du flux d'activité."""

    BUSINESS_CREATE = "BUSINESS.CREATE"
    MEMBER_INVITE = "MEMBER.INVITE"
    MEMBER_ACTIVE = "MEMBER.ACTIVE"
    MEMBER_ROLE = "MEMBER.ROLE"
    MEMBER_REMOVE = "MEMBER.REMOVE"
    ROLE_CREATE = "ROLE.CREATE"
    ROLE_DELETE = "ROLE.DELETE"
    CATEGORY_CREATE = "CATEGORY.CREATE"
    CATEGORY_UPDATE = "CATEGORY.UPDATE"
    CATEGORY_DELETE = "CATEGORY.DELETE"
    ITEM_CREATE = "ITEM.CREATE"
    ITEM_UPDATE = "ITEM.UPDATE"
    ITEM_DELETE = "ITEM.DELETE"
    PROCEDURE_CREATE = "PROCEDURE.CREATE"
    PROCEDURE_UPDATE = "PROCEDURE.UPDATE"
    PROCEDURE_DELETE = "PROCEDURE.DELETE"
    STOCK_ENTREE = "STOCK.ENTREE"
    STOCK_SORTIE = "STOCK.SORTIE"
    STOCK_RETOUR = "STOCK.RETOUR"
    STOCK_PERTE = "STOCK.PERTE"
    STOCK_DOMMAGE = "STOCK.DOMMAGE"
    TASK_CREATE = "TASK.CREATE"
    TASK_STEP = "TASK.STEP"
    TASK_CLOTURE = "TASK.CLOTURE"
    INVENTORY_CREATE = "INVENTORY.CREATE"
    INVENTORY_COUNT = "INVENTORY.COUNT"
    INVENTORY_CLOTURE = "INVENTORY.CLOTURE"
    ADJUSTMENT_CREATE = "ADJUSTMENT.CREATE"
    DECISION_EXCEPTION = "DECISION.EXCEPTION"
    RULE_ALERTE = "RULE.ALERTE"
    RULE_BLOCAGE = "RULE.BLOCAGE"
    RESERVATION_CREATE = "RESERVATION.CREATE"
    RESERVATION_VALIDEE = "RESERVATION.VALIDEE"
    RESERVATION_ANNULEE = "RESERVATION.ANNULEE"
    RESERVATION_EN_COURS = "RESERVATION.EN_COURS"
    RESERVATION_TERMINEE = "RESERVATION.TERMINEE"
    # Sprint 1: Attribution des tâches
    TASK_ASSIGNED = "TASK.ASSIGNED"
    TASK_UNASSIGNED = "TASK.UNASSIGNED"
    TASK_COMMENT = "TASK.COMMENT"
    # Sprint 2: Photos sur les étapes
    STEP_PHOTO = "STEP.PHOTO"
    # Sprint 3: Tâches récurrentes
    RECURRING_CREATE = "RECURRING.CREATE"
    RECURRING_DELETE = "RECURRING.DELETE"
    # V2: Booking Request
    BOOKING_REQUEST_NEW = "BOOKING_REQUEST.NEW"
    BOOKING_REQUEST_ACCEPTED = "BOOKING_REQUEST.ACCEPTED"
    BOOKING_REQUEST_REFUSED = "BOOKING_REQUEST.REFUSED"
    BOOKING_REQUEST_CONTRE_PROPOSITION = "BOOKING_REQUEST.CONTRE_PROPOSITION"
    BOOKING_REQUEST_CANCELLED = "BOOKING_REQUEST.CANCELLED"
    # V4: Facturation
    INVOICE_CREATE = "INVOICE.CREATE"
    INVOICE_SENT = "INVOICE.SENT"
    INVOICE_PAID = "INVOICE.PAID"


def log_activity(*, business, acteur, action, item=None, cible="", detail=None):
    """Ajoute un événement immuable au flux d'activité de l'équipe (US-27)."""
    return ActivityLog.objects.create(
        business=business,
        acteur=acteur,
        action=action,
        item=item,
        cible=_json_safe(cible) or (_json_safe(item.nom) if item else ""),
        detail=_json_safe(detail or {}),
    )


def notify_members(
    *, business, code, message, item=None, permission_codename=None, ignore_user=None,
    user_ids=None
):
    """Notifie les membres ACTIFS du business (US-28), optionnellement
    ceux disposant d'une permission donnée (RM-19 : ciblage par rôle).

    Si user_ids est fourni, seuls ces utilisateurs spécifiques sont notifiés
    (Sprint 1 : notifications ciblées pour attribution de tâches).
    """
    if user_ids:
        # Notification ciblée à des utilisateurs spécifiques
        recipients = list(User.objects.filter(id__in=user_ids))
    else:
        memberships = BusinessMember.objects.filter(
            business=business, statut=BusinessMember.Statut.ACTIF
        ).select_related("user")
        if permission_codename:
            memberships = memberships.filter(role__permissions__codename=permission_codename)
        recipients = [
            m.user
            for m in memberships.distinct()
            if m.user_id != (ignore_user.id if ignore_user else None)
        ]
    if not recipients:
        return 0
    Notification.objects.bulk_create(
        [
            Notification(business=business, user=user, code=code, message=message, item=item)
            for user in recipients
        ]
    )
    return len(recipients)