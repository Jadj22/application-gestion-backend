"""
Contrôle d'accès multi-tenant (RM-01 : un business ne voit jamais les données
d'un autre) + RBAC (RM-19 : permissions sur opérations sensibles).

Chaque requête protégée doit porter le header X-Business-ID et l'utilisateur
doit être membre ACTIF de ce business avec la permission requise.
"""

import uuid

from django.conf import settings
from rest_framework.permissions import BasePermission

from .models import Business, BusinessMember


def get_business_id(request):
    return request.headers.get(settings.BUSINESS_HEADER)


def parse_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None


def get_membership(request, allow_inactive=False):
    """Retourne la membership de request.user dans le business du header."""
    business_id = parse_uuid(get_business_id(request))
    if business_id is None:
        return None
    try:
        business = Business.objects.get(id=business_id)
    except Business.DoesNotExist:
        return None
    membership = BusinessMember.objects.filter(
        business=business, user=request.user
    ).select_related("role", "user", "business").first()
    if membership is None:
        return None
    if not allow_inactive and membership.statut != BusinessMember.Statut.ACTIF:
        return None
    return membership


class HasBusinessPermission(BasePermission):
    """Vérifie : header X-Business-ID + membre ACTIF + permission requise."""

    _codename = None
    message = "Accès refusé : business invalide ou permission manquante."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        membership = get_membership(request)
        if membership is None:
            return False
        business_id = view.kwargs.get("business_id") if view is not None else None
        if business_id is not None and parse_uuid(business_id) != membership.business_id:
            return False
        request.business = membership.business
        request.membership = membership
        if self._codename is None:
            return True
        return membership.role is not None and membership.role.permissions.filter(
            codename=self._codename
        ).exists()

    @classmethod
    def require(cls, codename):
        """Fabrique une classe de permission vérifiant un codename donné."""
        name = f"HasBusinessPermission_{codename.replace('.', '_')}"
        return type(name, (cls,), {"_codename": codename})


class IsSelfMember(BasePermission):
    """Autorise un utilisateur à accepter sa propre invitation."""

    message = "Vous n'êtes pas concerné par cette invitation."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        membership = get_membership(request, allow_inactive=True)
        if membership is None or membership.user_id != request.user.id:
            return False
        if membership.statut == BusinessMember.Statut.BLOQUE:
            return False
        request.business = membership.business
        request.membership = membership
        return True