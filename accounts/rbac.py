"""Catalogue des permissions et rôles par défaut (RM-16, RM-17, RM-18, RM-19).

Les rôles système OWNER / ADMIN / MEMBER sont créés pour tout business.
Des rôles supplémentaires peuvent être pré-configurés selon le type de
business choisi à l'onboarding (config conditionnelle par tenant).
"""

from .models import Business, Permission, Role

# --- Constantes -----------------------------------------------------------


class Perm:
    BUSINESS_VIEW = "business.view"
    BUSINESS_UPDATE = "business.update"
    MEMBER_VIEW = "member.view"
    MEMBER_INVITE = "member.invite"
    MEMBER_ROLE_UPDATE = "member.role_update"
    MEMBER_REMOVE = "member.remove"
    ROLE_VIEW = "role.view"
    ROLE_MANAGE = "role.manage"
    CATALOG_VIEW = "catalog.view"
    ITEM_EDIT = "item.edit"
    CATALOG_MANAGE = "catalog.manage"
    STOCK_VIEW = "stock.view"
    STOCK_MOUVEMENT = "stock.mouvement"
    STOCK_INVENTAIRE = "stock.inventaire"
    STOCK_EXCEPTION = "stock.exception"
    BUSINESS_RULES = "business.rules"
    ENTRETIEN_VIEW = "entretien.view"
    ENTRETIEN_MANAGE = "entretien.manage"
    ACTIVITY_VIEW = "activity.view"
    RESERVATION_VIEW = "reservation.view"
    RESERVATION_MANAGE = "reservation.manage"


class RoleNom:
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    MEMBER = "MEMBER"


PERMISSIONS_CATALOG = [
    (Perm.BUSINESS_VIEW, "Voir le business", "Consulter les informations du business."),
    (Perm.BUSINESS_UPDATE, "Modifier le business", "Modifier les informations du business."),
    (Perm.MEMBER_VIEW, "Voir les membres", "Lister les membres du business."),
    (Perm.MEMBER_INVITE, "Inviter un membre", "Inviter un collaborateur dans le business."),
    (Perm.MEMBER_ROLE_UPDATE, "Attribuer un rôle", "Changer le rôle ou le statut d'un membre."),
    (Perm.MEMBER_REMOVE, "Retirer un membre", "Bloquer ou retirer un membre du business."),
    (Perm.ROLE_VIEW, "Voir les rôles", "Consulter les rôles et leurs permissions."),
    (Perm.ROLE_MANAGE, "Gérer les rôles", "Créer, modifier et supprimer des rôles et permissions."),
    (Perm.CATALOG_VIEW, "Voir le catalogue", "Consulter les catégories et les articles."),
    (Perm.ITEM_EDIT, "Gérer les articles", "Créer et modifier des articles et leurs photos."),
    (Perm.CATALOG_MANAGE, "Gérer le catalogue", "Gérer les catégories et supprimer des articles."),
    (Perm.STOCK_VIEW, "Voir le stock", "Consulter les états de stock et l'historique des mouvements."),
    (Perm.STOCK_MOUVEMENT, "Enregistrer un mouvement", "Créer entrées, sorties, retours, pertes et dommages."),
    (Perm.STOCK_INVENTAIRE, "Gérer les inventaires", "Lancer un inventaire, saisir les comptages, clôturer et ajuster le stock."),
    (Perm.STOCK_EXCEPTION, "Décision exceptionnelle", "Utiliser un article malgré un avertissement, avec décision tracée (RM-06)."),
    (Perm.BUSINESS_RULES, "Configurer les règles métier", "Choisir avertissement ou blocage obligatoire pour chaque règle (RM-07)."),
    (Perm.ENTRETIEN_VIEW, "Voir l'entretien", "Consulter les procédures, les tâches et les états d'entretien."),
    (Perm.ENTRETIEN_MANAGE, "Gérer l'entretien", "Configurer les procédures, créer et suivre les tâches d'entretien."),
    (Perm.ACTIVITY_VIEW, "Voir l'activité", "Consulter le flux d'activité de l'équipe (RM-20)."),
    (Perm.RESERVATION_VIEW, "Voir les réservations", "Consulter les réservations et en créer une (US-29)."),
    (Perm.RESERVATION_MANAGE, "Gérer les réservations", "Valider, annuler, démarrer et terminer les réservations (US-30, US-31)."),
]

# Répartition initiale : équipe légère (RM-18), responsabilités claires (RM-16)
DEFAULT_ROLES = {
    RoleNom.OWNER: {p[0] for p in PERMISSIONS_CATALOG},
    RoleNom.ADMIN: {
        Perm.BUSINESS_VIEW,
        Perm.MEMBER_VIEW,
        Perm.MEMBER_INVITE,
        Perm.MEMBER_ROLE_UPDATE,
        Perm.MEMBER_REMOVE,
        Perm.ROLE_VIEW,
        Perm.CATALOG_VIEW,
        Perm.ITEM_EDIT,
        Perm.CATALOG_MANAGE,
        Perm.STOCK_VIEW,
        Perm.STOCK_MOUVEMENT,
        Perm.STOCK_INVENTAIRE,
        Perm.STOCK_EXCEPTION,
        Perm.BUSINESS_RULES,
        Perm.ENTRETIEN_VIEW,
        Perm.ENTRETIEN_MANAGE,
        Perm.RESERVATION_VIEW,
        Perm.RESERVATION_MANAGE,
    },
    RoleNom.MEMBER: {
        Perm.BUSINESS_VIEW,
        Perm.MEMBER_VIEW,
        Perm.ROLE_VIEW,
        Perm.CATALOG_VIEW,
        Perm.STOCK_VIEW,
        Perm.ENTRETIEN_VIEW,
        Perm.ACTIVITY_VIEW,
        Perm.RESERVATION_VIEW,
    },
}

# Rôles métier pré-configurés par type de business (config conditionnelle).
# Ex. : pour la location & décoration, un rôle GESTIONNAIRE (opérateur stock
# et catalogue, cœur du suivi des sorties/retours - Spr. 3 et Entretien - Spr 4).
TYPE_SPECIFIC_ROLES = {
    Business.BusinessType.DECORATION_RENTAL: {
        "GESTIONNAIRE": {
            Perm.BUSINESS_VIEW,
            Perm.CATALOG_VIEW,
            Perm.ITEM_EDIT,
            Perm.STOCK_VIEW,
            Perm.STOCK_MOUVEMENT,
            Perm.STOCK_INVENTAIRE,
            Perm.STOCK_EXCEPTION,
            Perm.BUSINESS_RULES,
            Perm.ROLE_VIEW,
            Perm.ENTRETIEN_VIEW,
            Perm.ENTRETIEN_MANAGE,
            Perm.ACTIVITY_VIEW,
            Perm.RESERVATION_VIEW,
            Perm.RESERVATION_MANAGE,
        },
    },
    Business.BusinessType.GENERAL_INVENTORY: {},
}


def seed_permission_catalog():
    """Crée le catalogue de permissions s'il n'existe pas encore."""
    for codename, libelle, description in PERMISSIONS_CATALOG:
        Permission.objects.get_or_create(
            codename=codename,
            defaults={"libelle": libelle, "description": description},
        )
    return Permission.objects.all()


def seed_default_roles(business):
    """Crée les rôles système + rôles spécifiques au type du business."""
    permissions = {p.codename: p for p in seed_permission_catalog()}
    roles = {}
    for nom, codes in DEFAULT_ROLES.items():
        role, _ = Role.objects.get_or_create(
            business=business, nom=nom, defaults={"is_system": True}
        )
        role.permissions.set([permissions[c] for c in codes])
        roles[nom] = role
    for nom, codes in TYPE_SPECIFIC_ROLES.get(business.business_type, {}).items():
        role, _ = Role.objects.get_or_create(
            business=business,
            nom=nom,
            defaults={"is_system": True, "description": f"Rôle métier ({business.business_type})"},
        )
        role.permissions.set([permissions[c] for c in codes])
        roles[nom] = role
    return roles


def role_has_permission(role, codename):
    if role is None:
        return False
    return role.permissions.filter(codename=codename).exists()