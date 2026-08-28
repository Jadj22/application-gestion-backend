"""Moteur des réservations (Sprint 8, S 8-02).

US-29 : un membre réserve un article sur une plage de dates (motif,
quantité). US-30 : un gestionnaire valide ou annule la réservation.
US-31 : le démarrage crée une sortie de stock, la terminaison crée le
retour (qui relance l'éventuel entretien automatique — RM-10).

Règles :
  - pas de chevauchement de plages pour un même article (hors réservations
    terminées ou annulées) ;
  - exposition pleine : les quantités réservées simultanément sur une plage
    ne peuvent pas dépasser le stock disponible souhaité à la création.
"""

from datetime import date

from django.db import transaction
from django.db.models import Q, Sum
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from .activite import Act, log_activity, notify_members
from .models import Item, Notification, Reservation
from .rbac import Perm
from .stock import create_movement, snapshot


def _chevauchant(qs, date_debut, date_fin):
    """Réservations actives dont la plage chevauche [date_debut, date_fin]."""
    return qs.filter(
        Q(date_debut__lte=date_fin) & Q(date_fin__gte=date_debut)
    )


def _reservations_actives(item):
    return item.reservations.exclude(statut__in=[
        Reservation.Statut.TERMINEE,
        Reservation.Statut.ANNULEE,
    ])


def _valider_et_creer_une(
    *, business, item, reserve_par, date_debut, date_fin, quantite, motif,
    lieu_nom="", lieu_adresse="", contact_nom="", contact_telephone="",
    livraison_prevue_le=None, reprise_prevue_le=None, notes_livraison="",
):
    """Verrouille l'article, contrôle capacité + chevauchement, puis crée la
    réservation. Doit être appelé à l'intérieur d'une transaction déjà
    ouverte par l'appelant (le verrou est levé à la fin de CETTE transaction,
    pas de celle-ci seule) — c'est ce qui permet à `create_reservations_bulk`
    de composer plusieurs appels dans une seule transaction atomique.

    Exposition pleine : la somme des quantités déjà réservées sur les plages
    chevauchant la demande + la quantité demandée ne peut pas dépasser le
    stock total possédé de l'article (source de vérité : moteur de stock).
    """
    if quantite < 1:
        raise ValidationError("La quantité doit être d'au moins 1.")
    if item.business_id != business.id:
        raise ValidationError("Article invalide pour ce business.")

    item = Item.objects.select_for_update().get(pk=item.pk)
    capacite = snapshot(item)["total"]
    if quantite > capacite:
        raise ValidationError(
            f"Exposition pleine : {capacite} unité(s) au total "
            f"pour {item.nom}."
        )
    deja_reserve = _chevauchant(
        _reservations_actives(item), date_debut, date_fin
    ).aggregate(total=Sum("quantite"))["total"] or 0
    if deja_reserve + quantite > capacite:
        restant = max(capacite - deja_reserve, 0)
        raise ValidationError(
            f"Disponibilité insuffisante pour {item.nom} sur cette période : "
            f"{restant} unité(s) restante(s) sur {capacite} "
            f"({deja_reserve} déjà réservée(s) sur une plage chevauchante)."
        )
    reservation = Reservation.objects.create(
        business=business,
        item=item,
        reserve_par=reserve_par,
        date_debut=date_debut,
        date_fin=date_fin,
        quantite=quantite,
        motif=motif,
        lieu_nom=lieu_nom,
        lieu_adresse=lieu_adresse,
        contact_nom=contact_nom,
        contact_telephone=contact_telephone,
        livraison_prevue_le=livraison_prevue_le,
        reprise_prevue_le=reprise_prevue_le,
        notes_livraison=notes_livraison,
    )
    log_activity(
        business=business,
        acteur=reserve_par,
        action=Act.RESERVATION_CREATE,
        item=item,
        cible=f"{date_debut} -> {date_fin}",
        detail={
            "quantite": quantite,
            "reservation": str(reservation.id),
            "lieu_nom": lieu_nom,
        },
    )
    return reservation


def _parse_dates(date_debut, date_fin):
    if isinstance(date_debut, str):
        date_debut = date.fromisoformat(date_debut)
    if isinstance(date_fin, str):
        date_fin = date.fromisoformat(date_fin)
    if date_fin < date_debut:
        raise ValidationError("La date de fin doit être postérieure ou égale "
                              "à la date de début.")
    return date_debut, date_fin


def create_reservation(
    *, business, item, reserve_par, date_debut, date_fin,
    quantite=1, motif="",
    lieu_nom="", lieu_adresse="", contact_nom="", contact_telephone="",
    livraison_prevue_le=None, reprise_prevue_le=None, notes_livraison="",
):
    """Crée une réservation EN_ATTENTE (US-29) avec contrôle d'occupation."""
    date_debut, date_fin = _parse_dates(date_debut, date_fin)
    with transaction.atomic():
        reservation = _valider_et_creer_une(
            business=business,
            item=item,
            reserve_par=reserve_par,
            date_debut=date_debut,
            date_fin=date_fin,
            quantite=quantite,
            motif=motif,
            lieu_nom=lieu_nom,
            lieu_adresse=lieu_adresse,
            contact_nom=contact_nom,
            contact_telephone=contact_telephone,
            livraison_prevue_le=livraison_prevue_le,
            reprise_prevue_le=reprise_prevue_le,
            notes_livraison=notes_livraison,
        )
        notify_members(
            business=business,
            code="RESERVATION.CREATE",
            message=f"Nouvelle réservation : {reservation.item.nom} "
                    f"({date_debut} -> {date_fin}).",
            item=reservation.item,
            permission_codename=Perm.RESERVATION_MANAGE,
            ignore_user=reserve_par,
        )
        return reservation


def create_reservations_bulk(
    *, business, items_quantites, reserve_par, date_debut, date_fin, motif="",
    lieu_nom="", lieu_adresse="", contact_nom="", contact_telephone="",
    livraison_prevue_le=None, reprise_prevue_le=None, notes_livraison="",
):
    """Crée plusieurs réservations (une par article) de façon atomique.

    `items_quantites` : liste de tuples `(item, quantite)` ou `(item, dict_data)`.
    Si dict_data, il peut contenir : quantite, lieu_nom, lieu_adresse, contact_nom,
    contact_telephone, notes_livraison (per-item, override les valeurs communes).

    Toutes les réservations demandées sont créées dans une seule transaction : si un
    seul article échoue (chevauchement, exposition pleine, article invalide),
    AUCUNE réservation n'est créée (US-29, cohérence multi-articles — évite
    les réservations partielles qu'on obtenait en appelant `create_reservation`
    en boucle depuis le client).
    """
    date_debut, date_fin = _parse_dates(date_debut, date_fin)
    if not items_quantites:
        raise ValidationError("Sélectionnez au moins un article.")

    with transaction.atomic():
        # Verrouille les articles dans un ordre stable (évite les deadlocks
        # si deux requêtes bulk se chevauchent sur les mêmes articles).
        ordonnes = sorted(items_quantites, key=lambda pair: str(pair[0].pk))
        created = []
        for item, data in ordonnes:
            if isinstance(data, dict):
                quantite = data.get("quantite", 1)
                # Per-item override des champs localisation
                item_lieu_nom = data.get("lieu_nom", lieu_nom)
                item_lieu_adresse = data.get("lieu_adresse", lieu_adresse)
                item_contact_nom = data.get("contact_nom", contact_nom)
                item_contact_telephone = data.get("contact_telephone", contact_telephone)
                item_notes_livraison = data.get("notes_livraison", notes_livraison)
            else:
                quantite = data
                item_lieu_nom = lieu_nom
                item_lieu_adresse = lieu_adresse
                item_contact_nom = contact_nom
                item_contact_telephone = contact_telephone
                item_notes_livraison = notes_livraison
            created.append(
                _valider_et_creer_une(
                    business=business,
                    item=item,
                    reserve_par=reserve_par,
                    date_debut=date_debut,
                    date_fin=date_fin,
                    quantite=quantite,
                    motif=motif,
                    lieu_nom=item_lieu_nom,
                    lieu_adresse=item_lieu_adresse,
                    contact_nom=item_contact_nom,
                    contact_telephone=item_contact_telephone,
                    livraison_prevue_le=livraison_prevue_le,
                    reprise_prevue_le=reprise_prevue_le,
                    notes_livraison=item_notes_livraison,
                )
            )
        if len(created) == 1:
            message = (
                f"Nouvelle réservation : {created[0].item.nom} "
                f"({date_debut} -> {date_fin})."
            )
        else:
            noms = ", ".join(r.item.nom for r in created)
            message = (
                f"Nouvelle réservation ({len(created)} articles) : {noms} "
                f"({date_debut} -> {date_fin})."
            )
        notify_members(
            business=business,
            code="RESERVATION.CREATE",
            message=message,
            permission_codename=Perm.RESERVATION_MANAGE,
            ignore_user=reserve_par,
        )
        return created


def valider_reservation(*, reservation, acteur):
    """Valide une réservation EN_ATTENTE (US-30, permission manage)."""
    if reservation.statut != Reservation.Statut.EN_ATTENTE:
        raise ValidationError(
            f"Impossible de valider une réservation {reservation.statut}."
        )
    with transaction.atomic():
        reservation.statut = Reservation.Statut.VALIDEE
        reservation.save(update_fields=["statut", "updated_at"])
        log_activity(
            business=reservation.business,
            acteur=acteur,
            action=Act.RESERVATION_VALIDEE,
            item=reservation.item,
            cible=str(reservation.id),
            detail={"quantite": reservation.quantite},
        )
        Notification.objects.create(
            business=reservation.business,
            user=reservation.reserve_par,
            code="RESERVATION.VALIDEE",
            message=f"Votre réservation de {reservation.item.nom} "
                    f"({reservation.date_debut} -> {reservation.date_fin}) "
                    f"est validée.",
            item=reservation.item,
        )
    return reservation


def annuler_reservation(*, reservation, acteur, motif=""):
    """Annule une réservation EN_ATTENTE ou VALIDEE (US-30)."""
    if reservation.statut in (
        Reservation.Statut.TERMINEE,
        Reservation.Statut.ANNULEE,
    ):
        raise ValidationError(
            f"Impossible d'annuler une réservation {reservation.statut}."
        )
    with transaction.atomic():
        reservation.statut = Reservation.Statut.ANNULEE
        reservation.save(update_fields=["statut", "updated_at"])
        log_activity(
            business=reservation.business,
            acteur=acteur,
            action=Act.RESERVATION_ANNULEE,
            item=reservation.item,
            cible=str(reservation.id),
            detail={"quantite": reservation.quantite, "motif": motif},
        )
        notify_members(
            business=reservation.business,
            code="RESERVATION.ANNULEE",
            message=f"Réservation annulée : {reservation.item.nom} "
                    f"({reservation.date_debut} -> {reservation.date_fin}).",
            item=reservation.item,
            permission_codename=Perm.RESERVATION_MANAGE,
            ignore_user=acteur,
        )
        Notification.objects.create(
            business=reservation.business,
            user=reservation.reserve_par,
            code="RESERVATION.ANNULEE",
            message=f"Votre réservation de {reservation.item.nom} "
                    f"({reservation.date_debut} -> {reservation.date_fin}) "
                    f"est annulée.",
            item=reservation.item,
        )
    return reservation


def demarrer_reservation(*, reservation, acteur):
    """Démarre la réservation : VALIDEE -> EN_COURS + sortie de stock."""
    if reservation.statut != Reservation.Statut.VALIDEE:
        raise ValidationError(
            f"Impossible de démarrer une réservation {reservation.statut}."
        )
    with transaction.atomic():
        create_movement(
            business=reservation.business,
            item=reservation.item,
            type="SORTIE",
            quantite=reservation.quantite,
            acteur=acteur,
            motif="Sortie réservation",
            reference=str(reservation.id),
        )
        reservation.statut = Reservation.Statut.EN_COURS
        reservation.save(update_fields=["statut", "updated_at"])
        log_activity(
            business=reservation.business,
            acteur=acteur,
            action=Act.RESERVATION_EN_COURS,
            item=reservation.item,
            cible=str(reservation.id),
            detail={"quantite": reservation.quantite},
        )
    return reservation


def terminer_reservation(
    *, reservation, acteur,
    quantite_retournee=None, quantite_abimee=None, quantite_perdue=None,
    observations="",
):
    """Termine : EN_COURS -> TERMINEE + retour de stock (US-31).

    Contrôle de retour (Sprint 8 bis) : au moment de terminer, le
    gestionnaire décompose la quantité réservée entre unités rendues en
    bon état, abîmées et perdues. Si les trois valeurs sont absentes,
    comportement historique : tout est considéré rendu en bon état.

    Comptabilité des mouvements (cohérente avec les états du stock) :
      - RETOUR de toutes les unités traitées (bonnes + abîmées + perdues)
        pour solder la sortie ;
      - DOMMAGE des abîmées (présentes mais inutilisables) ;
      - PERTE des perdues (retirées du total possédé).
    """
    if reservation.statut != Reservation.Statut.EN_COURS:
        raise ValidationError(
            f"Impossible de terminer une réservation {reservation.statut}."
        )
    controle = any(
        v is not None for v in (quantite_retournee, quantite_abimee, quantite_perdue)
    )
    if controle:
        quantite_retournee = quantite_retournee or 0
        quantite_abimee = quantite_abimee or 0
        quantite_perdue = quantite_perdue or 0
        if quantite_retournee + quantite_abimee + quantite_perdue != reservation.quantite:
            raise ValidationError(
                f"Le décompte du retour ({quantite_retournee} retourné(s), "
                f"{quantite_abimee} abîmé(s), {quantite_perdue} perdu(s)) ne "
                f"correspond pas à la quantité réservée ({reservation.quantite})."
            )
    else:
        quantite_retournee, quantite_abimee, quantite_perdue = (
            reservation.quantite, 0, 0
        )
    with transaction.atomic():
        create_movement(
            business=reservation.business,
            item=reservation.item,
            type="RETOUR",
            quantite=quantite_retournee + quantite_abimee + quantite_perdue,
            acteur=acteur,
            motif="Retour réservation",
            reference=str(reservation.id),
        )
        if quantite_abimee:
            create_movement(
                business=reservation.business,
                item=reservation.item,
                type="DOMMAGE",
                quantite=quantite_abimee,
                acteur=acteur,
                motif="Article(s) abîmé(s) au retour de la réservation",
                reference=str(reservation.id),
            )
        if quantite_perdue:
            create_movement(
                business=reservation.business,
                item=reservation.item,
                type="PERTE",
                quantite=quantite_perdue,
                acteur=acteur,
                motif="Article(s) perdu(s) pendant la réservation",
                reference=str(reservation.id),
            )
        reservation.quantite_retournee = quantite_retournee
        reservation.quantite_abimee = quantite_abimee
        reservation.quantite_perdue = quantite_perdue
        reservation.observations = observations
        reservation.retourne_le = timezone.now()
        reservation.statut = Reservation.Statut.TERMINEE
        reservation.save(update_fields=[
            "quantite_retournee", "quantite_abimee", "quantite_perdue",
            "observations", "retourne_le", "statut", "updated_at",
        ])
        log_activity(
            business=reservation.business,
            acteur=acteur,
            action=Act.RESERVATION_TERMINEE,
            item=reservation.item,
            cible=str(reservation.id),
            detail={
                "quantite": reservation.quantite,
                "retourne": quantite_retournee,
                "abime": quantite_abimee,
                "perdu": quantite_perdue,
                "observations": observations,
            },
        )
        if quantite_abimee or quantite_perdue:
            notify_members(
                business=reservation.business,
                code="RESERVATION.RETOUR",
                message=f"Retour de {reservation.item.nom} : "
                        f"{quantite_retournee} rendu(s), {quantite_abimee} "
                        f"abîmé(s), {quantite_perdue} perdu(s).",
                item=reservation.item,
                permission_codename=Perm.RESERVATION_MANAGE,
                ignore_user=acteur,
            )
    return reservation