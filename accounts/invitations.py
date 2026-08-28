"""Invitations par code (Sprint 11) + lien signé (Sprint 10, conservé).

Flux : POST /members/ crée le membership à l'état INVITE, génère un code
unique `DODO-XXXXXX` (haché en base, jamais en clair) puis envoie l'email
d'invitation contenant le code. L'invité saisit le code dans l'app →
POST /invitations/validate/ (aperçu) → POST /invitations/accept/
(activation + BusinessMember ACTIF).

Le lien signé (TimestampSigner) reste supporté pour la compatibilité deep
link : GET /invitations/<token>/ et POST /invitations/accept/ acceptent
toujours le token historique. Le code est le mécanisme fonctionnel actuel ;
le lien pourra redevenir le canal principal en production sans réécriture.

Le code est à usage unique : il n'est accepté que tant que le membership
reste INVITE (et non expiré), et l'acceptation le passe à ACTIF.
"""

import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.core import signing
from django.core.mail import EmailMultiAlternatives
from django.utils import timezone

from .models import BusinessMember

SALT = "dodome.invitation"

# Alphabet sans caractères ambigus (pas de O/0, I/1, L) : 32 symboles.
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_PREFIX = "DODO"
CODE_LENGTH = 6


def normalize_code(raw):
    """Normalise une saisie : majuscules, sans espaces ni tirets.

    `dodo-8f42k`, `DODO 8F42K` et `DODO8F42K` désignent le même code.
    """
    return "".join(ch for ch in str(raw or "").upper() if ch.isalnum())


def hash_code(code):
    """Empreinte d'un code normalisé : le code n'est jamais stocké en clair."""
    secret = settings.INVITATION_CODE_SALT
    return hashlib.sha256(f"{normalize_code(code)}|{secret}".encode()).hexdigest()


def format_code(code):
    """Affichage lisible : DODO8F42K -> DODO-8F42K."""
    normalized = normalize_code(code)
    if normalized.startswith(CODE_PREFIX) and len(normalized) > len(CODE_PREFIX):
        return f"{normalized[:len(CODE_PREFIX)]}-{normalized[len(CODE_PREFIX):]}"
    return normalized


def generate_code():
    """Génère un code unique `DODO` + 6 symboles (32^6 ≈ 1,07 milliard)."""
    for _ in range(20):
        suffix = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
        code = f"{CODE_PREFIX}{suffix}"
        if not BusinessMember.objects.filter(code_hash=hash_code(code)).exists():
            return code
    raise RuntimeError("Impossible de générer un code d'invitation unique.")


def issue_code(membership, save=True):
    """Génère, hash et enregistre un code sur le membership ; le renvoie
    (non haché) pour l'email et la réponse API. Prolonge l'expiration."""
    code = generate_code()
    membership.code_hash = hash_code(code)
    membership.expires_at = timezone.now() + timedelta(
        seconds=settings.INVITATION_CODE_DAYS * 86400
    )
    if save:
        membership.save(update_fields=["code_hash", "expires_at"])
    return code


def invitation_state(membership, now=None):
    """Statut effectif d'une invitation : EXPIRED est déduit de expires_at
    à la validation (le champ statut peut rester INVITE en base)."""
    if membership.statut == BusinessMember.Statut.INVITE:
        if membership.expires_at is not None:
            now = now or timezone.now()
            if now >= membership.expires_at:
                return BusinessMember.Statut.EXPIRED
    return membership.statut


def make_invitation_token(membership):
    """Token signé + horodaté pour un membership invité (compat deep link)."""
    signer = signing.TimestampSigner(salt=SALT)
    payload = f"{membership.id}:{membership.user.email.lower()}"
    return signer.sign(payload)


def _unsign(token):
    signer = signing.TimestampSigner(salt=SALT)
    try:
        return signer.unsign(token, max_age=settings.INVITATION_TOKEN_MAX_AGE)
    except signing.BadSignature:
        return None


def invitation_link(token):
    """URL publique du lien d'invitation (base configurable)."""
    base = settings.INVITATION_BASE_URL.rstrip("/")
    return f"{base}?token={token}"


def resolve_invitation(token):
    """Résout le token vers un BusinessMember, ou None si invalide/expiré.

    Le token reste lié au couple membership + email : rejouer un lien déjà
    accepté est bloqué en amont car le membership n'est alors plus INVITE.
    """
    payload = _unsign(token)
    if payload is None:
        return None
    member_id, sep, email = payload.partition(":")
    if not sep:
        return None
    membership = (
        BusinessMember.objects.filter(id=member_id)
        .select_related("user", "business", "role", "invited_by")
        .first()
    )
    if membership is None or membership.user.email.lower() != email:
        return None
    return membership


def resolve_invitation_by_code(raw_code):
    """Résout un code saisi (normalisé) vers un BusinessMember, ou None.

    La recherche se fait sur l'empreinte du code normalisé : aucun code
    n'est stocké en clair en base.
    """
    normalized = normalize_code(raw_code)
    if not normalized:
        return None
    return (
        BusinessMember.objects.filter(code_hash=hash_code(normalized))
        .select_related("user", "business", "role", "invited_by")
        .first()
    )


def _inviteur_display(membership):
    if not membership.invited_by:
        return "Un administrateur"
    inv = membership.invited_by
    return inv.get_full_name() or inv.first_name or inv.email


def _expiration_display(membership):
    if membership.expires_at is None:
        return "bientôt"
    return membership.expires_at.strftime("%d/%m/%Y à %H:%M")


def send_invitation_email(membership, code, link=None):
    """Envoie l'email d'invitation avec le code ; False si l'envoi échoue.

    La création de l'invitation réussit même sans SMTP : le code est aussi
    renvoyé dans la réponse API pour être partagé manuellement.
    """
    try:
        prenom = membership.user.first_name
        inviteur = _inviteur_display(membership)
        role = membership.role.nom if membership.role else "Membre"
        display = format_code(code)
        expires = _expiration_display(membership)
        subject = f"Invitation à rejoindre {membership.business.nom} sur DODOME"
        message = (
            f"Bonjour{prenom and ' ' + prenom or ''},\n\n"
            f"{inviteur} vous invite à rejoindre « {membership.business.nom} » "
            f"avec le rôle {role}.\n\n"
            f"Pour accepter cette invitation :\n"
            f"1. Téléchargez ou ouvrez l'application DODOME.\n"
            f"2. Sélectionnez « Vous avez reçu une invitation ? ».\n"
            f"3. Entrez le code d'invitation ci-dessous.\n\n"
            f"Votre code d'invitation : {display}\n\n"
            f"Cette invitation expire le {expires}.\n\n"
            f"Si vous n'êtes pas à l'origine de cette demande, "
            f"vous pouvez ignorer cet email.\n"
            f"L'équipe DODOME."
        )
        html = f"""
<div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;
            padding:24px;color:#1a2b45;">
  <h2 style="margin:0 0 8px;">Vous avez été invité à rejoindre DODOME</h2>
  <p style="color:#55657e;">{inviteur} vous invite à rejoindre :</p>
  <p style="font-size:18px;font-weight:bold;margin:4px 0;">{membership.business.nom}</p>
  <p style="color:#55657e;">Rôle : <strong>{role}</strong></p>
  <p style="margin:20px 0 8px;">Pour accepter cette invitation :</p>
  <ol style="color:#55657e;margin:0 0 16px;padding-left:20px;">
    <li>Téléchargez ou ouvrez l'application DODOME.</li>
    <li>Sélectionnez « Vous avez reçu une invitation ? ».</li>
    <li>Entrez le code d'invitation ci-dessous.</li>
  </ol>
  <div style="background:#f2f6fb;border:1px solid #dbe5f2;border-radius:12px;
              padding:16px;text-align:center;">
    <div style="font-size:12px;color:#55657e;text-transform:uppercase;
                letter-spacing:1px;">Votre code d'invitation</div>
    <div style="font-size:28px;font-weight:bold;letter-spacing:4px;
                color:#1a2b45;margin-top:6px;">{display}</div>
  </div>
  <p style="color:#55657e;margin-top:16px;">
    Cette invitation expire le <strong>{expires}</strong>.
  </p>
  <p style="color:#8a94a6;font-size:13px;margin-top:12px;">
    Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer
    cet email.
  </p>
</div>
"""
        email = EmailMultiAlternatives(
            subject=subject,
            body=message,
            from_email=None,
            to=[membership.user.email],
        )
        email.attach_alternative(html, "text/html")
        email.send(fail_silently=False)
        return True
    except Exception:
        return False


# ============================================================
# Emails pour les demandes de réservation (BookingRequest)
# ============================================================

def send_booking_request_accepted_email(booking_request, reservation_id):
    """Envoie un email au client quand sa demande est acceptée."""
    try:
        subject = f"Votre demande de location a été acceptée — {booking_request.item.business.nom}"
        
        message = (
            f"Bonjour {booking_request.client_nom},\n\n"
            f"Bonne nouvelle ! Votre demande de location a été acceptée par {booking_request.item.business.nom}.\n\n"
            f"Détails de votre réservation :\n"
            f"• Article : {booking_request.item.nom}\n"
            f"• Période : {booking_request.date_debut.strftime('%d/%m/%Y')} au {booking_request.date_fin.strftime('%d/%m/%Y')}\n"
            f"• Quantité : {booking_request.quantite}\n"
            f"• Lieu de livraison : {booking_request.lieu_nom or 'Non précisé'} ({booking_request.lieu_adresse or ''})\n"
            f"• Contact sur place : {booking_request.contact_nom or 'Non précisé'} ({booking_request.contact_telephone or ''})\n\n"
            f"Numéro de réservation : {reservation_id}\n\n"
            f"Le professionnel vous recontactera prochainement pour organiser la livraison.\n\n"
            f"Vous pouvez suivre l'état de votre réservation via votre lien de suivi.\n\n"
            f"L'équipe {booking_request.item.business.nom}."
        )
        
        html = f"""
        <div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#1a2b45;">
          <h2 style="margin:0 0 8px;color:#16a34a;">✅ Demande acceptée !</h2>
          <p style="color:#55657e;">Bonjour <strong>{booking_request.client_nom}</strong>,</p>
          <p style="color:#55657e;">Bonne nouvelle ! Votre demande de location a été acceptée par <strong>{booking_request.item.business.nom}</strong>.</p>
          
          <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:12px;padding:16px;margin:16px 0;">
            <h3 style="margin:0 0 12px;font-size:16px;color:#166534;">Détails de la réservation</h3>
            <ul style="margin:0;padding-left:20px;color:#1a2b45;">
              <li><strong>Article :</strong> {booking_request.item.nom}</li>
              <li><strong>Période :</strong> {booking_request.date_debut.strftime('%d/%m/%Y')} au {booking_request.date_fin.strftime('%d/%m/%Y')}</li>
              <li><strong>Quantité :</strong> {booking_request.quantite}</li>
              <li><strong>Lieu :</strong> {booking_request.lieu_nom or 'Non précisé'}</li>
              <li><strong>Contact :</strong> {booking_request.contact_nom or 'Non précisé'} ({booking_request.contact_telephone or ''})</li>
            </ul>
            <p style="margin:12px 0 0;color:#166534;"><strong>N° Réservation :</strong> {reservation_id}</p>
          </div>
          
          <p style="color:#55657e;">Le professionnel vous recontactera prochainement pour organiser la livraison.</p>
          <p style="color:#55657e;">Vous pouvez suivre l'état de votre réservation via votre lien de suivi.</p>
          
          <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">
          <p style="color:#8a94a6;font-size:13px;margin-top:12px;">L'équipe {booking_request.item.business.nom}.</p>
        </div>
        """
        
        email = EmailMultiAlternatives(
            subject=f"✅ Votre demande a été acceptée — {booking_request.item.business.nom}",
            body=f"Bonjour {booking_request.client_nom},\n\nVotre demande de location a été acceptée.\n\nDétails :\n• Article : {booking_request.item.nom}\n• Période : {booking_request.date_debut.strftime('%d/%m/%Y')} au {booking_request.date_fin.strftime('%d/%m/%Y')}\n• Quantité : {booking_request.quantite}\n• N° Réservation : {reservation_id}\n\nLe professionnel vous recontactera pour organiser la livraison.",
            from_email=None,
            to=[booking_request.client_email],
        )
        email.attach_alternative(html, "text/html")
        email.send(fail_silently=False)
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Failed to send booking accepted email")
        return False


def send_booking_request_refused_email(booking_request):
    """Envoie un email au client quand sa demande est refusée."""
    try:
        subject = f"Votre demande de location a été refusée — {booking_request.item.business.nom}"
        
        motif = booking_request.motif_refus or "Aucun motif précisé"
        
        email = EmailMultiAlternatives(
            subject=f"❌ Votre demande a été refusée — {booking_request.item.business.nom}",
            body=(
                f"Bonjour {booking_request.client_nom},\n\n"
                f"Nous sommes au regret de vous informer que votre demande de location a été refusée par {booking_request.item.business.nom}.\n\n"
                f"Article : {booking_request.item.nom}\n"
                f"Période : {booking_request.date_debut.strftime('%d/%m/%Y')} au {booking_request.date_fin.strftime('%d/%m/%Y')}\n"
                f"Quantité : {booking_request.quantite}\n\n"
                f"Motif du refus : {motif}\n\n"
                f"Vous pouvez consulter votre lien de suivi pour plus de détails.\n\n"
                f"L'équipe {booking_request.item.business.nom}."
            ),
            from_email=None,
            to=[booking_request.client_email],
        )
        email.send(fail_silently=False)
        return True
    except Exception:
        return False


def send_booking_request_counter_proposal_email(booking_request):
    """Envoie un email au client quand une contre-proposition est faite."""
    try:
        contre = booking_request.contre_proposition or {}
        
        subject = f"Contre-proposition pour votre demande — {booking_request.item.business.nom}"
        
        # Construire les détails de la contre-proposition
        details = []
        if "date_debut" in contre and "date_fin" in contre:
            details.append(f"• Nouvelle période : {contre['date_debut']} au {contre['date_fin']}")
        if "quantite" in contre:
            details.append(f"• Nouvelle quantité : {contre['quantite']}")
        if "prix" in contre:
            details.append(f"• Prix unitaire : {contre['prix']} F CFA")
        if "message" in contre and contre["message"]:
            details.append(f"• Message : {contre['message']}")
        
        details_text = "\n".join(details) if details else "Aucun détail supplémentaire."
        
        body = (
            f"Bonjour {booking_request.client_nom},\n\n"
            f"Le professionnel {booking_request.item.business.nom} vous fait une contre-proposition pour votre demande de location.\n\n"
            f"Article : {booking_request.item.nom}\n"
            f"Demande initiale :\n"
            f"  • Période : {booking_request.date_debut.strftime('%d/%m/%Y')} au {booking_request.date_fin.strftime('%d/%m/%Y')}\n"
            f"  • Quantité : {booking_request.quantite}\n\n"
            f"Contre-proposition :\n"
            f"{details_text}\n\n"
            f"Vous pouvez accepter ou refuser cette contre-proposition via votre lien de suivi :\n"
            f"https://votre-domaine.com/b/{booking_request.item.business.slug}/booking-requests/{booking_request.access_token}/\n\n"
            f"L'équipe {booking_request.item.business.nom}."
        )
        
        html = f"""
        <div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#1a2b45;">
          <h2 style="margin:0 0 8px;color:#f59e0b;">🔄 Contre-proposition reçue</h2>
          <p style="color:#55657e;">Bonjour <strong>{booking_request.client_nom}</strong>,</p>
          <p style="color:#55657e;">Le professionnel <strong>{booking_request.item.business.nom}</strong> vous fait une contre-proposition pour votre demande de location.</p>
          
          <div style="background:#fffbeb;border:1px solid #fcd34d;border-radius:12px;padding:16px;margin:16px 0;">
            <h3 style="margin:0 0 12px;font-size:16px;color:#92400e;">Contre-proposition</h3>
            <p style="margin:0 0 8px;color:#92400e;"><strong>Article :</strong> {booking_request.item.nom}</h3>
            <p style="margin:0 0 8px;color:#92400e;"><strong>Demande initiale :</strong></p>
            <ul style="margin:0;padding-left:20px;color:#1a2b45;">
              <li>Période : {booking_request.date_debut.strftime('%d/%m/%Y')} au {booking_request.date_fin.strftime('%d/%m/%Y')}</li>
              <li>Quantité : {booking_request.quantite}</li>
            </ul>
            <p style="margin:8px 0 0;color:#92400e;"><strong>Nouvelle proposition :</strong></p>
            <ul style="margin:0;padding-left:20px;color:#1a2b45;">
              {''.join([f'<li>{d.replace("• ", "")}</li>' for d in details])}
            </ul>
          </div>
          
          <div style="text-align:center;margin:24px 0;">
            <a href="https://votre-domaine.com/b/{booking_request.item.business.slug}/booking-requests/{booking_request.access_token}/" 
               style="background:#f59e0b;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;display:inline-block;">
              Voir et répondre à la contre-proposition
            </a>
          </div>
          
          <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">
          <p style="color:#8a94a6;font-size:13px;margin-top:12px;">L'équipe {booking_request.item.business.nom}.</p>
        </div>
        """
        
        email = EmailMultiAlternatives(
            subject=f"🔄 Contre-proposition pour votre demande — {booking_request.item.business.nom}",
            body=f"Bonjour {booking_request.client_nom},\n\n{booking_request.item.business.nom} vous fait une contre-proposition.\n\n{details_text}\n\nRépondez via votre lien de suivi.",
            from_email=None,
            to=[booking_request.client_email],
        )
        email.attach_alternative(html, "text/html")
        email.send(fail_silently=False)
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Failed to send counter proposal email")
        return False


# ============================================================
# Push Notifications FCM pour les demandes de réservation
# ============================================================

def send_booking_request_fcm(booking_request, title, body, data=None):
    """Envoie une notification push FCM au client."""
    try:
        # Récupérer le token FCM du client depuis le booking_request
        # Le client n'a pas de token FCM directement stocké sur le booking_request
        # Il faudrait l'associer via le client ou utiliser un autre mécanisme
        # Pour l'instant, on log seulement
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"FCM push would be sent to client for booking request {booking_request.id}: {title} - {body}")
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Failed to send FCM notification")
        return False


def send_booking_request_status_push(booking_request, new_status):
    """Envoie une notification push selon le nouveau statut."""
    status_messages = {
        "ACCEPTEE": ("✅ Demande acceptée", "Votre demande de location a été acceptée !"),
        "REFUSEE": ("❌ Demande refusée", "Votre demande a été refusée."),
        "CONVERTIE": ("✅ Réservation confirmée", "Votre demande a été convertie en réservation !"),
        "CONTRE_PROPOSITION": ("🔄 Contre-proposition", "Une contre-proposition vous a été faite."),
    }
    
    if new_status in status_messages:
        title, body = status_messages[new_status]
        send_booking_request_fcm(booking_request, title, body, {"status": new_status})