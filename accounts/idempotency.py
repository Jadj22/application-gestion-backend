"""Idempotence des mutations (Offline-First).

Le problème que ce module résout
--------------------------------

Un client hors ligne accumule des opérations et les rejoue au retour du réseau.
Entre l'instant où le serveur commite une création et celui où le client reçoit
la réponse, tout peut échouer : coupure, timeout, application tuée. Le client
n'a alors aucun moyen de savoir si l'opération a abouti — et sa seule option
raisonnable est de réessayer.

Sans garde-fou, chaque réessai crée un doublon : un article en double, un
mouvement de stock compté deux fois, une réservation fantôme. Réessayer devient
dangereux, donc le client cesse de réessayer, donc des opérations se perdent.
C'est exactement ce que l'architecture Offline-First doit empêcher.

La solution
-----------

Le client envoie un en-tête ``Idempotency-Key`` **stable entre les tentatives**
d'une même opération (il utilise l'identifiant de l'opération dans sa file). Le
serveur enregistre la première réponse réussie sous cette clé et la rejoue
telle quelle si la même clé revient.

Le rejeu renvoie la réponse d'origine, avec ``Idempotent-Replay: true`` : le
client peut ainsi traiter un réessai comme un succès, exactement comme s'il
avait reçu la première réponse.

Portée
------

* Uniquement les méthodes non sûres (POST, PATCH, PUT, DELETE).
* La clé est cloisonnée par utilisateur : deux appareils ne peuvent pas se
  marcher dessus, et une clé volée ne donne accès à rien.
* Les enregistrements expirent (``IDEMPOTENCY_RETENTION``) : au-delà, un client
  qui n'a pas synchronisé depuis des semaines repart normalement.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

HEADER = "Idempotency-Key"
META_KEY = "HTTP_IDEMPOTENCY_KEY"
REPLAY_HEADER = "Idempotent-Replay"

#: Durée de conservation d'une réponse. Assez longue pour couvrir un
#: utilisateur revenu après plusieurs jours hors ligne, assez courte pour que la
#: table ne devienne pas un journal permanent.
RETENTION = timedelta(days=14)

#: Au-delà, la réponse n'est pas mémorisée : rejouer une réponse volumineuse
#: coûterait plus cher que de laisser le client redemander la ressource.
MAX_STORED_BODY = 200_000

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

logger = logging.getLogger(__name__)


def fingerprint(request) -> str:
    """Empreinte de la requête, pour détecter une clé réutilisée à tort.

    Une même clé doit désigner une même opération. Si le corps diffère, c'est
    que le client s'est trompé de clé : mieux vaut le lui dire que de lui
    renvoyer silencieusement la réponse d'une autre opération.
    """
    raw = b"".join(
        [
            request.method.encode(),
            b"|",
            request.get_full_path().encode(),
            b"|",
            request.body or b"",
        ]
    )
    return hashlib.sha256(raw).hexdigest()


class IdempotencyMiddleware:
    """Mémorise et rejoue les réponses des mutations portant une clé.

    Les requêtes sans en-tête traversent le middleware sans coût.

    **Ce middleware ne doit jamais faire échouer une requête par lui-même.**
    Il est traversé par *toutes* les mutations de l'API : s'il propage ses
    propres erreurs (table absente parce qu'une migration n'a pas été
    appliquée, base indisponible, ligne corrompue), une fonction de confort
    devient une panne totale des écritures.

    En cas de problème interne, il s'efface donc et laisse passer la requête :
    on perd la protection contre les doublons — c'est signalé bruyamment dans
    les logs — mais l'application continue de fonctionner.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        key = request.META.get(META_KEY, "").strip()
        if not key or request.method not in UNSAFE_METHODS:
            return self.get_response(request)

        # Le corps doit être lu avant la vue (qui le consomme) pour calculer
        # l'empreinte.
        request_fingerprint = fingerprint(request)

        try:
            replay = self._lookup(request, key, request_fingerprint)
        except Exception:
            logger.exception(
                "Idempotence indisponible (lecture) : la requete passe sans "
                "protection contre les doublons. Verifiez que les migrations "
                "sont appliquees."
            )
            return self.get_response(request)

        if replay is not None:
            return replay

        response = self.get_response(request)

        # On ne mémorise que les succès : un échec doit pouvoir être réessayé
        # tel quel, éventuellement après correction côté client.
        if 200 <= response.status_code < 300:
            try:
                from .models import IdempotencyRecord

                _remember(
                    IdempotencyRecord,
                    key=key,
                    user_id=_resolve_user_id(request),
                    request_fingerprint=request_fingerprint,
                    response=response,
                )
            except Exception:
                # La mutation a réussi : la réponse doit partir intacte, même
                # si l'on n'a pas pu la mémoriser.
                logger.exception(
                    "Idempotence indisponible (ecriture) : la reponse n'a pas "
                    "ete memorisee, un reessai pourrait creer un doublon."
                )
        return response

    def _lookup(self, request, key, request_fingerprint):
        """Réponse à rejouer, ou None s'il faut exécuter la vue."""
        from .models import IdempotencyRecord

        user_id = _resolve_user_id(request)
        existing = IdempotencyRecord.objects.filter(
            key=key, user_id=user_id
        ).first()
        if existing is None:
            return None

        if existing.is_expired():
            existing.delete()
            return None

        if existing.request_fingerprint != request_fingerprint:
            return _json_response(
                409,
                {
                    "detail": (
                        "Cette clé d'idempotence a déjà été utilisée pour "
                        "une autre requête."
                    )
                },
            )

        return _replay(existing)


def _resolve_user_id(request):
    """Identifie l'appelant à partir de son JWT.

    Piège important : un middleware Django s'exécute **avant** la vue, donc
    avant l'authentification de DRF. ``request.user`` n'est alimenté que par
    ``AuthenticationMiddleware``, qui lit la *session* — inexistante pour une
    API en Bearer token. S'y fier laisserait ``user_id`` à ``None`` pour tout
    le monde, et les clés d'idempotence deviendraient **globales** : la clé
    d'un appareil pourrait alors entrer en collision avec celle d'un autre
    compte, voire lui renvoyer sa réponse mémorisée.

    On résout donc le porteur du jeton explicitement, ici.
    """
    # Une session Django (admin, navigateur) reste une identité valable.
    user = getattr(request, "user", None)
    if user is not None and user.is_authenticated:
        return user.id

    try:
        from rest_framework_simplejwt.authentication import JWTAuthentication

        resolved = JWTAuthentication().authenticate(request)
    except Exception:
        # Jeton absent, expiré ou illisible : la vue renverra elle-même le 401.
        # Le middleware n'a pas à trancher l'authentification.
        return None

    return resolved[0].id if resolved else None


def _remember(model, *, key, user_id, request_fingerprint, response):
    body = getattr(response, "content", b"") or b""
    if len(body) > MAX_STORED_BODY:
        return

    try:
        with transaction.atomic():
            model.objects.create(
                key=key,
                user_id=user_id,
                request_fingerprint=request_fingerprint,
                status_code=response.status_code,
                response_body=body.decode("utf-8", errors="replace"),
                content_type=response.get("Content-Type", "application/json"),
            )
    except IntegrityError:
        # Deux tentatives simultanées de la même opération : la première a
        # gagné, c'est le résultat attendu.
        pass


def _replay(record):
    response = _json_response(
        record.status_code,
        record.response_body,
        content_type=record.content_type,
        raw=True,
    )
    response[REPLAY_HEADER] = "true"
    return response


def _json_response(status, payload, content_type="application/json", raw=False):
    from django.http import HttpResponse

    body = payload if raw else json.dumps(payload)
    return HttpResponse(body, status=status, content_type=content_type)


def purge_expired():
    """Supprime les enregistrements arrivés à expiration.

    À appeler depuis une tâche planifiée. Sans purge, la table grossit
    indéfiniment alors que ces lignes n'ont plus aucune utilité.
    """
    from .models import IdempotencyRecord

    cutoff = timezone.now() - RETENTION
    deleted, _ = IdempotencyRecord.objects.filter(created_at__lt=cutoff).delete()
    return deleted
