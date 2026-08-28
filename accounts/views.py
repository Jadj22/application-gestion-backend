from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .models import (
    MAX_ITEM_PHOTOS,
    ActivityLog,
    Alert,
    BookingRequest,
    Business,
    BusinessMember,
    BusinessRule,
    Category,
    DecisionLog,
    Invoice,
    Inventory,
    InventoryCount,
    Item,
    ItemPhoto,
    MaintenanceTask,
    Notification,
    PerformanceAlert,
    Procedure,
    RecurringTask,
    Reminder,
    Reservation,
    Role,
    RolePermission,
    StockMovement,
    TaskComment,
    TaskStep,
    TaskStepPhoto,
)
from .permissions import HasBusinessPermission, IsSelfMember, get_membership
from .rbac import PERMISSIONS_CATALOG, Perm, RoleNom, seed_default_roles
from .serializers import (
    ActivityLogSerializer,
    AlertSerializer,
    BookingRequestActionSerializer,
    BookingRequestTeamSerializer,
    BusinessMemberSerializer,
    BusinessRuleSerializer,
    BusinessSerializer,
    BusinessTypeSerializer,
    CategorySerializer,
    DecisionLogSerializer,
    GoogleAuthSerializer,
    HistoryFilterSerializer,
    ImageDescriptionSerializer,
    InventoryCountSerializer,
    InventoryCountWriteSerializer,
    InventorySerializer,
    InvitationAcceptSerializer,
    InvitationCodeSerializer,
    InvitationPreviewSerializer,
    ItemPhotoSerializer,
    ItemSerializer,
    LoginSerializer,
    MaintenanceTaskSerializer,
    MemberInviteSerializer,
    MemberWriteSerializer,
    NotificationSerializer,
    PerformanceAlertSerializer,
    ProcedureSerializer,
    PublicBookingRequestCreateSerializer,
    PublicBookingRequestCounterResponseSerializer,
    PublicBookingRequestDetailSerializer,
    PublicCategorySerializer,
    PublicItemSerializer,
    RecoverBookingRequestSerializer,
    RecurringTaskCreateSerializer,
    RecurringTaskSerializer,
    RegisterSerializer,
    ReminderCreateSerializer,
    ReminderSerializer,
    ReservationBulkCreateSerializer,
    ReservationCreateSerializer,
    ReservationFinishSerializer,
    ReservationSerializer,
    RoleSerializer,
    RoleWriteSerializer,
    StockAdjustmentSerializer,
    StockAdjustmentWriteSerializer,
    StockMovementSerializer,
    TaskAssignSerializer,
    TaskCommentCreateSerializer,
    TaskCommentSerializer,
    TaskCreateSerializer,
    TaskStepPhotoCreateSerializer,
    TaskStepPhotoSerializer,
    TaskStepUpdateSerializer,
    TaskUpdateSerializer,
    UserSerializer,
    InvoiceSerializer,
    InvoiceCreateSerializer,
    InvoicePublicSerializer,
)
from .fiabilite import (
    a_verifier,
    a_verifier_bulk,
    cloturer_inventory,
    create_adjustment,
    declare_count,
)
from .ai import GeminiError, describe_image, suggerer_reference
from .maintenance import (
    auto_tache_retour,
    cloturer_task,
    create_task,
    entretien_requis,
    etat_entretien,
    etats_entretien,
    update_step,
)
from .alertes import check_rules, record_decision, seed_business_rules
from .activite import Act, log_activity, notify_members
from .invitations import (
    format_code,
    invitation_link,
    invitation_state,
    issue_code,
    make_invitation_token,
    resolve_invitation,
    resolve_invitation_by_code,
    send_invitation_email,
)
from .pagination import StandardPagination, paginated
from .reservation import (
    annuler_reservation,
    create_reservation,
    create_reservations_bulk,
    demarrer_reservation,
    terminer_reservation,
    valider_reservation,
)
from .stock import create_movement, get_adjustments, get_aggregates, snapshot

User = get_user_model()


def _tokens_for(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


# --- Authentification (S 1-02) ---------------------------------------------


class AuthThrottleMixin:
    """Scope de throttling commun aux endpoints d'authentification (S9)."""

    throttle_scopes = ("auth",)


class WriteThrottleMixin:
    """Scope de throttling commun aux mutations (créations / actions, S9)."""

    throttle_scopes = ("write",)


class RegisterView(AuthThrottleMixin, APIView):
    permission_classes = [AllowAny]
    serializer_class = UserSerializer

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {"user": UserSerializer(user).data, **_tokens_for(user)},
            status=status.HTTP_201_CREATED,
        )


class LoginView(AuthThrottleMixin, TokenObtainPairView):
    serializer_class = LoginSerializer


class RefreshView(AuthThrottleMixin, TokenRefreshView):
    pass


class MeView(APIView):
    serializer_class = UserSerializer

    def get(self, request):
        user = request.user
        memberships = user.memberships.select_related("business", "role").all()
        businesses = [
            {
                "id": m.business.id,
                "nom": m.business.nom,
                "slug": m.business.slug,
                "role": m.role.nom if m.role else None,
                "role_id": m.role.id if m.role else None,
                "statut": m.statut,
            }
            for m in memberships
        ]
        return Response({"user": UserSerializer(user).data, "businesses": businesses})

    def delete(self, request):
        """Suppression définitive du compte authentifié (RGPD / profil)."""
        from .account_deletion import delete_user_account

        delete_user_account(request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)


class GoogleAuthView(AuthThrottleMixin, APIView):
    """Connexion par ID token Google (S 1-02, OAuth 2.0 mobile).

    L'app Android envoie l'ID token obtenu via google_sign_in ; le token est
    vérifié (signature, émetteur, audience) puis un utilisateur local est
    trouvé ou créé (google_sub) et lié à l'email Google si le compte existe
    déjà. Réponse identique à /auth/login/ : {user, access, refresh}.
    """

    permission_classes = [AllowAny]
    serializer_class = GoogleAuthSerializer

    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            info = _verify_google_id_token(serializer.validated_data["id_token"])
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_401_UNAUTHORIZED)

        sub = info["sub"]
        email = (info.get("email") or "").lower()
        if not email:
            return Response(
                {"detail": "Le compte Google n'a pas d'adresse email."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        with transaction.atomic():
            user = User.objects.filter(google_sub=sub).first()
            if user is None:
                user = User.objects.filter(email=email).first()
            is_new = user is None
            if is_new:
                user = User(username=email, email=email, statut=User.Statut.ACTIF)
            user.google_sub = sub
            user.first_name = (info.get("given_name") or user.first_name or "")[:150]
            user.last_name = (info.get("family_name") or user.last_name or "")[:150]
            if not user.has_usable_password():
                user.set_unusable_password()
            user.save()

        return Response(
            {"user": UserSerializer(user).data, **_tokens_for(user)},
            status=status.HTTP_200_OK,
        )


def _verify_google_id_token(token):
    """Vérifie l'ID token via google-auth (JWKS Google) et retourne ses claims.

    Lève ValueError si le token est invalide ou que son audience (aud) n'est
    pas un client autorisé (settings.GOOGLE_CLIENT_IDS).
    """
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token as google_id_token

    info = google_id_token.verify_oauth2_token(
        token,
        google_requests.Request(),
        audience=None,
    )
    if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise ValueError("Émetteur du jeton Google invalide.")
    if not info.get("email_verified"):
        raise ValueError("L'email Google n'est pas vérifié.")
    aud = info.get("aud")
    if aud not in settings.GOOGLE_CLIENT_IDS:
        raise ValueError("Le jeton Google n'est pas destiné à cette application.")
    return info


# --- Businesses (US-01) ----------------------------------------------------


class BusinessTypeListView(APIView):
    """Liste fermée des types de business (étape 1 du tunnel d'onboarding).
    Catalogue statique : accessible sans authentification."""

    permission_classes = [AllowAny]
    serializer_class = BusinessTypeSerializer

    def get(self, request):
        return paginated(
            request,
            [
                {"codename": t.value, "libelle": t.label}
                for t in Business.BusinessType
            ],
            BusinessTypeSerializer,
        )


class BusinessListCreateView(WriteThrottleMixin, APIView):
    serializer_class = BusinessSerializer

    def get(self, request):
        memberships = request.user.memberships.select_related(
            "business", "role"
        ).filter(statut=BusinessMember.Statut.ACTIF).order_by(
            "business__created_at"
        )
        paginator = StandardPagination()
        page = paginator.paginate_queryset(memberships, request)
        data = [
            {
                "id": m.business.id,
                "nom": m.business.nom,
                "role": m.role.nom if m.role else None,
                "created_at": m.business.created_at,
            }
            for m in page
        ]
        return paginator.get_paginated_response(data)

    def post(self, request):
        serializer = BusinessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            business = serializer.save(created_by=request.user)
            roles = seed_default_roles(business)
            seed_business_rules(business)
            BusinessMember.objects.create(
                business=business,
                user=request.user,
                role=roles[RoleNom.OWNER],
                statut=BusinessMember.Statut.ACTIF,
            )
        log_activity(
            business=business,
            acteur=request.user,
            action=Act.BUSINESS_CREATE,
            cible=business.nom,
        )
        return Response(BusinessSerializer(business).data, status=status.HTTP_201_CREATED)


# --- Membres (US-02, US-03) ------------------------------------------------


class BusinessMembersView(WriteThrottleMixin, APIView):
    serializer_class = BusinessMemberSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.MEMBER_INVITE)()]
        return [HasBusinessPermission.require(Perm.MEMBER_VIEW)()]

    def get(self, request, business_id):
        members = request.business.memberships.select_related(
            "user", "role", "invited_by"
        ).order_by("invited_at")
        return paginated(request, members, BusinessMemberSerializer)

    def post(self, request, business_id):
        serializer = MemberInviteSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"].lower()
        role = serializer.validated_data.get("role_id") or request.business.roles.get(
            nom=RoleNom.MEMBER
        )

        user = User.objects.filter(email=email).first()
        if user is None:
            user = User.objects.create_user(
                email=email,
                username=email,
                first_name=serializer.validated_data.get("first_name", ""),
                last_name=serializer.validated_data.get("last_name", ""),
            )
            # Pas encore de mot de passe : l'invité se créera via un flux d'invitation

        membership, created = BusinessMember.objects.get_or_create(
            business=request.business,
            user=user,
            defaults={
                "role": role,
                "statut": BusinessMember.Statut.INVITE,
                "invited_by": request.user,
            },
        )
        if not created and membership.statut == BusinessMember.Statut.BLOQUE:
            return Response(
                {"detail": "Ce membre est bloqué."},
                status=status.HTTP_409_CONFLICT,
            )
        membership.role = role
        membership.invited_by = request.user
        if membership.statut in (
            BusinessMember.Statut.INVITE,
            BusinessMember.Statut.EXPIRED,
            BusinessMember.Statut.CANCELLED,
        ):
            # Réinvitation : on réutilise l'association existante (unicité
            # user ↔ business), on la repasse en attente et on régénère un
            # code + une nouvelle expiration.
            membership.statut = BusinessMember.Statut.INVITE
            membership.accepted_at = None
        membership.save()
        code = issue_code(membership)
        token = make_invitation_token(membership)
        link = invitation_link(token)
        email_sent = send_invitation_email(membership, code, link)
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.MEMBER_INVITE,
            cible=email,
            detail={"role": role.nom if role else None},
        )
        data = BusinessMemberSerializer(membership).data
        data["invitation_code"] = format_code(code)
        data["invitation_expires_at"] = membership.expires_at.isoformat()
        data["invitation_link"] = link
        data["invitation_email_sent"] = email_sent
        return Response(data, status=status.HTTP_201_CREATED)


class AcceptInvitationView(APIView):
    permission_classes = [IsSelfMember]
    serializer_class = BusinessMemberSerializer

    def post(self, request, business_id, member_id):
        if request.membership.id != member_id:
            return Response(
                {"detail": "Invitation introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        if request.membership.statut == BusinessMember.Statut.INVITE:
            request.membership.statut = BusinessMember.Statut.ACTIF
            request.membership.save()
            log_activity(
                business=request.business,
                acteur=request.user,
                action=Act.MEMBER_ACTIVE,
                cible=request.user.email,
            )
        return Response(BusinessMemberSerializer(request.membership).data)


class InvitationPreviewView(AuthThrottleMixin, APIView):
    """Aperçu public d'une invitation (GET /invitations/<token>/).

    Conserve le token signé pour la compatibilité deep link ; les nouveaux
    parcours utilisent POST /invitations/validate/ avec le code.
    """

    permission_classes = [AllowAny]
    serializer_class = InvitationPreviewSerializer

    def get(self, request, token):
        membership = resolve_invitation(token)
        if membership is None:
            return Response(
                {"detail": "Lien d'invitation invalide ou expiré."},
                status=status.HTTP_404_NOT_FOUND,
            )
        statut = invitation_state(membership)
        if statut == BusinessMember.Statut.BLOQUE:
            return Response(
                {"detail": "Cette invitation a été annulée."},
                status=status.HTTP_409_CONFLICT,
            )
        if statut == BusinessMember.Statut.CANCELLED:
            return Response(
                {"detail": "Cette invitation n'est plus valide."},
                status=status.HTTP_409_CONFLICT,
            )
        if statut == BusinessMember.Statut.EXPIRED:
            return Response(
                {"detail": "Cette invitation a expiré."},
                status=status.HTTP_410_GONE,
            )
        if statut != BusinessMember.Statut.INVITE:
            return Response(
                {"detail": "Cette invitation a déjà été utilisée."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {
                "email": membership.user.email,
                "business_id": membership.business.id,
                "business_nom": membership.business.nom,
                "inviteur": (
                    membership.invited_by.email
                    if membership.invited_by
                    else None
                ),
                "role": membership.role.nom if membership.role else None,
                "statut": statut,
            }
        )


class InvitationValidateView(AuthThrottleMixin, WriteThrottleMixin, APIView):
    """Validation d'un code d'invitation (POST /invitations/validate/).

    Renvoie les informations nécessaires à la confirmation (business, rôle,
    inviteur) — jamais d'information sensible. La sécurité (statut,
    expiration, identité) reste entièrement côté backend.
    """

    permission_classes = [AllowAny]
    serializer_class = InvitationCodeSerializer
    throttle_scopes = ("auth", "write")

    def post(self, request):
        serializer = InvitationCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        membership = resolve_invitation_by_code(
            serializer.validated_data["code"]
        )
        if membership is None:
            return Response(
                {"detail": "Code invalide."},
                status=status.HTTP_404_NOT_FOUND,
            )
        statut = invitation_state(membership)
        if statut in (
            BusinessMember.Statut.BLOQUE,
            BusinessMember.Statut.CANCELLED,
        ):
            return Response(
                {"detail": "Cette invitation n'est plus valide."},
                status=status.HTTP_409_CONFLICT,
            )
        if statut == BusinessMember.Statut.EXPIRED:
            return Response(
                {"detail": "Cette invitation a expiré."},
                status=status.HTTP_410_GONE,
            )
        if statut != BusinessMember.Statut.INVITE:
            return Response(
                {"detail": "Cette invitation a déjà été utilisée."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        inviteur = membership.invited_by
        return Response(
            {
                "valid": True,
                "invitation": {
                    "email": membership.user.email,
                    "business_id": membership.business.id,
                    "business_nom": membership.business.nom,
                    "role": membership.role.nom if membership.role else None,
                    "inviteur": (
                        inviteur.get_full_name() or inviteur.email
                        if inviteur
                        else None
                    ),
                    "expires_at": membership.expires_at.isoformat()
                    if membership.expires_at
                    else None,
                },
            }
        )


class InvitationAcceptView(AuthThrottleMixin, WriteThrottleMixin, APIView):
    """Acceptation d'une invitation par code ou lien signé.

    * Non connecté : le mot de passe est requis (compte créé à
      l'invitation), le membership est activé et des JWT sont renvoyés.
    * Connecté : pas de mot de passe requis ; l'utilisateur courant doit
      correspondre à l'email invité (le code n'est jamais transférable).

    La réponse est identique à /auth/register/ ({user, access, refresh}).
    """

    permission_classes = [AllowAny]
    serializer_class = InvitationAcceptSerializer
    throttle_scopes = ("auth", "write")

    def post(self, request):
        serializer = InvitationAcceptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data.get("token")
        code = serializer.validated_data.get("code")
        membership = (
            resolve_invitation(token)
            if token
            else resolve_invitation_by_code(code)
        )
        if membership is None:
            return Response(
                {"detail": "Code invalide."},
                status=status.HTTP_404_NOT_FOUND,
            )
        statut = invitation_state(membership)
        if statut in (
            BusinessMember.Statut.BLOQUE,
            BusinessMember.Statut.CANCELLED,
        ):
            return Response(
                {"detail": "Cette invitation n'est plus valide."},
                status=status.HTTP_409_CONFLICT,
            )
        if statut == BusinessMember.Statut.EXPIRED:
            return Response(
                {"detail": "Cette invitation a expiré."},
                status=status.HTTP_410_GONE,
            )
        if statut != BusinessMember.Statut.INVITE:
            return Response(
                {"detail": "Cette invitation a déjà été utilisée."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = membership.user
        authenticated = (
            request.user is not None and request.user.is_authenticated
        )
        with transaction.atomic():
            if authenticated:
                if request.user.id != user.id:
                    return Response(
                        {
                            "detail": (
                                "Cette invitation est destinée à un autre "
                                "compte. Connectez-vous avec l'email invité."
                            )
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )
            else:
                password = serializer.validated_data.get("password")
                if not password:
                    return Response(
                        {"detail": "Le mot de passe est requis."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                try:
                    validate_password(password, user=user)
                except DjangoValidationError as exc:
                    raise serializers.ValidationError(
                        {"password": list(exc.messages)}
                    ) from exc
                user.set_password(password)
                user.first_name = (
                    serializer.validated_data.get("first_name")
                    or user.first_name
                )
                user.last_name = (
                    serializer.validated_data.get("last_name") or user.last_name
                )
                user.telephone = (
                    serializer.validated_data.get("telephone")
                    or user.telephone
                )
                user.statut = User.Statut.ACTIF
                user.save(
                    update_fields=[
                        "password",
                        "first_name",
                        "last_name",
                        "telephone",
                        "statut",
                    ]
                )
            membership.statut = BusinessMember.Statut.ACTIF
            membership.accepted_at = timezone.now()
            membership.save(update_fields=["statut", "accepted_at"])
            log_activity(
                business=membership.business,
                acteur=user,
                action=Act.MEMBER_ACTIVE,
                cible=user.email,
            )
        return Response(
            {"user": UserSerializer(user).data, **_tokens_for(user)},
            status=status.HTTP_200_OK,
        )


class ImageDescriptionView(WriteThrottleMixin, APIView):
    """Analyse d'une photo d'article par Gemini (Sprint 10).

    Renvoie {"nom": ..., "description": ...} pour pré-remplir le formulaire
    de création d'article quand l'utilisateur ne connaît pas l'article.
    La clé Gemini reste côté serveur (settings.GEMINI_API_KEY).
    """

    serializer_class = ImageDescriptionSerializer
    throttle_scopes = ("write", "ai")

    def _business(self, request):
        """Business du header X-Business-ID, si l'utilisateur en est membre.

        L'analyse fonctionne sans business (le header est facultatif) ; avec,
        elle classe l'article dans les catégories déjà créées et propose une
        référence libre dans ce catalogue.
        """
        membership = get_membership(request)
        return membership.business if membership else None

    def post(self, request):
        if not settings.GEMINI_API_KEY:
            return Response(
                {"detail": "L'analyse d'image n'est pas configurée."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        serializer = ImageDescriptionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        image = serializer.validated_data["image"]
        business = self._business(request)
        categories = (
            list(business.categories.values_list("nom", flat=True))
            if business
            else []
        )
        try:
            result = describe_image(
                image.read(), image.content_type or "image/jpeg", categories
            )
        except GeminiError as exc:
            if exc.retryable:
                detail = (
                    "L'analyse IA est temporairement indisponible "
                    "(forte demande sur Gemini). Réessayez dans quelques instants."
                )
                code = status.HTTP_503_SERVICE_UNAVAILABLE
            else:
                detail = str(exc)
                code = status.HTTP_502_BAD_GATEWAY
            return Response({"detail": detail}, status=code)
        return Response(self._enrichir(result, business))

    def _enrichir(self, result, business):
        """Relie la suggestion au catalogue : catégorie existante et référence.

        `category_id` n'est renseigné que si le libellé proposé correspond à
        une catégorie déjà créée ; sinon `categorie` reste une proposition que
        l'application peut offrir de créer.
        """
        result = dict(result)
        result["category_id"] = None
        result["reference"] = ""
        if business is None:
            return result

        libelle = (result.get("categorie") or "").strip().casefold()
        if libelle:
            correspondance = next(
                (
                    c
                    for c in business.categories.all()
                    if c.nom.strip().casefold() == libelle
                ),
                None,
            )
            if correspondance is not None:
                result["category_id"] = str(correspondance.id)
                result["categorie"] = correspondance.nom

        result["reference"] = suggerer_reference(
            result.get("nom"),
            business.items.exclude(reference__isnull=True).values_list(
                "reference", flat=True
            ),
        )
        return result


class MemberDetailView(APIView):
    serializer_class = BusinessMemberSerializer

    def get_permissions(self):
        action = getattr(self.request, "method", "")
        if action == "DELETE":
            return [HasBusinessPermission.require(Perm.MEMBER_REMOVE)()]
        return [
            HasBusinessPermission.require(Perm.MEMBER_ROLE_UPDATE)(),
            HasBusinessPermission.require(Perm.MEMBER_REMOVE)(),
        ]

    def _get_member(self, request, business_id, member_id):
        return request.business.memberships.filter(id=member_id).select_related(
            "user", "role"
        ).first()

    def _is_owner(self, membership):
        if membership.role is None:
            return False
        return membership.role.nom == RoleNom.OWNER and membership.role.is_system

    def patch(self, request, business_id, member_id):
        membership = self._get_member(request, business_id, member_id)
        if membership is None:
            return Response({"detail": "Membre introuvable."}, status=status.HTTP_404_NOT_FOUND)
        self_kwargs = {"business": request.business}
        serializer = MemberWriteSerializer(data=request.data, context=self_kwargs)
        serializer.is_valid(raise_exception=True)

        role = serializer.validated_data.get("role_id")
        statut = serializer.validated_data.get("statut")

        not_owner_permission = HasBusinessPermission.require(Perm.MEMBER_REMOVE)
        if self._is_owner(membership) and (role is not None or statut == BusinessMember.Statut.BLOQUE):
            return Response(
                {"detail": "Le rôle de propriétaire ne peut pas être modifié (RM-17)."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if statut == BusinessMember.Statut.BLOQUE:
            if not not_owner_permission().has_permission(request, None):
                return Response(
                    {"detail": "Permission requise pour bloquer ce membre."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        if statut == BusinessMember.Statut.CANCELLED:
            if membership.statut != BusinessMember.Statut.INVITE:
                return Response(
                    {
                        "detail": (
                            "Seule une invitation en attente peut être annulée."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if not not_owner_permission().has_permission(request, None):
                return Response(
                    {"detail": "Permission requise pour annuler l'invitation."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        if role is not None:
            self_kwargs_member = HasBusinessPermission.require(Perm.MEMBER_ROLE_UPDATE)
            if not self_kwargs_member().has_permission(request, None):
                return Response(
                    {"detail": "Permission requise pour attribuer un rôle."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        if role is not None:
            membership.role = role
        if statut is not None:
            membership.statut = statut
        membership.save()
        if role is not None:
            log_activity(
                business=request.business,
                acteur=request.user,
                action=Act.MEMBER_ROLE,
                cible=membership.user.email,
                detail={"role": role.nom},
            )
        return Response(BusinessMemberSerializer(membership).data)

    def delete(self, request, business_id, member_id):
        membership = self._get_member(request, business_id, member_id)
        if membership is None:
            return Response({"detail": "Membre introuvable."}, status=status.HTTP_404_NOT_FOUND)
        if self._is_owner(membership):
            return Response(
                {"detail": "Le propriétaire ne peut pas être retiré (RM-17)."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if membership.user_id == request.user.id:
            return Response(
                {"detail": "Impossible de se retirer du business."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.MEMBER_REMOVE,
            cible=membership.user.email,
        )
        membership.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Rôles et permissions (US-04, RM-19) -----------------------------------


class BusinessRolesView(WriteThrottleMixin, APIView):
    serializer_class = RoleSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.ROLE_MANAGE)()]
        return [HasBusinessPermission.require(Perm.ROLE_VIEW)()]

    def get(self, request, business_id):
        roles = request.business.roles.prefetch_related("permissions").all()
        return paginated(request, roles, RoleSerializer)

    def post(self, request, business_id):
        serializer = RoleWriteSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        role = serializer.save()
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.ROLE_CREATE,
            cible=role.nom,
        )
        return Response(RoleSerializer(role).data, status=status.HTTP_201_CREATED)


class RoleDetailView(APIView):
    serializer_class = RoleSerializer

    permission_classes = [HasBusinessPermission.require(Perm.ROLE_MANAGE)]

    def _get_role(self, request, business_id, role_id):
        return request.business.roles.filter(id=role_id).first()

    def put(self, request, business_id, role_id):
        role = self._get_role(request, business_id, role_id)
        if role is None:
            return Response({"detail": "Rôle introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = RoleWriteSerializer(
            role, data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        role = serializer.save()
        return Response(RoleSerializer(role).data)

    def delete(self, request, business_id, role_id):
        role = self._get_role(request, business_id, role_id)
        if role is None:
            return Response({"detail": "Rôle introuvable."}, status=status.HTTP_404_NOT_FOUND)
        if role.is_system:
            return Response(
                {"detail": "Les rôles système ne peuvent pas être supprimés."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if role.memberships.exists():
            return Response(
                {"detail": "Ce rôle est attribué à des membres."},
                status=status.HTTP_409_CONFLICT,
            )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.ROLE_DELETE,
            cible=role.nom,
        )
        role.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PermissionCatalogView(APIView):
    serializer_class = serializers.Serializer

    def get(self, request):
        permissions = [
            {"codename": c, "libelle": l, "description": d}
            for c, l, d in PERMISSIONS_CATALOG
        ]
        paginator = StandardPagination()
        page = paginator.paginate_queryset(permissions, request)
        return paginator.get_paginated_response(page)


# --- Catalogue : catégories (US-05) ----------------------------------------


class CategoryListCreateView(WriteThrottleMixin, APIView):
    serializer_class = CategorySerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.CATALOG_MANAGE)()]
        return [HasBusinessPermission.require(Perm.CATALOG_VIEW)()]

    def get(self, request, business_id):
        qs = request.business.categories.annotate(item_count=Count("items"))
        search = request.query_params.get("search")
        if search:
            qs = qs.filter(nom__icontains=search)
        parent = request.query_params.get("parent_id")
        if parent:
            qs = qs.filter(parent_id=parent)
        return paginated(request, qs, CategorySerializer, business=request.business, request=request)

    def post(self, request, business_id):
        serializer = CategorySerializer(
            data=request.data, context={"business": request.business, "request": request}
        )
        serializer.is_valid(raise_exception=True)
        category = serializer.save(business=request.business)
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.CATEGORY_CREATE,
            cible=category.nom,
        )
        return Response(CategorySerializer(category, context={"request": request}).data, status=status.HTTP_201_CREATED)


class CategoryDetailView(APIView):
    serializer_class = CategorySerializer

    def _is_write(self):
        return self.request.method in ("PUT", "PATCH", "DELETE")

    def get_permissions(self):
        if self._is_write():
            return [HasBusinessPermission.require(Perm.CATALOG_MANAGE)()]
        return [HasBusinessPermission.require(Perm.CATALOG_VIEW)()]

    def _get_category(self, request, business_id, category_id):
        return request.business.categories.annotate(item_count=Count("items")).filter(
            id=category_id
        ).first()

    def get(self, request, business_id, category_id):
        category = self._get_category(request, business_id, category_id)
        if category is None:
            return Response({"detail": "Catégorie introuvable."}, status=status.HTTP_404_NOT_FOUND)
        return Response(CategorySerializer(category, context={"request": request}).data)

    def put(self, request, business_id, category_id):
        return self._save(request, business_id, category_id, partial=False)

    def patch(self, request, business_id, category_id):
        return self._save(request, business_id, category_id, partial=True)

    def _save(self, request, business_id, category_id, partial):
        category = self._get_category(request, business_id, category_id)
        if category is None:
            return Response({"detail": "Catégorie introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = CategorySerializer(
            category, data=request.data, partial=partial,
            context={"business": request.business, "request": request},
        )
        serializer.is_valid(raise_exception=True)
        category = serializer.save()
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.CATEGORY_UPDATE,
            cible=category.nom,
        )
        return Response(CategorySerializer(category, context={"request": request}).data)

    def delete(self, request, business_id, category_id):
        category = self._get_category(request, business_id, category_id)
        if category is None:
            return Response({"detail": "Catégorie introuvable."}, status=status.HTTP_404_NOT_FOUND)
        if category.items.exists():
            return Response(
                {"detail": "Cette catégorie contient des articles."},
                status=status.HTTP_409_CONFLICT,
            )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.CATEGORY_DELETE,
            cible=category.nom,
        )
        category.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Catalogue : articles (US-06, US-07) -----------------------------------


class ItemListCreateView(WriteThrottleMixin, APIView):
    serializer_class = ItemSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.ITEM_EDIT)()]
        return [HasBusinessPermission.require(Perm.CATALOG_VIEW)()]

    def get(self, request, business_id):
        qs = request.business.items.select_related("category").prefetch_related("photos")
        search = request.query_params.get("search")
        if search:
            qs = qs.filter(
                Q(nom__icontains=search)
                | Q(reference__icontains=search)
                | Q(description__icontains=search)
            )
        category_id = request.query_params.get("category_id")
        if category_id:
            qs = qs.filter(category_id=category_id)
        statut = request.query_params.get("statut")
        if statut:
            qs = qs.filter(statut=statut)
        paginator = StandardPagination()
        page = paginator.paginate_queryset(qs, request)
        items = list(page)
        serializer = ItemSerializer(
            items, many=True,
            context={
                "business": request.business,
                "etats": etats_entretien(items),
                "a_verifier": a_verifier_bulk(items),
            },
        )
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, business_id):
        serializer = ItemSerializer(
            data=request.data,
            context={"business": request.business, "user": request.user},
        )
        serializer.is_valid(raise_exception=True)
        item = serializer.save()
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.ITEM_CREATE,
            item=item,
        )
        return Response(
            ItemSerializer(
                item,
                context={
                    "business": request.business,
                    "etats": {item.id: etat_entretien(item)},
                    "a_verifier": {item.id: a_verifier(item)},
                },
            ).data,
            status=status.HTTP_201_CREATED,
        )


class ItemDetailView(APIView):
    serializer_class = ItemSerializer

    def _is_write(self):
        return self.request.method in ("PUT", "PATCH")

    def get_permissions(self):
        if self.request.method == "DELETE":
            return [HasBusinessPermission.require(Perm.CATALOG_MANAGE)()]
        if self._is_write():
            return [HasBusinessPermission.require(Perm.ITEM_EDIT)()]
        return [HasBusinessPermission.require(Perm.CATALOG_VIEW)()]

    def _get_item(self, request, business_id, item_id):
        return request.business.items.select_related("category").prefetch_related(
            "photos"
        ).filter(id=item_id).first()

    def get(self, request, business_id, item_id):
        item = self._get_item(request, business_id, item_id)
        if item is None:
            return Response({"detail": "Article introuvable."}, status=status.HTTP_404_NOT_FOUND)
        return Response(
            ItemSerializer(
                item,
                context={
                    "business": request.business,
                    "etats": {item.id: etat_entretien(item)},
                    "a_verifier": {item.id: a_verifier(item)},
                },
            ).data
        )

    def _save(self, request, business_id, item_id, partial):
        item = self._get_item(request, business_id, item_id)
        if item is None:
            return Response({"detail": "Article introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = ItemSerializer(
            item, data=request.data, partial=partial, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        item = serializer.save()
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.ITEM_UPDATE,
            item=item,
        )
        return Response(
            ItemSerializer(
                item,
                context={
                    "business": request.business,
                    "etats": {item.id: etat_entretien(item)},
                    "a_verifier": {item.id: a_verifier(item)},
                },
            ).data
        )

    def put(self, request, business_id, item_id):
        return self._save(request, business_id, item_id, partial=False)

    def patch(self, request, business_id, item_id):
        return self._save(request, business_id, item_id, partial=True)

    def delete(self, request, business_id, item_id):
        item = self._get_item(request, business_id, item_id)
        if item is None:
            return Response({"detail": "Article introuvable."}, status=status.HTTP_404_NOT_FOUND)
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.ITEM_DELETE,
            item=item,
        )
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Photos des articles (S 2-03) ------------------------------------------


class ItemPhotoView(WriteThrottleMixin, APIView):
    permission_classes = [HasBusinessPermission.require(Perm.ITEM_EDIT)]
    serializer_class = ItemPhotoSerializer

    def _get_item(self, request, business_id, item_id):
        return request.business.items.filter(id=item_id).first()

    def post(self, request, business_id, item_id):
        item = self._get_item(request, business_id, item_id)
        if item is None:
            return Response({"detail": "Article introuvable."}, status=status.HTTP_404_NOT_FOUND)
        if item.photos.count() >= MAX_ITEM_PHOTOS:
            return Response(
                {"detail": f"Maximum {MAX_ITEM_PHOTOS} photos par article."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = ItemPhotoSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        photo = serializer.save(item=item)
        return Response(ItemPhotoSerializer(photo).data, status=status.HTTP_201_CREATED)

    def delete(self, request, business_id, item_id, photo_id):
        photo = ItemPhoto.objects.filter(id=photo_id, item_id=item_id).first()
        if photo is None or photo.item.business_id != request.business.id:
            return Response({"detail": "Photo introuvable."}, status=status.HTTP_404_NOT_FOUND)
        photo.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Stock & traçabilité (Sprint 3, US-08 à US-12) -------------------------
# L'historique est immuable : aucun endpoint de modification/suppression
# n'existe (RM-02, RM-03). Le stock est recalculé depuis l'historique (RM-04).


class StockListView(APIView):
    """Stock courant de tous les articles, avec états calculés (S 3-03)."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_VIEW)]
    serializer_class = serializers.Serializer

    def get(self, request, business_id):
        qs = request.business.items.select_related("category")
        search = request.query_params.get("search")
        if search:
            qs = qs.filter(
                Q(nom__icontains=search) | Q(reference__icontains=search)
            )
        category_id = request.query_params.get("category_id")
        if category_id:
            qs = qs.filter(category_id=category_id)
        paginator = StandardPagination()
        page = paginator.paginate_queryset(qs, request)
        items = list(page)
        aggregates = get_aggregates(
            request.business.id, [i.id for i in items]
        )
        adjustments = get_adjustments(
            request.business.id, [i.id for i in items]
        )
        etats = etats_entretien(items)
        flags = a_verifier_bulk(items)
        rows = []
        for item in items:
            rows.append(
                {
                    "item_id": item.id,
                    "nom": item.nom,
                    "reference": item.reference,
                    "statut": item.statut,
                    "entretien_requis": entretien_requis(item),
                    "etat_entretien": etats[item.id],
                    "a_verifier": flags[item.id],
                    **snapshot(item, aggregates, adjustments),
                }
            )
        return paginator.get_paginated_response(rows)


class ItemStockView(APIView):
    """Stock d'un article + mouvements récents (fiche stock, S 3-03/04)."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_VIEW)]
    serializer_class = serializers.Serializer

    def get(self, request, business_id, item_id):
        item = request.business.items.filter(id=item_id).first()
        if item is None:
            return Response({"detail": "Article introuvable."}, status=status.HTTP_404_NOT_FOUND)
        movements = item.movements.select_related("acteur")[:25]
        return Response(
            {
                "item_id": item.id,
                "nom": item.nom,
                "reference": item.reference,
                "entretien_requis": entretien_requis(item),
                "etat_entretien": etat_entretien(item),
                "a_verifier": a_verifier(item),
                **snapshot(item),
                "recent_movements": StockMovementSerializer(movements, many=True).data,
            }
        )


class MovementHistoryView(APIView):
    """Historique immuable complet et filtrable d'un article (S 3-04)."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_VIEW)]
    serializer_class = StockMovementSerializer

    def get(self, request, business_id, item_id):
        item = request.business.items.filter(id=item_id).first()
        if item is None:
            return Response({"detail": "Article introuvable."}, status=status.HTTP_404_NOT_FOUND)
        qs = item.movements.select_related("acteur", "related_to")
        mvt_type = request.query_params.get("type")
        if mvt_type:
            qs = qs.filter(type=mvt_type)
        return paginated(request, qs, StockMovementSerializer)


class StockMovementCreateView(WriteThrottleMixin, APIView):
    """Crée un mouvement (US-08 à US-12) : entrée, sortie, retour, perte, dommage.

    Sprint 6 (RM-22) : une sortie est d'abord évaluée contre les règles
    métier du business (RM-05, RM-07). Règle BLOCAGE = refus obligatoire ;
    règle AVERTISSEMENT = la demande renvoie les alertes et exige, pour
    poursuivre, `ignorer_avertissements=true` + `motif_exception` (US-19,
    US-20, US-21) ainsi que la permission stock.exception (RM-19).
    """

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_MOUVEMENT)]
    serializer_class = StockMovementSerializer

    def post(self, request, business_id):
        serializer = StockMovementSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        item = data["item_id"]
        quantite = data["quantite"]

        violations = []
        bypass_motif = ""
        if data["type"] == StockMovement.Type.SORTIE:
            violations = check_rules(
                business=request.business,
                item=item,
                acteur=request.user,
                quantite=quantite,
            )
            bloquants = [
                v for v in violations if v["mode"] == BusinessRule.Mode.BLOCAGE
            ]
            if bloquants:
                log_activity(
                    business=request.business,
                    acteur=request.user,
                    action=Act.RULE_BLOCAGE,
                    item=item,
                    detail={"codes": [v["code"] for v in bloquants]},
                )
                notify_members(
                    business=request.business,
                    code="RULE.BLOCAGE",
                    message=(
                        f"Opération refusée sur « {item.nom} » : règle bloquante "
                        f"({', '.join(v['code'] for v in bloquants)})."
                    ),
                    item=item,
                    permission_codename=Perm.STOCK_EXCEPTION,
                    ignore_user=request.user,
                )
                return Response(
                    {
                        "detail": (
                            "Règle bloquante : l'opération est refusée, "
                            "le blocage est obligatoire (RM-22)."
                        ),
                        "bloque": bloquants,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if violations:
                log_activity(
                    business=request.business,
                    acteur=request.user,
                    action=Act.RULE_ALERTE,
                    item=item,
                    detail={"codes": [v["code"] for v in violations]},
                )
                if not bool(request.data.get("ignorer_avertissements", False)):
                    return Response(
                        {
                            "detail": (
                                "Avertissement(s) émis. Pour utiliser malgré "
                                "l'avertissement, envoyez ignorer_avertissements=true "
                                "et un motif_exception."
                            ),
                            "avertissements": violations,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                bypass_motif = (request.data.get("motif_exception") or "").strip()
                if not bypass_motif:
                    return Response(
                        {
                            "detail": "motif_exception est obligatoire pour "
                            "utiliser malgré l'avertissement (RM-06).",
                            "avertissements": violations,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                exception_permission = HasBusinessPermission.require(Perm.STOCK_EXCEPTION)
                if not exception_permission().has_permission(request, None):
                    return Response(
                        {
                            "detail": "Permission requise pour une décision "
                            "exceptionnelle (RM-19).",
                            "avertissements": violations,
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

        movement, state = create_movement(
            business=request.business,
            item=item,
            type=data["type"],
            quantite=quantite,
            acteur=request.user,
            motif=data.get("motif", ""),
            reference=data.get("reference", ""),
            related_to=data.get("related_to"),
        )

        response = {
            "movement": StockMovementSerializer(movement).data,
            "stock": state,
        }
        if violations:
            alert_ids = [v["alert_id"] for v in violations]
            Alert.objects.filter(id__in=alert_ids).update(mouvement=movement)
            rules_by_code = {
                r.code: r
                for r in request.business.rules.filter(
                    code__in=[v["code"] for v in violations]
                )
            }
            decisions = [
                record_decision(
                    business=request.business,
                    item=item,
                    rule=rules_by_code[v["code"]],
                    acteur=request.user,
                    motif=bypass_motif,
                    quantite=quantite,
                    mouvement=movement,
                    code=v["code"],
                )
                for v in violations
            ]
            response["avertissements"] = violations
            response["decisions"] = DecisionLogSerializer(decisions, many=True).data
        return Response(response, status=status.HTTP_201_CREATED)


# --- Entretien (Sprint 4, US-13 à US-17) -----------------------------------
# Procédures (RM-09), tâches (RM-10), étapes (US-16), entretien partiel
# accepté (RM-11). L'état réel est TOUJOURS dérivé de la dernière tâche.


class ProcedureListCreateView(WriteThrottleMixin, APIView):
    serializer_class = ProcedureSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)()]
        return [HasBusinessPermission.require(Perm.ENTRETIEN_VIEW)()]

    def get(self, request, business_id):
        qs = request.business.procedures.prefetch_related("steps")
        search = request.query_params.get("search")
        if search:
            qs = qs.filter(nom__icontains=search)
        est_actif = request.query_params.get("est_actif")
        if est_actif in ("true", "false"):
            qs = qs.filter(est_actif=est_actif == "true")
        return paginated(request, qs, ProcedureSerializer)

    def post(self, request, business_id):
        serializer = ProcedureSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        procedure = serializer.save(
            business=request.business, created_by=request.user
        )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.PROCEDURE_CREATE,
            cible=procedure.nom,
        )
        return Response(
            ProcedureSerializer(procedure).data, status=status.HTTP_201_CREATED
        )


class ProcedureDetailView(APIView):
    serializer_class = ProcedureSerializer

    def _is_write(self):
        return self.request.method in ("PUT", "PATCH", "DELETE")

    def get_permissions(self):
        if self._is_write():
            return [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)()]
        return [HasBusinessPermission.require(Perm.ENTRETIEN_VIEW)()]

    def _get_procedure(self, request, business_id, procedure_id):
        return request.business.procedures.prefetch_related("steps").filter(
            id=procedure_id
        ).first()

    def get(self, request, business_id, procedure_id):
        procedure = self._get_procedure(request, business_id, procedure_id)
        if procedure is None:
            return Response({"detail": "Procédure introuvable."}, status=status.HTTP_404_NOT_FOUND)
        return Response(ProcedureSerializer(procedure).data)

    def put(self, request, business_id, procedure_id):
        return self._save(request, business_id, procedure_id, partial=False)

    def patch(self, request, business_id, procedure_id):
        return self._save(request, business_id, procedure_id, partial=True)

    def _save(self, request, business_id, procedure_id, partial):
        procedure = self._get_procedure(request, business_id, procedure_id)
        if procedure is None:
            return Response({"detail": "Procédure introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = ProcedureSerializer(
            procedure, data=request.data, partial=partial,
            context={"business": request.business},
        )
        serializer.is_valid(raise_exception=True)
        procedure = serializer.save()
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.PROCEDURE_UPDATE,
            cible=procedure.nom,
        )
        return Response(ProcedureSerializer(procedure).data)

    def delete(self, request, business_id, procedure_id):
        procedure = self._get_procedure(request, business_id, procedure_id)
        if procedure is None:
            return Response({"detail": "Procédure introuvable."}, status=status.HTTP_404_NOT_FOUND)
        if procedure.tasks.exists():
            return Response(
                {"detail": "Cette procédure est utilisée par des tâches."},
                status=status.HTTP_409_CONFLICT,
            )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.PROCEDURE_DELETE,
            cible=procedure.nom,
        )
        procedure.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TaskListCreateView(WriteThrottleMixin, APIView):
    """Liste des tâches (filtrable) + création manuelle (US-15)."""

    serializer_class = MaintenanceTaskSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)()]
        return [HasBusinessPermission.require(Perm.ENTRETIEN_VIEW)()]

    def get(self, request, business_id):
        qs = request.business.maintenance_tasks.select_related(
            "item", "assigned_to", "assigned_by", "created_by"
        ).order_by("-created_at", "-id")
        item_id = request.query_params.get("item_id")
        if item_id:
            qs = qs.filter(item_id=item_id)
        statut = request.query_params.get("statut")
        if statut:
            qs = qs.filter(statut=statut)
        procedure_id = request.query_params.get("procedure_id")
        if procedure_id:
            qs = qs.filter(procedure_id=procedure_id)
        # Sprint 1: Filtre par assignation
        assigned_to_id = request.query_params.get("assigned_to_id")
        if assigned_to_id:
            qs = qs.filter(assigned_to_id=assigned_to_id)
        mes_taches = request.query_params.get("mes_taches")
        if mes_taches == "true":
            qs = qs.filter(assigned_to=request.user)
        non_assignees = request.query_params.get("non_assignees")
        if non_assignees == "true":
            qs = qs.filter(assigned_to__isnull=True)
        paginator = StandardPagination()
        page = paginator.paginate_queryset(qs, request)
        tasks = list(page)
        etats = etats_entretien([t.item for t in tasks])
        return paginator.get_paginated_response(
            MaintenanceTaskSerializer(
                tasks, many=True, context={"etats": etats}
            ).data
        )

    def post(self, request, business_id):
        serializer = TaskCreateSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        task = create_task(
            business=request.business,
            item=serializer.validated_data["item_id"],
            acteur=request.user,
            procedure=serializer.validated_data.get("procedure_id"),
            motif=serializer.validated_data.get("motif", ""),
        )
        # Sprint 1: Attribution à la création
        assigned_to = serializer.validated_data.get("assigned_to_id")
        if assigned_to:
            task.assigned_to = assigned_to
            task.assigned_at = timezone.now()
            task.assigned_by = request.user
            task.save(update_fields=["assigned_to", "assigned_at", "assigned_by"])
            # Notification au membre assigné
            if assigned_to != request.user:
                notify_members(
                    business=request.business,
                    code="TASK.ASSIGNED",
                    message=f"Une tâche vous a été assignée : {task.procedure_nom} sur {task.item.nom}",
                    item=task.item,
                    user_ids=[assigned_to.id],
                )
        # Sprint 2: Coûts estimés
        cout_main_oeuvre = serializer.validated_data.get("cout_main_oeuvre")
        cout_materiel = serializer.validated_data.get("cout_materiel")
        if cout_main_oeuvre is not None or cout_materiel is not None:
            if cout_main_oeuvre is not None:
                task.cout_main_oeuvre = cout_main_oeuvre
            if cout_materiel is not None:
                task.cout_materiel = cout_materiel
            task.save(update_fields=["cout_main_oeuvre", "cout_materiel"])
        return Response(
            MaintenanceTaskSerializer(
                task, context={"etats": {task.item_id: etat_entretien(task.item)}}
            ).data,
            status=status.HTTP_201_CREATED,
        )


class TaskDetailView(APIView):
    serializer_class = MaintenanceTaskSerializer

    def get_permissions(self):
        if self.request.method == "PATCH":
            return [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)()]
        return [HasBusinessPermission.require(Perm.ENTRETIEN_VIEW)()]

    def _get_task(self, request, task_id):
        return request.business.maintenance_tasks.select_related(
            "item", "assigned_to", "assigned_by", "created_by"
        ).prefetch_related("steps", "comments").filter(id=task_id).first()

    def get(self, request, business_id, task_id):
        task = self._get_task(request, task_id)
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        return Response(
            MaintenanceTaskSerializer(
                task, context={"etats": {task.item_id: etat_entretien(task.item)}}
            ).data
        )

    def patch(self, request, business_id, task_id):
        """Mise à jour d'une tâche (attribution, coûts) - Sprint 1 & 2."""
        task = self._get_task(request, task_id)
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = TaskUpdateSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        update_fields = []
        # Attribution
        if "assigned_to_id" in serializer.validated_data:
            new_assigned = serializer.validated_data["assigned_to_id"]
            old_assigned = task.assigned_to
            if new_assigned != old_assigned:
                task.assigned_to = new_assigned
                task.assigned_at = timezone.now() if new_assigned else None
                task.assigned_by = request.user if new_assigned else None
                update_fields.extend(["assigned_to", "assigned_at", "assigned_by"])
                # Notification
                if new_assigned and new_assigned != request.user:
                    notify_members(
                        business=request.business,
                        code="TASK.ASSIGNED",
                        message=f"Une tâche vous a été assignée : {task.procedure_nom} sur {task.item.nom}",
                        item=task.item,
                        user_ids=[new_assigned.id],
                    )
                log_activity(
                    business=request.business,
                    acteur=request.user,
                    action=Act.TASK_ASSIGNED if new_assigned else Act.TASK_UNASSIGNED,
                    item=task.item,
                    detail={"assigned_to": str(new_assigned.id) if new_assigned else None},
                )
        # Coûts
        if "cout_main_oeuvre" in serializer.validated_data:
            task.cout_main_oeuvre = serializer.validated_data["cout_main_oeuvre"]
            update_fields.append("cout_main_oeuvre")
        if "cout_materiel" in serializer.validated_data:
            task.cout_materiel = serializer.validated_data["cout_materiel"]
            update_fields.append("cout_materiel")
        if update_fields:
            task.save(update_fields=update_fields)
        return Response(
            MaintenanceTaskSerializer(
                task, context={"etats": {task.item_id: etat_entretien(task.item)}}
            ).data
        )


class TaskStepUpdateView(APIView):
    """Met à jour une étape d'une tâche ouverte (US-16)."""

    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]
    serializer_class = TaskStepUpdateSerializer

    def patch(self, request, business_id, task_id, step_id):
        task = request.business.maintenance_tasks.filter(id=task_id).first()
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        step = task.steps.filter(id=step_id).first()
        if step is None:
            return Response({"detail": "Étape introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = TaskStepUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        step = update_step(step, serializer.validated_data["statut"], request.user)
        return Response(
            {
                "id": step.id,
                "statut": step.statut,
                "started_at": step.started_at,
                "finished_at": step.finished_at,
            }
        )


class TaskClotureView(APIView):
    """Clôture une tâche : TERMINEE ou PARTIELLE acceptée (US-16, US-17, RM-11)."""

    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]
    serializer_class = MaintenanceTaskSerializer

    def post(self, request, business_id, task_id):
        task = request.business.maintenance_tasks.select_related("item").filter(
            id=task_id
        ).first()
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        partielle = bool(request.data.get("partielle", False))
        task = cloturer_task(task, acteur=request.user, partielle=partielle)
        return Response(
            MaintenanceTaskSerializer(
                task, context={"etats": {task.item_id: etat_entretien(task.item)}}
            ).data
        )


# --- Sprint 1: Commentaires sur les tâches ----------------------------------


class TaskCommentListCreateView(WriteThrottleMixin, APIView):
    """Liste et création de commentaires sur une tâche."""

    serializer_class = TaskCommentSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)()]
        return [HasBusinessPermission.require(Perm.ENTRETIEN_VIEW)()]

    def _get_task(self, request, task_id):
        return request.business.maintenance_tasks.filter(id=task_id).first()

    def get(self, request, business_id, task_id):
        task = self._get_task(request, task_id)
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        comments = task.comments.select_related("auteur").order_by("created_at")
        return Response(TaskCommentSerializer(comments, many=True).data)

    def post(self, request, business_id, task_id):
        task = self._get_task(request, task_id)
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = TaskCommentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        comment = TaskComment.objects.create(
            task=task,
            auteur=request.user,
            contenu=serializer.validated_data["contenu"],
        )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.TASK_COMMENT,
            item=task.item,
            detail={"task_id": str(task.id)},
        )
        # Notifier le membre assigné et le créateur
        notify_users = set()
        if task.assigned_to and task.assigned_to != request.user:
            notify_users.add(task.assigned_to.id)
        if task.created_by and task.created_by != request.user:
            notify_users.add(task.created_by.id)
        if notify_users:
            notify_members(
                business=request.business,
                code="TASK.COMMENT",
                message=f"Nouveau commentaire sur la tâche {task.procedure_nom}",
                item=task.item,
                user_ids=list(notify_users),
            )
        return Response(
            TaskCommentSerializer(comment).data, status=status.HTTP_201_CREATED
        )


class TaskCommentDetailView(APIView):
    """Détail et suppression d'un commentaire."""

    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def delete(self, request, business_id, task_id, comment_id):
        task = request.business.maintenance_tasks.filter(id=task_id).first()
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        comment = task.comments.filter(id=comment_id).first()
        if comment is None:
            return Response({"detail": "Commentaire introuvable."}, status=status.HTTP_404_NOT_FOUND)
        # Seul l'auteur ou un admin peut supprimer
        if comment.auteur != request.user:
            return Response(
                {"detail": "Vous ne pouvez supprimer que vos propres commentaires."},
                status=status.HTTP_403_FORBIDDEN,
            )
        comment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Sprint 2: Photos sur les étapes ----------------------------------------


class TaskStepPhotoListCreateView(WriteThrottleMixin, APIView):
    """Liste et upload de photos sur une étape de tâche."""

    serializer_class = TaskStepPhotoSerializer
    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def _get_step(self, request, task_id, step_id):
        task = request.business.maintenance_tasks.filter(id=task_id).first()
        if task is None:
            return None, None
        step = task.steps.filter(id=step_id).first()
        return task, step

    def get(self, request, business_id, task_id, step_id):
        task, step = self._get_step(request, task_id, step_id)
        if step is None:
            return Response({"detail": "Étape introuvable."}, status=status.HTTP_404_NOT_FOUND)
        photos = step.photos.select_related("uploaded_by").order_by("created_at")
        return Response(TaskStepPhotoSerializer(photos, many=True).data)

    def post(self, request, business_id, task_id, step_id):
        task, step = self._get_step(request, task_id, step_id)
        if step is None:
            return Response({"detail": "Étape introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = TaskStepPhotoCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        photo = TaskStepPhoto.objects.create(
            step=step,
            image=serializer.validated_data["image"],
            type=serializer.validated_data["type"],
            caption=serializer.validated_data.get("caption", ""),
            uploaded_by=request.user,
        )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.STEP_PHOTO,
            item=task.item,
            detail={"step_id": str(step.id), "photo_type": photo.type},
        )
        return Response(
            TaskStepPhotoSerializer(photo).data, status=status.HTTP_201_CREATED
        )


class TaskStepPhotoDeleteView(APIView):
    """Suppression d'une photo d'étape."""

    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def delete(self, request, business_id, task_id, step_id, photo_id):
        task = request.business.maintenance_tasks.filter(id=task_id).first()
        if task is None:
            return Response({"detail": "Tâche introuvable."}, status=status.HTTP_404_NOT_FOUND)
        step = task.steps.filter(id=step_id).first()
        if step is None:
            return Response({"detail": "Étape introuvable."}, status=status.HTTP_404_NOT_FOUND)
        photo = step.photos.filter(id=photo_id).first()
        if photo is None:
            return Response({"detail": "Photo introuvable."}, status=status.HTTP_404_NOT_FOUND)
        photo.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Sprint 3: Tâches récurrentes -------------------------------------------


class RecurringTaskListCreateView(WriteThrottleMixin, APIView):
    """Liste et création de tâches récurrentes."""

    serializer_class = RecurringTaskSerializer
    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def get(self, request, business_id):
        qs = request.business.recurring_tasks.select_related(
            "item", "category", "procedure", "created_by"
        ).order_by("prochaine_execution")
        est_actif = request.query_params.get("est_actif")
        if est_actif in ("true", "false"):
            qs = qs.filter(est_actif=est_actif == "true")
        return paginated(request, qs, RecurringTaskSerializer)

    def post(self, request, business_id):
        serializer = RecurringTaskCreateSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        recurring_task = RecurringTask.objects.create(
            business=request.business,
            item=serializer.validated_data.get("item_id"),
            category=serializer.validated_data.get("category_id"),
            procedure=serializer.validated_data["procedure_id"],
            frequence_jours=serializer.validated_data["frequence_jours"],
            prochaine_execution=serializer.validated_data["prochaine_execution"],
            est_actif=serializer.validated_data.get("est_actif", True),
            created_by=request.user,
        )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.RECURRING_CREATE,
            cible=f"{recurring_task.procedure.nom} ({recurring_task.frequence_jours}j)",
        )
        return Response(
            RecurringTaskSerializer(recurring_task).data,
            status=status.HTTP_201_CREATED,
        )


class RecurringTaskDetailView(APIView):
    """Détail, modification et suppression d'une tâche récurrente."""

    serializer_class = RecurringTaskSerializer
    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def _get_recurring(self, request, recurring_id):
        return request.business.recurring_tasks.select_related(
            "item", "category", "procedure", "created_by"
        ).filter(id=recurring_id).first()

    def get(self, request, business_id, recurring_id):
        recurring = self._get_recurring(request, recurring_id)
        if recurring is None:
            return Response(
                {"detail": "Tâche récurrente introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(RecurringTaskSerializer(recurring).data)

    def patch(self, request, business_id, recurring_id):
        recurring = self._get_recurring(request, recurring_id)
        if recurring is None:
            return Response(
                {"detail": "Tâche récurrente introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        update_fields = []
        for field in ["frequence_jours", "prochaine_execution", "est_actif"]:
            if field in request.data:
                setattr(recurring, field, request.data[field])
                update_fields.append(field)
        if update_fields:
            recurring.save(update_fields=update_fields)
        return Response(RecurringTaskSerializer(recurring).data)

    def delete(self, request, business_id, recurring_id):
        recurring = self._get_recurring(request, recurring_id)
        if recurring is None:
            return Response(
                {"detail": "Tâche récurrente introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.RECURRING_DELETE,
            cible=f"{recurring.procedure.nom}",
        )
        recurring.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Sprint 3: Rappels ------------------------------------------------------


class ReminderListCreateView(WriteThrottleMixin, APIView):
    """Liste et création de rappels."""

    serializer_class = ReminderSerializer
    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def get(self, request, business_id):
        qs = request.business.reminders.select_related(
            "task", "item", "user", "created_by"
        ).order_by("rappel_a")
        # Filtres
        user_id = request.query_params.get("user_id")
        if user_id:
            qs = qs.filter(user_id=user_id)
        mes_rappels = request.query_params.get("mes_rappels")
        if mes_rappels == "true":
            qs = qs.filter(user=request.user)
        envoye = request.query_params.get("envoye")
        if envoye in ("true", "false"):
            qs = qs.filter(envoye=envoye == "true")
        return paginated(request, qs, ReminderSerializer)

    def post(self, request, business_id):
        serializer = ReminderCreateSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        reminder = Reminder.objects.create(
            business=request.business,
            task=serializer.validated_data.get("task_id"),
            item=serializer.validated_data.get("item_id"),
            user=serializer.validated_data["user_id"],
            rappel_a=serializer.validated_data["rappel_a"],
            message=serializer.validated_data["message"],
            created_by=request.user,
        )
        return Response(
            ReminderSerializer(reminder).data, status=status.HTTP_201_CREATED
        )


class ReminderDetailView(APIView):
    """Suppression d'un rappel."""

    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def delete(self, request, business_id, reminder_id):
        reminder = request.business.reminders.filter(id=reminder_id).first()
        if reminder is None:
            return Response(
                {"detail": "Rappel introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        reminder.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Sprint 6: QR Code scanning ---------------------------------------------


class ItemScanView(APIView):
    """Récupère un article par son QR code."""

    permission_classes = [HasBusinessPermission.require(Perm.CATALOG_VIEW)]

    def get(self, request, business_id, qr_code):
        item = request.business.items.filter(qr_code=qr_code).first()
        if item is None:
            return Response(
                {"detail": "Article introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        return Response(ItemSerializer(item, context={"business": request.business}).data)


# --- Sprint 4: Historique avec filtres --------------------------------------


class HistoryView(APIView):
    """Historique global avec filtres (tâches, stock, réservations, décisions)."""

    permission_classes = [HasBusinessPermission.require(Perm.CATALOG_VIEW)]

    def get(self, request, business_id):
        from datetime import datetime
        from itertools import chain

        filter_type = request.query_params.get("type", "all")
        item_id = request.query_params.get("item_id")
        acteur_id = request.query_params.get("acteur_id")
        date_from = request.query_params.get("date_from")
        date_to = request.query_params.get("date_to")

        results = []

        # Tâches de maintenance
        if filter_type in ("all", "task"):
            qs = request.business.maintenance_tasks.select_related(
                "item", "created_by"
            )
            if item_id:
                qs = qs.filter(item_id=item_id)
            if acteur_id:
                qs = qs.filter(created_by_id=acteur_id)
            if date_from:
                qs = qs.filter(created_at__date__gte=date_from)
            if date_to:
                qs = qs.filter(created_at__date__lte=date_to)
            for t in qs[:50]:
                results.append({
                    "type": "task",
                    "id": str(t.id),
                    "item_id": str(t.item_id),
                    "item_nom": t.item.nom,
                    "action": f"Tâche {t.procedure_nom} - {t.statut}",
                    "acteur": t.created_by.email if t.created_by else None,
                    "date": t.created_at.isoformat(),
                })

        # Mouvements de stock
        if filter_type in ("all", "stock"):
            qs = request.business.stock_movements.select_related("item", "acteur")
            if item_id:
                qs = qs.filter(item_id=item_id)
            if acteur_id:
                qs = qs.filter(acteur_id=acteur_id)
            if date_from:
                qs = qs.filter(created_at__date__gte=date_from)
            if date_to:
                qs = qs.filter(created_at__date__lte=date_to)
            for m in qs[:50]:
                results.append({
                    "type": "stock",
                    "id": str(m.id),
                    "item_id": str(m.item_id),
                    "item_nom": m.item.nom,
                    "action": f"{m.type} x{m.quantite}",
                    "acteur": m.acteur.email,
                    "date": m.created_at.isoformat(),
                })

        # Réservations
        if filter_type in ("all", "reservation"):
            qs = request.business.reservations.select_related("item", "reserve_par")
            if item_id:
                qs = qs.filter(item_id=item_id)
            if acteur_id:
                qs = qs.filter(reserve_par_id=acteur_id)
            if date_from:
                qs = qs.filter(created_at__date__gte=date_from)
            if date_to:
                qs = qs.filter(created_at__date__lte=date_to)
            for r in qs[:50]:
                results.append({
                    "type": "reservation",
                    "id": str(r.id),
                    "item_id": str(r.item_id),
                    "item_nom": r.item.nom,
                    "action": f"Réservation {r.statut} x{r.quantite}",
                    "acteur": r.reserve_par.email,
                    "date": r.created_at.isoformat(),
                })

        # Décisions
        if filter_type in ("all", "decision"):
            qs = request.business.decisions.select_related("item", "acteur")
            if item_id:
                qs = qs.filter(item_id=item_id)
            if acteur_id:
                qs = qs.filter(acteur_id=acteur_id)
            if date_from:
                qs = qs.filter(created_at__date__gte=date_from)
            if date_to:
                qs = qs.filter(created_at__date__lte=date_to)
            for d in qs[:50]:
                results.append({
                    "type": "decision",
                    "id": str(d.id),
                    "item_id": str(d.item_id),
                    "item_nom": d.item.nom,
                    "action": f"Décision {d.code}: {d.motif[:50]}",
                    "acteur": d.acteur.email,
                    "date": d.created_at.isoformat(),
                })

        # Tri par date décroissante
        results.sort(key=lambda x: x["date"], reverse=True)
        return Response(results[:100])


# --- Sprint 5: Analytics ---------------------------------------------------


class AnalyticsView(APIView):
    """Statistiques avancées pour le dashboard."""

    permission_classes = [HasBusinessPermission.require(Perm.CATALOG_VIEW)]

    def get(self, request, business_id):
        from datetime import timedelta
        from django.db.models import Avg, Sum
        from django.db.models.functions import TruncMonth

        business = request.business
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)

        # Tâches par mois (6 derniers mois)
        six_months_ago = now - timedelta(days=180)
        taches_par_mois = list(
            business.maintenance_tasks.filter(created_at__gte=six_months_ago)
            .annotate(mois=TruncMonth("created_at"))
            .values("mois")
            .annotate(count=Count("id"))
            .order_by("mois")
        )

        # Taux de complétion (tâches terminées / total des 30 derniers jours)
        tasks_30j = business.maintenance_tasks.filter(created_at__gte=thirty_days_ago)
        total_tasks = tasks_30j.count()
        completed_tasks = tasks_30j.filter(statut=MaintenanceTask.Statut.TERMINEE).count()
        taux_completion = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0

        # Articles les plus entretenus
        articles_plus_entretenus = list(
            business.maintenance_tasks.values("item__nom", "item_id")
            .annotate(count=Count("id"))
            .order_by("-count")[:10]
        )

        # Coûts totaux (30 derniers jours)
        couts_30j = business.maintenance_tasks.filter(
            created_at__gte=thirty_days_ago
        ).aggregate(
            total_main_oeuvre=Sum("cout_main_oeuvre"),
            total_materiel=Sum("cout_materiel"),
        )

        # Temps moyen par procédure
        from django.db.models import F, ExpressionWrapper, DurationField
        temps_par_procedure = []
        for proc in business.procedures.all()[:10]:
            steps = TaskStep.objects.filter(
                task__procedure=proc,
                finished_at__isnull=False,
                started_at__isnull=False,
            )
            durees = [
                (s.finished_at - s.started_at).total_seconds()
                for s in steps
            ]
            if durees:
                temps_par_procedure.append({
                    "procedure_nom": proc.nom,
                    "duree_moyenne_secondes": sum(durees) / len(durees),
                })

        # Tendance 30 jours (nombre de tâches par jour)
        from django.db.models.functions import TruncDate
        tendance_30_jours = list(
            business.maintenance_tasks.filter(created_at__gte=thirty_days_ago)
            .annotate(jour=TruncDate("created_at"))
            .values("jour")
            .annotate(count=Count("id"))
            .order_by("jour")
        )

        return Response({
            "taches_par_mois": [
                {"mois": t["mois"].isoformat() if t["mois"] else None, "count": t["count"]}
                for t in taches_par_mois
            ],
            "taux_completion": round(taux_completion, 1),
            "articles_plus_entretenus": [
                {"item_id": str(a["item_id"]), "nom": a["item__nom"], "count": a["count"]}
                for a in articles_plus_entretenus
            ],
            "couts_30_jours": {
                "main_oeuvre": float(couts_30j["total_main_oeuvre"] or 0),
                "materiel": float(couts_30j["total_materiel"] or 0),
                "total": float((couts_30j["total_main_oeuvre"] or 0) + (couts_30j["total_materiel"] or 0)),
            },
            "temps_moyen_par_procedure": temps_par_procedure,
            "tendance_30_jours": [
                {"jour": t["jour"].isoformat() if t["jour"] else None, "count": t["count"]}
                for t in tendance_30_jours
            ],
        })


# --- Sprint 9: Alertes de performance ---------------------------------------


class PerformanceAlertListView(APIView):
    """Liste des alertes de performance."""

    serializer_class = PerformanceAlertSerializer
    permission_classes = [HasBusinessPermission.require(Perm.CATALOG_VIEW)]

    def get(self, request, business_id):
        qs = request.business.performance_alerts.select_related("item", "resolved_by")
        resolved = request.query_params.get("resolved")
        if resolved in ("true", "false"):
            qs = qs.filter(resolved=resolved == "true")
        return paginated(request, qs, PerformanceAlertSerializer)


class PerformanceAlertResolveView(APIView):
    """Marque une alerte de performance comme résolue."""

    permission_classes = [HasBusinessPermission.require(Perm.ENTRETIEN_MANAGE)]

    def post(self, request, business_id, alert_id):
        alert = request.business.performance_alerts.filter(id=alert_id).first()
        if alert is None:
            return Response(
                {"detail": "Alerte introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        if alert.resolved:
            return Response(
                {"detail": "Alerte déjà résolue."}, status=status.HTTP_400_BAD_REQUEST
            )
        alert.resolved = True
        alert.resolved_at = timezone.now()
        alert.resolved_by = request.user
        alert.save(update_fields=["resolved", "resolved_at", "resolved_by"])
        return Response(PerformanceAlertSerializer(alert).data)


# --- Disponibilité & fiabilité (Sprint 5, US-18, US-22 à US-26) ------------
# RM-13 : écart = événement. RM-14 : déclaré ≠ vérifié. RM-15 : estimé ≠ certain.


class InventoryListCreateView(WriteThrottleMixin, APIView):
    serializer_class = InventorySerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.STOCK_INVENTAIRE)()]
        return [HasBusinessPermission.require(Perm.STOCK_VIEW)()]

    def get(self, request, business_id):
        qs = request.business.inventories.select_related("created_by")
        statut = request.query_params.get("statut")
        if statut:
            qs = qs.filter(statut=statut)
        return paginated(request, qs, InventorySerializer)

    def post(self, request, business_id):
        serializer = InventorySerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        inventory = serializer.save(
            business=request.business, created_by=request.user
        )
        return Response(
            InventorySerializer(inventory).data, status=status.HTTP_201_CREATED
        )


class InventoryDetailView(APIView):
    serializer_class = InventorySerializer

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_VIEW)]

    def _get_inventory(self, request, business_id, inventory_id):
        return request.business.inventories.filter(id=inventory_id).first()

    def get(self, request, business_id, inventory_id):
        inventory = self._get_inventory(request, business_id, inventory_id)
        if inventory is None:
            return Response(
                {"detail": "Inventaire introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        counts = inventory.counts.select_related("item", "declared_by")
        return Response(
            {
                **InventorySerializer(inventory).data,
                "counts": InventoryCountSerializer(counts, many=True).data,
            }
        )


class InventoryCountView(WriteThrottleMixin, APIView):
    """Déclare ou remplace le comptage d'un article (US-22, RM-14)."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_INVENTAIRE)]
    serializer_class = InventoryCountSerializer

    def post(self, request, business_id, inventory_id):
        inventory = request.business.inventories.filter(id=inventory_id).first()
        if inventory is None:
            return Response(
                {"detail": "Inventaire introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = InventoryCountWriteSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        count, created = declare_count(
            inventory=inventory,
            item=serializer.validated_data["item_id"],
            quantite_comptee=serializer.validated_data["quantite_comptee"],
            fiabilite=serializer.validated_data["fiabilite"],
            acteur=request.user,
        )
        return Response(
            InventoryCountSerializer(count).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class InventoryCountDetailView(APIView):
    """Met à jour fiabilité / quantité d'un comptage tant que l'inventaire est ouvert."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_INVENTAIRE)]
    serializer_class = InventoryCountSerializer

    def patch(self, request, business_id, inventory_id, count_id):
        count = InventoryCount.objects.filter(
            id=count_id, inventory_id=inventory_id
        ).first()
        if count is None or count.inventory.business_id != request.business.id:
            return Response(
                {"detail": "Comptage introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        if count.inventory.statut != Inventory.Statut.EN_COURS:
            return Response(
                {"detail": "Inventaire clôturé : comptage figé."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = InventoryCountWriteSerializer(
            data=request.data, partial=True, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        if "quantite_comptee" in serializer.validated_data:
            count.quantite_comptee = serializer.validated_data["quantite_comptee"]
        if "fiabilite" in serializer.validated_data:
            count.fiabilite = serializer.validated_data["fiabilite"]
        count.declared_by = request.user
        count.save()
        return Response(InventoryCountSerializer(count).data)


class InventoryClotureView(WriteThrottleMixin, APIView):
    """Clôture : chaque écart non nul devient un ajustement immuable (RM-13)."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_INVENTAIRE)]
    serializer_class = InventorySerializer

    def post(self, request, business_id, inventory_id):
        inventory = request.business.inventories.filter(id=inventory_id).first()
        if inventory is None:
            return Response(
                {"detail": "Inventaire introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        summary = cloturer_inventory(inventory=inventory, acteur=request.user)
        inventory.refresh_from_db()
        return Response(
            {**InventorySerializer(inventory).data, "bilan": summary}
        )


class AdjustmentListCreateView(WriteThrottleMixin, APIView):
    """Ajustements : liste filtrable (US-26) + ajustement manuel (US-24)."""

    serializer_class = StockAdjustmentSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.STOCK_INVENTAIRE)()]
        return [HasBusinessPermission.require(Perm.STOCK_VIEW)()]

    def get(self, request, business_id):
        qs = request.business.adjustments.select_related("item", "acteur")
        item_id = request.query_params.get("item_id")
        if item_id:
            qs = qs.filter(item_id=item_id)
        inventory_id = request.query_params.get("inventory_id")
        if inventory_id:
            qs = qs.filter(inventory_id=inventory_id)
        return paginated(request, qs, StockAdjustmentSerializer)

    def post(self, request, business_id):
        serializer = StockAdjustmentWriteSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        adjustment = create_adjustment(
            business=request.business,
            item=serializer.validated_data["item_id"],
            quantite_comptee=serializer.validated_data["quantite_comptee"],
            acteur=request.user,
            motif=serializer.validated_data.get("motif", ""),
            reference=serializer.validated_data.get("reference", ""),
        )
        return Response(
            StockAdjustmentSerializer(adjustment).data,
            status=status.HTTP_201_CREATED,
        )


# --- Alertes, décisions & règles métier (Sprint 6, US-19 à US-21) ----------
# RM-22 : Informer -> Avertir -> Décider -> Tracer. Les alertes et les
# décisions sont des journaux immuables : aucune modification ni suppression.
# Les règles sont configurables par business (RM-07) : mode AVERTISSEMENT
# (dépassable avec permission + décision) ou BLOCAGE (obligatoire).


class RulesListView(APIView):
    """Règles métier du business (RM-07, S 6-05). Listées dès la création."""

    permission_classes = [HasBusinessPermission.require(Perm.BUSINESS_RULES)]
    serializer_class = BusinessRuleSerializer

    def get(self, request, business_id):
        return paginated(
            request, request.business.rules.all(), BusinessRuleSerializer
        )


class RuleDetailView(APIView):
    """Modifie le mode (AVERTISSEMENT / BLOCAGE) ou l'activation d'une règle."""

    permission_classes = [HasBusinessPermission.require(Perm.BUSINESS_RULES)]
    serializer_class = BusinessRuleSerializer

    def _get_rule(self, request, business_id, rule_id):
        return request.business.rules.filter(id=rule_id).first()

    def patch(self, request, business_id, rule_id):
        rule = self._get_rule(request, business_id, rule_id)
        if rule is None:
            return Response({"detail": "Règle introuvable."}, status=status.HTTP_404_NOT_FOUND)
        serializer = BusinessRuleSerializer(rule, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        rule = serializer.save()
        return Response(BusinessRuleSerializer(rule).data)


class AlertsListView(APIView):
    """Alertes émises (US-19). Immuables : le problème reste visible."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_VIEW)]
    serializer_class = AlertSerializer

    def get(self, request, business_id):
        qs = request.business.alerts.select_related("item", "acteur")
        item_id = request.query_params.get("item_id")
        if item_id:
            qs = qs.filter(item_id=item_id)
        code = request.query_params.get("code")
        if code:
            qs = qs.filter(code=code)
        mode = request.query_params.get("mode")
        if mode:
            qs = qs.filter(mode=mode)
        return paginated(request, qs, AlertSerializer)


class DecisionsListView(APIView):
    """Journal des décisions exceptionnelles (US-21, RM-06)."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_VIEW)]
    serializer_class = DecisionLogSerializer

    def get(self, request, business_id):
        qs = request.business.decisions.select_related("item", "acteur")
        item_id = request.query_params.get("item_id")
        if item_id:
            qs = qs.filter(item_id=item_id)
        code = request.query_params.get("code")
        if code:
            qs = qs.filter(code=code)
        return paginated(request, qs, DecisionLogSerializer)


# --- Collaboration & visibilité (Sprint 7, US-27, US-28) -------------------
# RM-20 : flux d'activité visible par l'équipe (immuable).
# US-28 : notifications par membre (lues / non lues), isolées par business.


class ActivitiesListView(APIView):
    """Flux d'activité de l'équipe (US-27, RM-20). Journaux immuables."""

    permission_classes = [HasBusinessPermission.require(Perm.ACTIVITY_VIEW)]
    serializer_class = ActivityLogSerializer

    def get(self, request, business_id):
        qs = request.business.activities.select_related("acteur", "item")
        action = request.query_params.get("action")
        if action:
            qs = qs.filter(action=action)
        item_id = request.query_params.get("item_id")
        if item_id:
            qs = qs.filter(item_id=item_id)
        user_id = request.query_params.get("user_id")
        if user_id:
            qs = qs.filter(acteur_id=user_id)
        return paginated(request, qs, ActivityLogSerializer)


class NotificationsListView(APIView):
    """Notifications de l'utilisateur connecté (US-28) — propres à chacun."""

    permission_classes = [HasBusinessPermission.require(Perm.BUSINESS_VIEW)]
    serializer_class = NotificationSerializer

    def get(self, request, business_id):
        qs = request.business.notifications.filter(user=request.user)
        lu = request.query_params.get("lu")
        if lu in ("true", "false"):
            qs = qs.filter(lu=lu == "true")
        code = request.query_params.get("code")
        if code:
            qs = qs.filter(code=code)
        return paginated(request, qs, NotificationSerializer)


class NotificationDetailView(APIView):
    """Marque une notification de l'utilisateur comme lue / non lue (S 7-08)."""

    permission_classes = [HasBusinessPermission.require(Perm.BUSINESS_VIEW)]
    serializer_class = NotificationSerializer

    def patch(self, request, business_id, notification_id):
        notification = request.business.notifications.filter(
            id=notification_id, user=request.user
        ).first()
        if notification is None:
            return Response(
                {"detail": "Notification introuvable."}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = NotificationSerializer(
            notification, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        notification = serializer.save()
        return Response(NotificationSerializer(notification).data)


class NotificationsMarkAllReadView(APIView):
    """Marque toutes les notifications de l'utilisateur comme lues."""

    permission_classes = [HasBusinessPermission.require(Perm.BUSINESS_VIEW)]
    serializer_class = NotificationSerializer

    def post(self, request, business_id):
        updated = request.business.notifications.filter(
            user=request.user, lu=False
        ).update(lu=True)
        return Response({"marquees_lues": updated})


class DashboardView(APIView):
    """Synthèse du business pour le tableau de bord (S 7-04, RM-20)."""

    permission_classes = [HasBusinessPermission.require(Perm.STOCK_VIEW)]
    serializer_class = serializers.Serializer

    def get(self, request, business_id):
        business = request.business
        items = list(business.items.select_related("category"))
        etats = etats_entretien(items)
        etat_codes = [e["code"] for e in etats.values()]
        flags = a_verifier_bulk(items)

        def code_count(codes, wanted):
            return sum(1 for c in codes if c == wanted)

        inventaire_actif = (
            business.inventories.filter(statut=Inventory.Statut.EN_COURS)
            .order_by("-created_at", "-id")
            .first()
        )

        aggregates = get_aggregates(business.id)
        adjustments = get_adjustments(business.id)

        # Un seul GROUP BY plutôt qu'un COUNT par statut de réservation.
        reservations_par_statut = {
            row["statut"]: row["total"]
            # order_by() vide l'ordre par défaut du modèle : sans cela il
            # entrerait dans le GROUP BY et produirait une ligne par réservation.
            for row in business.reservations.order_by()
            .values("statut")
            .annotate(total=Count("id"))
        }
        totals = {"total": 0, "disponibles": 0, "en_location": 0,
                  "endommages": 0, "perdus": 0}
        for item in items:
            state = snapshot(item, aggregates, adjustments)
            totals["total"] += state["total"]
            totals["disponibles"] += state["disponibles"]
            totals["en_location"] += state["sorties"]
            totals["endommages"] += state["endommages"]
            totals["perdus"] += state["perdus"]

        active_resas = list(
            business.reservations.exclude(statut__in=[
                Reservation.Statut.TERMINEE, Reservation.Statut.ANNULEE,
            ]).order_by("item_id", "date_debut")
        )
        conflits = 0
        by_item = {}
        for resa in active_resas:
            by_item.setdefault(resa.item_id, []).append(resa)
        for group in by_item.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    if (group[i].date_debut <= group[j].date_fin
                            and group[j].date_debut <= group[i].date_fin):
                        conflits += 1

        return Response(
            {
                "articles": {
                    "total": len(items),
                    "en_entretien": code_count(etat_codes, "EN_ENTRETIEN"),
                    "entretien_partiel": code_count(etat_codes, "PARTIEL"),
                    "a_controler": code_count(etat_codes, "A_CONTROLER"),
                    "a_entretenir": code_count(etat_codes, "A_ENTRETENIR"),
                    "a_verifier": sum(1 for f in flags.values() if f),
                },
                "stock": totals,
                "conflits_reservation": conflits,
                "taches_en_cours": business.maintenance_tasks.filter(
                    statut=MaintenanceTask.Statut.EN_COURS
                ).count(),
                "reservations": {
                    "en_attente": reservations_par_statut.get("EN_ATTENTE", 0),
                    "validees": reservations_par_statut.get("VALIDEE", 0),
                    "en_cours": reservations_par_statut.get("EN_COURS", 0),
                },
                "inventaire_actif": (
                    {
                        **InventorySerializer(inventaire_actif).data,
                        "counts": InventoryCountSerializer(
                            inventaire_actif.counts.select_related("item"), many=True
                        ).data,
                    }
                    if inventaire_actif
                    else None
                ),
                "alertes_recents": AlertSerializer(
                    business.alerts.select_related("item", "acteur")[:5], many=True
                ).data,
                "decisions_recents": DecisionLogSerializer(
                    business.decisions.select_related("item", "acteur")[:5], many=True
                ).data,
                "mouvements_recents": StockMovementSerializer(
                    business.stock_movements.select_related("acteur", "item")[:5],
                    many=True,
                ).data,
                "activite_recents": ActivityLogSerializer(
                    business.activities.select_related("acteur", "item")[:10],
                    many=True,
                ).data,
            }
        )


# --- Sprint 8 : réservations (US-29, US-30, US-31) -------------------------


class ReservationListCreateView(WriteThrottleMixin, APIView):
    """Liste et création de réservations (US-29, RM-01)."""

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_VIEW)]
    serializer_class = ReservationSerializer

    def get(self, request, business_id):
        qs = request.business.reservations.select_related("item", "reserve_par")
        statut = request.query_params.get("statut")
        if statut:
            qs = qs.filter(statut=statut)
        item_id = request.query_params.get("item_id")
        if item_id:
            qs = qs.filter(item_id=item_id)
        return paginated(request, qs, ReservationSerializer)

    def post(self, request, business_id):
        serializer = ReservationCreateSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        reservation = create_reservation(
            business=request.business,
            item=serializer.validated_data["item_id"],
            reserve_par=request.user,
            date_debut=serializer.validated_data["date_debut"],
            date_fin=serializer.validated_data["date_fin"],
            quantite=serializer.validated_data["quantite"],
            motif=serializer.validated_data.get("motif", ""),
        )
        return Response(
            ReservationSerializer(reservation).data, status=status.HTTP_201_CREATED
        )


class ReservationBulkCreateView(WriteThrottleMixin, APIView):
    """Réservation de plusieurs articles en un seul appel atomique (US-29).

    Toutes les réservations demandées sont créées dans une unique transaction
    côté moteur (`create_reservations_bulk`) : si un seul article échoue
    (chevauchement, exposition pleine, article invalide...), la requête
    entière est rejetée et AUCUNE réservation n'est créée — corrige le
    comportement précédent où le client appelait la création une fois par
    article, pouvant laisser une réservation partiellement créée.
    """

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_VIEW)]
    serializer_class = ReservationBulkCreateSerializer

    def post(self, request, business_id):
        serializer = ReservationBulkCreateSerializer(
            data=request.data, context={"business": request.business}
        )
        serializer.is_valid(raise_exception=True)
        reservations = create_reservations_bulk(
            business=request.business,
            items_quantites=serializer.validated_data["items"],
            reserve_par=request.user,
            date_debut=serializer.validated_data["date_debut"],
            date_fin=serializer.validated_data["date_fin"],
            motif=serializer.validated_data.get("motif", ""),
        )
        return Response(
            ReservationSerializer(reservations, many=True).data,
            status=status.HTTP_201_CREATED,
        )


class ReservationDetailView(APIView):
    """Détail d'une réservation du business (US-29, RM-01)."""

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_VIEW)]
    serializer_class = ReservationSerializer

    def get(self, request, business_id, reservation_id):
        reservation = request.business.reservations.select_related(
            "item", "reserve_par"
        ).filter(id=reservation_id).first()
        if reservation is None:
            return Response(
                {"detail": "Réservation introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(ReservationSerializer(reservation).data)


class _ReservationActionView(WriteThrottleMixin, APIView):
    """Base des actions de gestion (US-30, US-31) : permission manage."""

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_MANAGE)]
    serializer_class = ReservationSerializer
    execute_action = None

    def post(self, request, business_id, reservation_id):
        reservation = request.business.reservations.select_related(
            "item", "reserve_par"
        ).filter(id=reservation_id).first()
        if reservation is None:
            return Response(
                {"detail": "Réservation introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(
            ReservationSerializer(self.execute_action(request, reservation)).data
        )


class ReservationValidateView(_ReservationActionView):
    execute_action = staticmethod(
        lambda request, reservation: valider_reservation(
            reservation=reservation, acteur=request.user
        )
    )


class ReservationCancelView(_ReservationActionView):
    execute_action = staticmethod(
        lambda request, reservation: annuler_reservation(
            reservation=reservation,
            acteur=request.user,
            motif=request.data.get("motif", ""),
        )
    )


class ReservationStartView(_ReservationActionView):
    execute_action = staticmethod(
        lambda request, reservation: demarrer_reservation(
            reservation=reservation, acteur=request.user
        )
    )


class ReservationFinishView(WriteThrottleMixin, APIView):
    """Termine la réservation avec contrôle de retour (Sprint 8 bis).

    Le corps peut fournir le décompte : quantite_retournee, quantite_abimee,
    quantite_perdue, observations. Sans décompte, tout est rendu en bon état.
    """

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_MANAGE)]
    serializer_class = ReservationFinishSerializer

    def post(self, request, business_id, reservation_id):
        reservation = request.business.reservations.select_related(
            "item", "reserve_par"
        ).filter(id=reservation_id).first()
        if reservation is None:
            return Response(
                {"detail": "Réservation introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        payload = ReservationFinishSerializer(data=request.data)
        payload.is_valid(raise_exception=True)
        returned = terminer_reservation(
            reservation=reservation,
            acteur=request.user,
            quantite_retournee=payload.validated_data.get("quantite_retournee"),
            quantite_abimee=payload.validated_data.get("quantite_abimee"),
            quantite_perdue=payload.validated_data.get("quantite_perdue"),
            observations=payload.validated_data.get("observations", ""),
        )
        return Response(ReservationSerializer(returned).data)


# --- Public Business (V1) ------------------------------------------------------


class PublicBusinessDetailView(APIView):
    """Informations publiques d'un business par slug (sans authentification).

    GET /api/public/b/<slug>/
    """

    permission_classes = [AllowAny]

    def get(self, request, slug):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        from .serializers import PublicBusinessSerializer
        return Response(PublicBusinessSerializer(business).data)


# --- Public Catalog (V1) ------------------------------------------------------


class PublicCatalogView(APIView):
    """Catalogue public d'un business (lecture seule, sans authentification).

    GET /api/public/b/<slug>/items/
    Retourne les articles publiés (is_published=True, statut=ACTIF).

    Query params optionnels (Option B - dispo temps réel) :
    - date_debut=YYYY-MM-DD
    - date_fin=YYYY-MM-DD
    Si fournis, ajoute pour chaque article :
      - total_stock: stock total possédé
      - disponible: unités disponibles sur la période
      - reserves_pendant_periode: unités déjà réservées sur la période
      - en_entretien: unités en maintenance
      - peut_reserver: booléen
    """

    permission_classes = [AllowAny]
    serializer_class = PublicItemSerializer

    def get(self, request, slug):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        date_debut = request.query_params.get("date_debut")
        date_fin = request.query_params.get("date_fin")
        has_dates = date_debut and date_fin

        items = business.items.filter(
            is_published=True, statut=Item.Statut.ACTIF
        ).select_related("category").prefetch_related("photos")

        # Pagination intelligente côté serveur si page/page_size demandés
        page_param = request.query_params.get("page")
        page_size_param = request.query_params.get("page_size")

        if not has_dates:
            if page_param is not None or page_size_param is not None:
                paginator = StandardPagination()
                if page_size_param:
                    try:
                        paginator.page_size = min(int(page_size_param), paginator.max_page_size)
                    except ValueError:
                        pass
                page_qs = paginator.paginate_queryset(items, request)
                serializer = PublicItemSerializer(
                    page_qs, many=True, context={"request": request}
                )
                return paginator.get_paginated_response(serializer.data)
            serializer = PublicItemSerializer(
                items, many=True, context={"request": request}
            )
            return Response(serializer.data)

        # Option B : calculer dispo pour chaque article sur la période
        from django.db.models import Q, Sum
        from datetime import date
        from .stock import snapshot
        from .maintenance import etat_entretien

        try:
            date_debut = date.fromisoformat(date_debut)
            date_fin = date.fromisoformat(date_fin)
        except ValueError:
            return Response(
                {"detail": "Format de date invalide (YYYY-MM-DD)."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if date_fin < date_debut:
            return Response(
                {"detail": "date_fin doit être >= date_debut."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        results = []
        for item in items:
            stock = snapshot(item)
            total = stock["total"]
            disponibles = stock["disponibles"]

            # Réservations actives chevauchantes
            reserves_qs = item.reservations.exclude(
                statut__in=[Reservation.Statut.TERMINEE, Reservation.Statut.ANNULEE]
            ).filter(
                Q(date_debut__lte=date_fin) & Q(date_fin__gte=date_debut)
            )
            reserves_pendant = reserves_qs.aggregate(total=Sum("quantite"))["total"] or 0

            # Booking Requests en attente/acceptees chevauchantes (V2)
            from .models import BookingRequest
            br_qs = item.booking_requests.filter(
                statut__in=[BookingRequest.Statut.EN_ATTENTE, BookingRequest.Statut.ACCEPTEE]
            ).filter(
                Q(date_debut__lte=date_fin) & Q(date_fin__gte=date_debut)
            )
            br_pendant = br_qs.aggregate(total=Sum("quantite"))["total"] or 0

            # Articles en entretien (pas dispo)
            etat = etat_entretien(item)
            en_entretien = 1 if etat["code"] in ("EN_ENTRETIEN", "PARTIEL") else 0

            dispo_periode = max(total - reserves_pendant - br_pendant - en_entretien, 0)

            base = PublicItemSerializer(item, context={"request": request}).data
            base.update({
                "total_stock": total,
                "disponible": dispo_periode,
                "reserves_pendant_periode": reserves_pendant,
                "booking_requests_pendantes": br_pendant,
                "en_entretien": en_entretien,
                "peut_reserver": dispo_periode > 0,
            })
            results.append(base)

        # Pagination intelligente pour le mode disponibilité aussi
        if page_param is not None or page_size_param is not None:
            paginator = StandardPagination()
            if page_size_param:
                try:
                    paginator.page_size = min(int(page_size_param), paginator.max_page_size)
                except ValueError:
                    pass
            page_results = paginator.paginate_queryset(results, request)
            return paginator.get_paginated_response(page_results)
        return Response(results)


class PublicCategoryListView(APIView):
    """Catégories publiques d'un business (lecture seule, sans auth).

    GET /api/public/b/<slug>/categories/
    Retourne les catégories avec leur image dédiée (jamais d'image d'article).
    """

    permission_classes = [AllowAny]
    serializer_class = PublicCategorySerializer

    def get(self, request, slug):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        categories = business.categories.all().order_by("nom")
        serializer = PublicCategorySerializer(
            categories, many=True, context={"request": request}
        )
        return Response(serializer.data)


class PublicAvailabilityView(APIView):
    """Disponibilité d'un article précis sur une période (Option B).

    GET /api/public/b/<slug>/items/<uuid:item_id>/availability/?date_debut=...&date_fin=...
    """

    permission_classes = [AllowAny]

    def get(self, request, slug, item_id):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        item = business.items.filter(
            id=item_id, is_published=True, statut=Item.Statut.ACTIF
        ).first()
        if item is None:
            return Response(
                {"detail": "Article introuvable ou non publié."},
                status=status.HTTP_404_NOT_FOUND,
            )

        date_debut = request.query_params.get("date_debut")
        date_fin = request.query_params.get("date_fin")
        if not date_debut or not date_fin:
            return Response(
                {"detail": "date_debut et date_fin sont requis."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.db.models import Q, Sum
        from datetime import date
        from .stock import snapshot
        from .maintenance import etat_entretien

        try:
            date_debut = date.fromisoformat(date_debut)
            date_fin = date.fromisoformat(date_fin)
        except ValueError:
            return Response(
                {"detail": "Format de date invalide (YYYY-MM-DD)."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if date_fin < date_debut:
            return Response(
                {"detail": "date_fin doit être >= date_debut."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        stock = snapshot(item)
        total = stock["total"]
        disponibles = stock["disponibles"]

        reserves_qs = item.reservations.exclude(
            statut__in=[Reservation.Statut.TERMINEE, Reservation.Statut.ANNULEE]
        ).filter(
            Q(date_debut__lte=date_fin) & Q(date_fin__gte=date_debut)
        )
        reserves_pendant = reserves_qs.aggregate(total=Sum("quantite"))["total"] or 0

        # Booking Requests en attente/acceptees chevauchantes (V2)
        from .models import BookingRequest
        br_qs = item.booking_requests.filter(
            statut__in=[BookingRequest.Statut.EN_ATTENTE, BookingRequest.Statut.ACCEPTEE]
        ).filter(
            Q(date_debut__lte=date_fin) & Q(date_fin__gte=date_debut)
        )
        br_pendant = br_qs.aggregate(total=Sum("quantite"))["total"] or 0

        etat = etat_entretien(item)
        en_entretien = 1 if etat["code"] in ("EN_ENTRETIEN", "PARTIEL") else 0

        dispo_periode = max(total - reserves_pendant - br_pendant - en_entretien, 0)

        return Response({
            "item_id": str(item.id),
            "item_nom": item.nom,
            "date_debut": date_debut.isoformat(),
            "date_fin": date_fin.isoformat(),
            "total_stock": total,
            "disponible": dispo_periode,
            "reserves_pendant_periode": reserves_pendant,
            "booking_requests_pendantes": br_pendant,
            "en_entretien": en_entretien,
            "en_stock_physique": disponibles,
            "peut_reserver": dispo_periode > 0,
            "detail_reservations": [
                {
                    "id": str(r.id),
                    "date_debut": r.date_debut.isoformat(),
                    "date_fin": r.date_fin.isoformat(),
                    "quantite": r.quantite,
                    "statut": r.statut,
                }
                for r in reserves_qs[:10]
            ],
            "detail_booking_requests": [
                {
                    "id": str(r.id),
                    "date_debut": r.date_debut.isoformat(),
                    "date_fin": r.date_fin.isoformat(),
                    "quantite": r.quantite,
                    "statut": r.statut,
                    "client_nom": r.client_nom,
                }
                for r in br_qs[:10]
            ],
        })


# --- V2 : Booking Request (Public) --------------------------------------------


class PublicBookingRequestCreateView(APIView):
    """Création d'une demande de location par un client externe.

    POST /api/public/b/<slug>/booking-requests/
    """

    permission_classes = [AllowAny]
    serializer_class = PublicBookingRequestCreateSerializer

    def post(self, request, slug):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Idempotency: priorité header, puis body
        idempotency_key = request.headers.get("Idempotency-Key") or request.data.get("idempotency_key") or ""
        visitor_id = request.headers.get("X-Visitor-Id") or request.data.get("visitor_id") or ""
        # Normaliser : si idempotency_key fourni, vérifier doublon
        if idempotency_key:
            from .models import BookingRequest
            existing = BookingRequest.objects.filter(
                business=business,
                idempotency_key=idempotency_key,
            ).first()
            if existing:
                return Response(
                    {
                        "id": str(existing.id),
                        "access_token": existing.access_token,
                        "expires_at": existing.expires_at.isoformat(),
                        "detail_url": f"/api/public/b/{slug}/booking-requests/{existing.access_token}/",
                        "message": "Demande déjà enregistrée (idempotence).",
                    },
                    status=status.HTTP_200_OK,
                )

        serializer = PublicBookingRequestCreateSerializer(
            data=request.data, context={"business": business}
        )
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        # Priorité header pour visitor/idempotency si non fourni en body
        if not data.get("visitor_id") and visitor_id:
            data["visitor_id"] = visitor_id
        if not data.get("idempotency_key") and idempotency_key:
            data["idempotency_key"] = idempotency_key

        from .models import BookingRequest
        booking_request = BookingRequest.objects.create(
            business=business,
            item=data["item_id"],
            client_nom=data["client_nom"],
            client_telephone=data.get("client_telephone", ""),
            client_email=data["client_email"],
            date_debut=data["date_debut"],
            date_fin=data["date_fin"],
            quantite=data["quantite"],
            message=data.get("message", ""),
            lieu_nom=data.get("lieu_nom", ""),
            lieu_adresse=data.get("lieu_adresse", ""),
            contact_nom=data.get("contact_nom", ""),
            contact_telephone=data.get("contact_telephone", ""),
            notes_livraison=data.get("notes_livraison", ""),
            visitor_id=data.get("visitor_id", "") or visitor_id,
            idempotency_key=data.get("idempotency_key", "") or idempotency_key,
        )

        # Notifier l'équipe
        from .activite import notify_members
        from .rbac import Perm
        notify_members(
            business=business,
            code="BOOKING_REQUEST.NEW",
            message=f"Nouvelle demande : {booking_request.client_nom} - "
                    f"{booking_request.item.nom} ({booking_request.date_debut} -> {booking_request.date_fin})",
            item=booking_request.item,
            permission_codename=Perm.RESERVATION_MANAGE,
        )

        # Retourner le token pour suivi client
        return Response(
            {
                "id": str(booking_request.id),
                "access_token": booking_request.access_token,
                "expires_at": booking_request.expires_at.isoformat(),
                "detail_url": f"/api/public/b/{slug}/booking-requests/{booking_request.access_token}/",
                "message": "Demande envoyée. L'équipe vous répondra sous peu.",
            },
            status=status.HTTP_201_CREATED,
        )


class PublicActiveRequestView(APIView):
    """Vérifie si le visiteur a une demande active.

    GET /api/public/b/<slug>/active-request?visitor_id=xxx
    Source de vérité backend, localStorage n'est qu'un cache.
    """

    permission_classes = [AllowAny]

    def get(self, request, slug):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response({"detail": "Business introuvable."}, status=status.HTTP_404_NOT_FOUND)
        visitor_id = request.query_params.get("visitor_id") or request.headers.get("X-Visitor-Id") or ""
        if not visitor_id:
            return Response({"hasActiveRequest": False, "request": None})
        active_statuts = [BookingRequest.Statut.EN_ATTENTE, BookingRequest.Statut.ACCEPTEE, BookingRequest.Statut.DRAFT]
        req = BookingRequest.objects.filter(
            business=business, visitor_id=visitor_id, statut__in=active_statuts
        ).order_by("-created_at").first()
        # Expiration auto
        if req and req.is_expired and req.statut == BookingRequest.Statut.EN_ATTENTE:
            req.statut = BookingRequest.Statut.EXPIREE
            req.save(update_fields=["statut"])
        if not req:
            return Response({"hasActiveRequest": False, "request": None})
        data = PublicBookingRequestDetailSerializer(req, context={"request": request}).data
        # Ajouter trackingCode = access_token pour le frontend
        data["trackingCode"] = req.access_token
        data["requestId"] = str(req.id)
        return Response({"hasActiveRequest": True, "request": data})


class PublicRecoverView(APIView):
    """Retrouver une demande via email/téléphone/visitorId (sans OTP strict pour MVP).

    POST /api/public/b/<slug>/recover {email, phone, visitor_id}
    Retourne les demandes récentes masquées, nécessite vérification côté prod (OTP).
    """

    permission_classes = [AllowAny]

    def post(self, request, slug):
        from .serializers import RecoverBookingRequestSerializer
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response({"detail": "Business introuvable."}, status=status.HTTP_404_NOT_FOUND)
        ser = RecoverBookingRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        email = (ser.validated_data.get("email") or "").strip().lower()
        phone = (ser.validated_data.get("phone") or "").strip()
        visitor_id = (ser.validated_data.get("visitor_id") or "").strip()
        qs = BookingRequest.objects.filter(business=business).order_by("-created_at")
        if visitor_id:
            qs = qs.filter(visitor_id=visitor_id)
        elif email:
            qs = qs.filter(client_email__iexact=email)
        elif phone:
            # Normaliser téléphone : garder chiffres
            import re
            norm = re.sub(r"\D", "", phone)
            # Cherche exact ou contient les 8 derniers chiffres
            qs = qs.filter(client_telephone__icontains=norm[-8:] if len(norm) >= 8 else norm)
        qs = qs[:10]
        # Ne jamais exposer toutes les données sans vérification forte ; on masque
        results = []
        for r in qs:
            results.append({
                "id": str(r.id),
                "trackingCode": r.access_token,
                "statut": r.statut,
                "statut_display": r.get_statut_display(),
                "item_nom": r.item.nom,
                "date_debut": r.date_debut.isoformat(),
                "date_fin": r.date_fin.isoformat(),
                "created_at": r.created_at.isoformat(),
                "expires_at": r.expires_at.isoformat(),
            })
        return Response({"results": results})


class PublicCustomerRequestsView(APIView):
    """Liste des demandes d'un visiteur (pour page Mes demandes).

    GET /api/public/b/<slug>/requests?visitor_id=xxx
    """

    permission_classes = [AllowAny]

    def get(self, request, slug):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response({"detail": "Business introuvable."}, status=status.HTTP_404_NOT_FOUND)
        visitor_id = request.query_params.get("visitor_id") or request.headers.get("X-Visitor-Id") or ""
        if not visitor_id:
            return Response({"results": []})
        qs = BookingRequest.objects.filter(business=business, visitor_id=visitor_id).order_by("-created_at")[:20]
        data = []
        for r in qs:
            # Expiration
            if r.is_expired and r.statut == BookingRequest.Statut.EN_ATTENTE:
                r.statut = BookingRequest.Statut.EXPIREE
                r.save(update_fields=["statut"])
            data.append({
                "id": str(r.id),
                "trackingCode": r.access_token,
                "statut": r.statut,
                "statut_display": r.get_statut_display(),
                "item_nom": r.item.nom,
                "date_debut": r.date_debut.isoformat(),
                "date_fin": r.date_fin.isoformat(),
                "created_at": r.created_at.isoformat(),
                "expires_at": r.expires_at.isoformat(),
            })
        return Response({"results": data})


class PublicBookingRequestDetailView(APIView):
    """Suivi d'une demande par le client (via token magique).

    GET /api/public/b/<slug>/booking-requests/<token>/
    """

    permission_classes = [AllowAny]
    serializer_class = PublicBookingRequestDetailSerializer

    def get(self, request, slug, token):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        booking_request = BookingRequest.objects.filter(
            business=business, access_token=token
        ).select_related("item").first()

        if booking_request is None:
            return Response(
                {"detail": "Demande introuvable ou lien expiré."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if booking_request.is_expired and booking_request.statut == BookingRequest.Statut.EN_ATTENTE:
            booking_request.statut = BookingRequest.Statut.EXPIREE
            booking_request.save(update_fields=["statut", "updated_at"])

        serializer = PublicBookingRequestDetailSerializer(
            booking_request, context={"request": request}
        )
        return Response(serializer.data)


class PublicBookingRequestByTokenView(APIView):
    """Suivi d'une demande par le client, sans connaître le slug.

    GET /api/public/booking-requests/<token>/
    Retourne la demande + le slug du business pour rediriger.
    """

    permission_classes = [AllowAny]

    def get(self, request, token):
        booking_request = BookingRequest.objects.filter(
            access_token=token
        ).select_related("item", "item__business").first()

        if booking_request is None:
            return Response(
                {"detail": "Demande introuvable ou lien expiré."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if booking_request.is_expired and booking_request.statut == BookingRequest.Statut.EN_ATTENTE:
            booking_request.statut = BookingRequest.Statut.EXPIREE
            booking_request.save(update_fields=["statut", "updated_at"])

        serializer = PublicBookingRequestDetailSerializer(
            booking_request, context={"request": request}
        )
        data = serializer.data
        data["business_slug"] = booking_request.business.slug
        return Response(data)


class PublicBookingRequestCancelView(APIView):
    """Annulation d'une demande par le client.

    POST /api/public/b/<slug>/booking-requests/<token>/cancel/
    """

    permission_classes = [AllowAny]

    def post(self, request, slug, token):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        booking_request = BookingRequest.objects.filter(
            business=business, access_token=token
        ).first()

        if booking_request is None:
            return Response(
                {"detail": "Demande introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not booking_request.can_client_cancel:
            return Response(
                {"detail": f"Impossible d'annuler une demande {booking_request.statut}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        booking_request.statut = BookingRequest.Statut.ANNULEE_CLIENT
        booking_request.save(update_fields=["statut", "updated_at"])

        # Pas d'ActivityLog pour action client (pas d'utilisateur authentifié)
        # L'historique est dans la demande elle-même (statut, updated_at)

        return Response({"message": "Demande annulée."})


# --- V3 : Client Counter-Proposal Response ------------------------------------


class PublicBookingRequestAcceptCounterView(APIView):
    """Client accepte la contre-proposition de l'équipe.

    POST /api/public/b/<slug>/booking-requests/<token>/accept-counter/
    Crée la réservation avec les termes de la contre-proposition.
    """

    permission_classes = [AllowAny]

    def post(self, request, slug, token):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        booking_request = BookingRequest.objects.filter(
            business=business, access_token=token
        ).select_related("item").first()

        if booking_request is None:
            return Response(
                {"detail": "Demande introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if booking_request.statut != BookingRequest.Statut.EN_ATTENTE:
            return Response(
                {"detail": f"Impossible de répondre à une demande {booking_request.statut}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not booking_request.contre_proposition:
            return Response(
                {"detail": "Aucune contre-proposition en attente."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Vérifier dispo avec les nouveaux termes
        contre = booking_request.contre_proposition
        date_debut = contre.get("date_debut", booking_request.date_debut.isoformat())
        date_fin = contre.get("date_fin", booking_request.date_fin.isoformat())
        quantite = contre.get("quantite", booking_request.quantite)

        from datetime import date
        from django.db.models import Q, Sum
        from .stock import snapshot
        from .models import BookingRequest as BR
        from .reservation import _chevauchant, _reservations_actives

        try:
            date_debut = date.fromisoformat(date_debut)
            date_fin = date.fromisoformat(date_fin)
        except ValueError:
            return Response(
                {"detail": "Dates invalides dans la contre-proposition."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        item = booking_request.item
        stock = snapshot(item)
        total = stock["total"]

        # Réservations + booking requests chevauchantes (exclure la nôtre)
        reserves_qs = _chevauchant(_reservations_actives(item), date_debut, date_fin)
        reserves = reserves_qs.aggregate(total=Sum("quantite"))["total"] or 0

        br_qs = _chevauchant(
            BR.objects.filter(
                business=business, item=item,
                statut__in=[BR.Statut.EN_ATTENTE, BR.Statut.ACCEPTEE]
            ).exclude(id=booking_request.id), date_debut, date_fin
        )
        br_pending = br_qs.aggregate(total=Sum("quantite"))["total"] or 0

        dispo = max(total - reserves - br_pending, 0)
        if quantite > dispo:
            return Response(
                {"detail": f"Plus assez de dispo pour cette contre-proposition ({dispo} dispo)."},
                status=status.HTTP_409_CONFLICT,
            )

        # Créer la réservation avec les termes de la contre-proposition
        from .reservation import create_reservation
        from .activite import log_activity, Act, notify_members
        from .rbac import Perm
        from django.utils import timezone

        reservation = create_reservation(
            business=business,
            item=item,
            reserve_par=booking_request.traite_par or business.created_by,  # fallback
            date_debut=date_debut,
            date_fin=date_fin,
            quantite=quantite,
            motif=f"Contre-proposition acceptée par client: {booking_request.client_nom} - {contre.get('message', '')}",
            lieu_nom=booking_request.lieu_nom,
            lieu_adresse=booking_request.lieu_adresse,
            contact_nom=booking_request.contact_nom,
            contact_telephone=booking_request.contact_telephone,
            notes_livraison=booking_request.notes_livraison,
        )

        booking_request.statut = BookingRequest.Statut.CONVERTIE
        booking_request.reservation_creee = reservation
        booking_request.traite_le = timezone.now()
        booking_request.save(update_fields=[
            "statut", "reservation_creee", "traite_le", "updated_at"
        ])

        log_activity(
            business=business,
            acteur=booking_request.traite_par or business.created_by,
            action=Act.BOOKING_REQUEST_ACCEPTED,
            item=item,
            cible=f"BookingRequest {booking_request.id} -> Reservation {reservation.id}",
            detail={"client_nom": booking_request.client_nom, "par_client": True},
        )

        notify_members(
            business=business,
            code="BOOKING_REQUEST.COUNTER_ACCEPTED",
            message=f"Client a accepté la contre-proposition : {item.nom} -> Réservation créée",
            item=item,
            permission_codename=Perm.RESERVATION_MANAGE,
        )

        return Response({
            "message": "Contre-proposition acceptée, réservation créée.",
            "reservation_id": str(reservation.id),
            "reservation": {
                "date_debut": date_debut.isoformat(),
                "date_fin": date_fin.isoformat(),
                "quantite": quantite,
            },
        })


class PublicBookingRequestRejectCounterView(APIView):
    """Client refuse la contre-proposition de l'équipe.

    POST /api/public/b/<slug>/booking-requests/<token>/reject-counter/
    """

    permission_classes = [AllowAny]

    def post(self, request, slug, token):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        booking_request = BookingRequest.objects.filter(
            business=business, access_token=token
        ).first()

        if booking_request is None:
            return Response(
                {"detail": "Demande introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if booking_request.statut != BookingRequest.Statut.EN_ATTENTE:
            return Response(
                {"detail": f"Impossible de répondre à une demande {booking_request.statut}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not booking_request.contre_proposition:
            return Response(
                {"detail": "Aucune contre-proposition en attente."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from .activite import log_activity, Act
        from django.utils import timezone

        motif = request.data.get("motif_refus", "Client a refusé la contre-proposition")
        booking_request.statut = BookingRequest.Statut.REFUSEE
        booking_request.motif_refus = motif
        booking_request.traite_le = timezone.now()
        booking_request.save(update_fields=[
            "statut", "motif_refus", "traite_le", "updated_at"
        ])

        # Pas d'ActivityLog pour action client (pas d'utilisateur authentifié)
        # L'historique est dans la demande elle-même (statut, motif_refus, updated_at)

        return Response({"message": "Contre-proposition refusée."})


# --- V2 : Booking Request (Team) ----------------------------------------------


class BookingRequestListView(APIView):
    """Liste des demandes pour l'équipe (filtres statut, dates).

    GET /api/businesses/<uuid:business_id>/booking-requests/
    """

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_VIEW)]
    serializer_class = BookingRequestTeamSerializer

    def get(self, request, business_id):
        qs = request.business.booking_requests.select_related("item", "traite_par").order_by("-created_at")

        statut = request.query_params.get("statut")
        if statut:
            qs = qs.filter(statut=statut)

        date_debut = request.query_params.get("date_debut")
        if date_debut:
            qs = qs.filter(date_debut__gte=date_debut)

        date_fin = request.query_params.get("date_fin")
        if date_fin:
            qs = qs.filter(date_fin__lte=date_fin)

        return paginated(request, qs, BookingRequestTeamSerializer)


class BookingRequestDetailView(APIView):
    """Détail d'une demande pour l'équipe.

    GET /api/businesses/<uuid:business_id>/booking-requests/<uuid:request_id>/
    """

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_VIEW)]
    serializer_class = BookingRequestTeamSerializer

    def get(self, request, business_id, request_id):
        booking_request = request.business.booking_requests.filter(id=request_id).first()
        if booking_request is None:
            return Response(
                {"detail": "Demande introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = BookingRequestTeamSerializer(booking_request)
        return Response(serializer.data)


class BookingRequestActionView(WriteThrottleMixin, APIView):
    """Actions équipe : accepter, refuser, contre-proposer.

    POST /api/businesses/<uuid:business_id>/booking-requests/<uuid:request_id>/action/
    """

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_MANAGE)]
    serializer_class = BookingRequestActionSerializer

    def post(self, request, business_id, request_id):
        booking_request = request.business.booking_requests.filter(id=request_id).first()
        if booking_request is None:
            return Response(
                {"detail": "Demande introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not booking_request.can_team_process:
            return Response(
                {"detail": f"Impossible de traiter une demande {booking_request.statut}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = BookingRequestActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        action = serializer.validated_data["action"]

        from .reservation import create_reservation
        from .activite import log_activity, Act, notify_members
        from .rbac import Perm
        from django.utils import timezone

        if action == "accepter":
            with transaction.atomic():
                reservation = create_reservation(
                    business=booking_request.business,
                    item=booking_request.item,
                    reserve_par=request.user,
                    date_debut=booking_request.date_debut,
                    date_fin=booking_request.date_fin,
                    quantite=booking_request.quantite,
                    motif=f"Demande client: {booking_request.client_nom} - {booking_request.message}",
                    lieu_nom=booking_request.lieu_nom,
                    lieu_adresse=booking_request.lieu_adresse,
                    contact_nom=booking_request.contact_nom,
                    contact_telephone=booking_request.contact_telephone,
                    notes_livraison=booking_request.notes_livraison,
                )
                booking_request.statut = BookingRequest.Statut.CONVERTIE
                booking_request.reservation_creee = reservation
                booking_request.traite_par = request.user
                booking_request.traite_le = timezone.now()
                booking_request.save(update_fields=[
                    "statut", "reservation_creee", "traite_par", "traite_le", "updated_at"
                ])

                log_activity(
                    business=booking_request.business,
                    acteur=request.user,
                    action=Act.BOOKING_REQUEST_ACCEPTED,
                    item=booking_request.item,
                    cible=f"BookingRequest {booking_request.id} -> Reservation {reservation.id}",
                    detail={"client_nom": booking_request.client_nom},
                )

                notify_members(
                    business=booking_request.business,
                    code="BOOKING_REQUEST.ACCEPTED",
                    message=f"Demande acceptée : {booking_request.item.nom} -> Réservation créée",
                    item=booking_request.item,
                    permission_codename=Perm.RESERVATION_MANAGE,
                    ignore_user=request.user,
                )

                # Envoyer email au client
                from .invitations import send_booking_request_accepted_email
                send_booking_request_accepted_email(booking_request, str(reservation.id))

                # Push notification FCM
                from .invitations import send_booking_request_status_push
                send_booking_request_status_push(booking_request, "ACCEPTEE")

                return Response({
                    "message": "Demande acceptée, réservation créée.",
                    "reservation_id": str(reservation.id),
                })

        elif action == "refuser":
            booking_request.statut = BookingRequest.Statut.REFUSEE
            booking_request.motif_refus = serializer.validated_data["motif_refus"]
            booking_request.traite_par = request.user
            booking_request.traite_le = timezone.now()
            booking_request.save(update_fields=[
                "statut", "motif_refus", "traite_par", "traite_le", "updated_at"
            ])

            log_activity(
                business=booking_request.business,
                acteur=request.user,
                action=Act.BOOKING_REQUEST_REFUSED,
                item=booking_request.item,
                cible=f"BookingRequest {booking_request.id}",
                detail={"client_nom": booking_request.client_nom, "motif": booking_request.motif_refus},
            )

            # Envoyer email au client
            from .invitations import send_booking_request_refused_email
            send_booking_request_refused_email(booking_request)

            # Push notification FCM
            from .invitations import send_booking_request_status_push
            send_booking_request_status_push(booking_request, "REFUSEE")

            return Response({"message": "Demande refusée."})

        elif action == "contre_proposer":
            # Mettre à jour la demande avec la contre-proposition
            contre = {}
            if "date_debut" in serializer.validated_data:
                contre["date_debut"] = serializer.validated_data["date_debut"].isoformat()
            if "date_fin" in serializer.validated_data:
                contre["date_fin"] = serializer.validated_data["date_fin"].isoformat()
            if "quantite" in serializer.validated_data:
                contre["quantite"] = serializer.validated_data["quantite"]
            if "prix" in serializer.validated_data:
                contre["prix"] = str(serializer.validated_data["prix"])
            if "message" in serializer.validated_data:
                contre["message"] = serializer.validated_data["message"]

            booking_request.contre_proposition = contre
            booking_request.traite_par = request.user
            booking_request.traite_le = timezone.now()
            booking_request.save(update_fields=[
                "contre_proposition", "traite_par", "traite_le", "updated_at"
            ])

            log_activity(
                business=booking_request.business,
                acteur=request.user,
                action=Act.BOOKING_REQUEST_CONTRE_PROPOSITION,
                item=booking_request.item,
                cible=f"BookingRequest {booking_request.id}",
                detail={"contre_proposition": contre},
            )

            # Envoyer email au client
            from .invitations import send_booking_request_counter_proposal_email
            send_booking_request_counter_proposal_email(booking_request)

            return Response({
                "message": "Contre-proposition envoyée au client.",
                "contre_proposition": contre,
            })

        return Response({"detail": "Action inconnue."}, status=status.HTTP_400_BAD_REQUEST)


# --- V4 : Facturation ---------------------------------------------------------


class InvoiceListCreateView(APIView):
    """Liste et création des factures du business.

    GET /api/businesses/<uuid:business_id>/invoices/
    POST /api/businesses/<uuid:business_id>/invoices/
    """

    serializer_class = InvoiceSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasBusinessPermission.require(Perm.RESERVATION_MANAGE)()]
        return [HasBusinessPermission.require(Perm.CATALOG_VIEW)()]

    def get(self, request, business_id):
        qs = request.business.invoices.select_related("reservation__item", "generee_par").order_by("-generee_le")

        statut = request.query_params.get("statut")
        if statut:
            qs = qs.filter(statut=statut)

        type_facture = request.query_params.get("type")
        if type_facture:
            qs = qs.filter(type=type_facture)

        return paginated(request, qs, InvoiceSerializer)

    def post(self, request, business_id):
        serializer = InvoiceCreateSerializer(data=request.data, context={"business": request.business})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        reservation = data["reservation_id"]
        type_facture = data["type"]
        tva_taux = data["tva_taux"]
        lignes_input = data.get("lignes")

        # Vérifier qu'aucune facture n'existe déjà
        if hasattr(reservation, "invoice"):
            return Response(
                {"detail": "Cette réservation a déjà une facture."},
                status=status.HTTP_409_CONFLICT,
            )

        # Construire les lignes automatiquement si non fournies
        if not lignes_input:
            lignes = [{
                "description": f"Location {reservation.item.nom} ({reservation.date_debut} au {reservation.date_fin})",
                "quantite": reservation.quantite,
                "prix_unitaire": str(reservation.item.prix),
                "total": str(reservation.item.prix * reservation.quantite),
            }]
            # Ajouter frais de livraison si notes_livraison
            if reservation.lieu_nom or reservation.lieu_adresse:
                lignes.append({
                    "description": f"Livraison / Reprise : {reservation.lieu_nom or ''} {reservation.lieu_adresse or ''}".strip(),
                    "quantite": 1,
                    "prix_unitaire": "0.00",
                    "total": "0.00",
                })
        else:
            lignes = lignes_input

        # Créer la facture — gère idempotence et race sur le numéro
        from decimal import Decimal
        from django.db import IntegrityError, transaction

        # Idempotence : si la réservation a déjà une facture (concurrent), renvoyer l'existante
        # Le check initial a pu être contourné par une course ; on revérifie dans la transaction
        try:
            with transaction.atomic():
                # Revérifie à l'intérieur de la transaction (verrou)
                reservation.refresh_from_db()
                if hasattr(reservation, "invoice") and reservation.invoice is not None:
                    existing = reservation.invoice
                    return Response(
                        InvoiceSerializer(existing, context={"request": request}).data,
                        status=status.HTTP_200_OK,
                    )
                invoice = Invoice.objects.create(
                    business=request.business,
                    reservation=reservation,
                    type=type_facture,
                    tva_taux=tva_taux,
                    lignes=lignes,
                    client_nom=reservation.contact_nom or reservation.reserve_par.get_full_name() or reservation.reserve_par.email,
                    client_email=reservation.reserve_par.email,
                    client_telephone=reservation.contact_telephone or reservation.reserve_par.telephone,
                    client_adresse=reservation.lieu_adresse or "",
                    generee_par=request.user,
                )
                invoice.calculer_montants()
                invoice.statut = Invoice.Statut.PROFORMA if type_facture == Invoice.Type.PROFORMA else Invoice.Statut.DEFINITIVE
                invoice.save()
        except IntegrityError as e:
            # Conflit sur le numéro séquentiel ou sur la réservation (OneToOne)
            # On tente de retourner la facture existante si elle a été créée entre-temps
            try:
                reservation.refresh_from_db()
                if hasattr(reservation, "invoice") and reservation.invoice is not None:
                    return Response(
                        InvoiceSerializer(reservation.invoice, context={"request": request}).data,
                        status=status.HTTP_200_OK,
                    )
                # Si c'est un conflit de numéro, on retente une fois avec un nouveau numéro
                if "numero" in str(e) or "uniq_invoice" in str(e):
                    # Le modèle Invoice.save() gère déjà le retry sur 3 tentatives,
                    # si on arrive ici c'est que les 3 ont échoué — on renvoie 409
                    return Response(
                        {"detail": "Conflit de numérotation, veuillez réessayer."},
                        status=status.HTTP_409_CONFLICT,
                    )
            except Exception:
                pass
            # Fallback générique
            return Response(
                {"detail": "Cette réservation a déjà une facture ou le numéro existe déjà."},
                status=status.HTTP_409_CONFLICT,
            )

        # Générer PDF (TODO: weasyprint)
        # invoice.generer_pdf()

        from .activite import log_activity, Act
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.INVOICE_CREATE,
            item=reservation.item,
            cible=f"Invoice {invoice.numero}",
            detail={"type": type_facture, "total_ttc": str(invoice.total_ttc)},
        )

        return Response(
            InvoiceSerializer(invoice, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class InvoiceDetailView(APIView):
    """Détail d'une facture.

    GET /api/businesses/<uuid:business_id>/invoices/<uuid:invoice_id>/
    """

    permission_classes = [HasBusinessPermission.require(Perm.CATALOG_VIEW)]
    serializer_class = InvoiceSerializer

    def get(self, request, business_id, invoice_id):
        invoice = request.business.invoices.filter(id=invoice_id).first()
        if invoice is None:
            return Response(
                {"detail": "Facture introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = InvoiceSerializer(invoice, context={"request": request})
        return Response(serializer.data)


class InvoicePDFView(APIView):
    """Télécharge le PDF de la facture.

    GET /api/businesses/<uuid:business_id>/invoices/<uuid:invoice_id>/pdf/
    """

    permission_classes = [HasBusinessPermission.require(Perm.CATALOG_VIEW)]

    def get(self, request, business_id, invoice_id):
        invoice = request.business.invoices.filter(id=invoice_id).first()
        if invoice is None:
            return Response(
                {"detail": "Facture introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not invoice.pdf:
            return Response(
                {"detail": "PDF non encore généré."},
                status=status.HTTP_404_NOT_FOUND,
            )

        from django.http import FileResponse
        return FileResponse(
            invoice.pdf.open(),
            as_attachment=True,
            filename=f"{invoice.numero}.pdf",
        )


class InvoiceMarkSentView(APIView):
    """Marque la facture comme envoyée au client.

    POST /api/businesses/<uuid:business_id>/invoices/<uuid:invoice_id>/mark-sent/
    """

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_MANAGE)]

    def post(self, request, business_id, invoice_id):
        invoice = request.business.invoices.filter(id=invoice_id).first()
        if invoice is None:
            return Response(
                {"detail": "Facture introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        invoice.marquer_envoyee()

        from .activite import log_activity, Act
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.INVOICE_SENT,
            item=invoice.reservation.item,
            cible=f"Invoice {invoice.numero}",
            detail={"action": "envoyee_au_client"},
        )

        return Response({"message": "Facture marquée comme envoyée.", "envoyee_le": invoice.envoyee_le})


class InvoiceMarkPaidView(APIView):
    """Marque la facture comme payée.

    POST /api/businesses/<uuid:business_id>/invoices/<uuid:invoice_id>/mark-paid/
    """

    permission_classes = [HasBusinessPermission.require(Perm.RESERVATION_MANAGE)]

    def post(self, request, business_id, invoice_id):
        invoice = request.business.invoices.filter(id=invoice_id).first()
        if invoice is None:
            return Response(
                {"detail": "Facture introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if invoice.statut == Invoice.Statut.ANNULEE:
            return Response(
                {"detail": "Impossible de marquer une facture annulée comme payée."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        invoice.marquer_payee()

        from .activite import log_activity, Act
        log_activity(
            business=request.business,
            acteur=request.user,
            action=Act.INVOICE_PAID,
            item=invoice.reservation.item,
            cible=f"Invoice {invoice.numero}",
            detail={"action": "marquee_payee"},
        )

        return Response({"message": "Facture marquée comme payée.", "payee_le": invoice.payee_le})


class PublicInvoiceDetailView(APIView):
    """Téléchargement facture par le client (via token réservation).

    GET /api/public/b/<slug>/invoices/<uuid:reservation_id>/
    """

    permission_classes = [AllowAny]
    serializer_class = InvoicePublicSerializer

    def get(self, request, slug, reservation_id):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        invoice = Invoice.objects.filter(
            business=business, reservation_id=reservation_id
        ).first()

        if invoice is None:
            return Response(
                {"detail": "Facture introuvable pour cette réservation."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = InvoicePublicSerializer(invoice, context={"request": request})
        return Response(serializer.data)


class PublicInvoicePDFView(APIView):
    """Téléchargement PDF facture par le client (public).

    GET /api/public/b/<slug>/invoices/<uuid:reservation_id>/pdf/
    """

    permission_classes = [AllowAny]

    def get(self, request, slug, reservation_id):
        business = Business.objects.filter(slug=slug).first()
        if business is None:
            return Response(
                {"detail": "Business introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        invoice = Invoice.objects.filter(
            business=business, reservation_id=reservation_id
        ).first()

        if invoice is None or not invoice.pdf:
            return Response(
                {"detail": "Facture ou PDF introuvable."},
                status=status.HTTP_404_NOT_FOUND,
            )

        from django.http import FileResponse
        return FileResponse(
            invoice.pdf.open(),
            as_attachment=True,
            filename=f"{invoice.numero}.pdf",
        )


class DeviceRegisterView(APIView):
    """POST /api/devices/ — enregistre le token FCM de l'appareil pour les notifications push."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        fcm_token = request.data.get("fcm_token")
        platform = request.data.get("platform", "android")
        installation_id = request.data.get("installation_id")
        app_version = request.data.get("app_version", "1.0.0")

        if not fcm_token:
            return Response(
                {"detail": "fcm_token requis."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Récupérer le membership actif pour ce business
        business_id = request.query_params.get("business_id")
        if not business_id:
            return Response(
                {"detail": "business_id requis en query param."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        membership = BusinessMember.objects.filter(
            user=request.user, business_id=business_id, statut=BusinessMember.Statut.ACTIF
        ).first()

        if not membership:
            return Response(
                {"detail": "Membre non trouvé pour ce business."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Mettre à jour le token FCM
        membership.fcm_token = fcm_token
        membership.device_type = platform.upper()
        membership.save(update_fields=["fcm_token", "device_type"])

        return Response(
            {"id": str(membership.id), "updated": True},
            status=status.HTTP_200_OK,
        )


class DeviceUnregisterView(APIView):
    """DELETE /api/devices/ — supprime le token FCM (déconnexion push)."""

    permission_classes = [IsAuthenticated]

    def delete(self, request):
        business_id = request.query_params.get("business_id")
        if not business_id:
            return Response(
                {"detail": "business_id requis en query param."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        membership = BusinessMember.objects.filter(
            user=request.user, business_id=business_id
        ).first()

        if not membership:
            return Response(
                {"detail": "Membre non trouvé pour ce business."},
                status=status.HTTP_404_NOT_FOUND,
            )

        membership.fcm_token = ""
        membership.save(update_fields=["fcm_token"])

        return Response(status=status.HTTP_204_NO_CONTENT)