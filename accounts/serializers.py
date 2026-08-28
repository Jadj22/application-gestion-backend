from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

MAX_ITEM_PHOTO_SIZE = 5 * 1024 * 1024

from .models import (
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
    Permission,
    Procedure,
    ProcedureStep,
    RecurringTask,
    Reminder,
    Reservation,
    Role,
    StockAdjustment,
    StockMovement,
    TaskComment,
    TaskStep,
    TaskStepPhoto,
)

User = get_user_model()

from .fiabilite import a_verifier, progress
from .maintenance import etat_entretien


class CategoryShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ["id", "nom"]


class UserSerializer(serializers.ModelSerializer):
    """User sérialisé avec un id string (cohérent avec les UUID du reste de l'API)."""

    id = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name", "telephone", "statut"]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, style={"input_type": "password"})
    id = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "password", "first_name", "last_name", "telephone"]
        extra_kwargs = {
            "email": {"required": True},
            "first_name": {"required": False, "allow_blank": True},
            "last_name": {"required": False, "allow_blank": True},
        }

    def create(self, validated_data):
        password = validated_data.pop("password")
        email = validated_data["email"]
        user = User(username=email, **validated_data)
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(TokenObtainPairSerializer):
    """JWT + infos utilisateur dans la réponse de connexion."""

    def validate(self, attrs):
        data = super().validate(attrs)
        data["user"] = UserSerializer(self.user).data
        return data


class GoogleAuthSerializer(serializers.Serializer):
    """Connexion Google : reçoit l'ID token OAuth 2.0 de l'app Android."""

    id_token = serializers.CharField()


class InvitationPreviewSerializer(serializers.Serializer):
    """Aperçu public d'une invitation (GET /invitations/<token>/)."""

    email = serializers.EmailField()
    business_id = serializers.UUIDField()
    business_nom = serializers.CharField()
    inviteur = serializers.EmailField(allow_null=True)
    role = serializers.CharField(allow_null=True)
    statut = serializers.CharField()


class InvitationCodeSerializer(serializers.Serializer):
    """Validation d'un code d'invitation (POST /invitations/validate/).

    La normalisation et la recherche se font côté vue ; un code inconnu ou
    malformé est traité comme « Code invalide » (404), pas comme une erreur
    de champ.
    """

    code = serializers.CharField(max_length=24)


class InvitationAcceptSerializer(serializers.Serializer):
    """Acceptation d'une invitation (POST /invitations/accept/).

    Deux modes :
    * non connecté : `code` (ou `token`) + mot de passe requis (compte créé à
      l'invitation sans mot de passe) → JWT renvoyés (connexion immédiate) ;
    * connecté : `code` seul, l'utilisateur courant doit correspondre à
      l'email invité → le membership est activé sans nouveau mot de passe.
    """

    token = serializers.CharField(required=False)
    code = serializers.CharField(required=False, max_length=24)
    password = serializers.CharField(
        required=False,
        min_length=8,
        write_only=True,
        style={"input_type": "password"},
    )
    first_name = serializers.CharField(
        required=False, allow_blank=True, max_length=150
    )
    last_name = serializers.CharField(
        required=False, allow_blank=True, max_length=150
    )
    telephone = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        if not attrs.get("token") and not attrs.get("code"):
            raise serializers.ValidationError(
                "Un code ou un lien d'invitation est requis."
            )
        return attrs


class ImageDescriptionSerializer(serializers.Serializer):
    """Photo d'article analysée par Gemini (POST /ai/image-description/)."""

    image = serializers.ImageField()

    def validate_image(self, image):
        if image.size > MAX_ITEM_PHOTO_SIZE:
            raise serializers.ValidationError(
                f"Photo trop lourde : {image.size} octets "
                f"(max {MAX_ITEM_PHOTO_SIZE})."
            )
        return image


class BusinessSerializer(serializers.ModelSerializer):
    logoUrl = serializers.URLField(source="logo_url", required=False, allow_blank=True)
    logo = serializers.ImageField(write_only=True, required=False, allow_null=True)

    class Meta:
        model = Business
        fields = ["id", "nom", "slug", "business_type", "adresse", "telephone", "email", "logoUrl", "logo", "created_at"]
        read_only_fields = ["id", "slug", "created_at"]

    def _apply_logo(self, instance, logo):
        if not logo:
            return instance
        # 1) Le fichier est stocké (nom final généré par pre_save),
        # 2) logo_url pointe alors vers l'URL servie (/media/...).
        instance.logo = logo
        instance.save(update_fields=["logo"])
        instance.logo_url = instance.logo.url
        instance.save(update_fields=["logo_url"])
        return instance

    def create(self, validated_data):
        logo = validated_data.pop("logo", None)
        instance = super().create(validated_data)
        return self._apply_logo(instance, logo)

    def update(self, instance, validated_data):
        logo = validated_data.pop("logo", None)
        instance = super().update(instance, validated_data)
        return self._apply_logo(instance, logo)


class BusinessTypeSerializer(serializers.Serializer):
    codename = serializers.CharField()
    libelle = serializers.CharField()


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ["id", "nom", "description", "is_system", "permissions"]
        read_only_fields = ["id", "is_system"]

    def get_permissions(self, obj):
        return [
            {"codename": p.codename, "libelle": p.libelle}
            for p in obj.permissions.order_by("codename")
        ]


class RoleWriteSerializer(serializers.ModelSerializer):
    permission_codenames = serializers.ListField(
        child=serializers.CharField(), write_only=True, required=False
    )

    class Meta:
        model = Role
        fields = ["id", "nom", "description", "permission_codenames"]
        read_only_fields = ["id"]

    def _validated_permissions(self, codenames):
        if codenames is None:
            return None
        perms = Permission.objects.filter(codename__in=codenames)
        if perms.count() != len(set(codenames)):
            raise serializers.ValidationError(
                {"permission_codenames": "Certaines permissions sont inconnues."}
            )
        return perms

    def create(self, validated_data):
        codenames = validated_data.pop("permission_codenames", None)
        business = self.context["business"]
        if Role.objects.filter(business=business, nom=validated_data["nom"]).exists():
            raise serializers.ValidationError({"nom": "Ce rôle existe déjà."})
        permissions = self._validated_permissions(codenames)
        role = Role.objects.create(business=business, **validated_data)
        if permissions is not None:
            role.permissions.set(permissions)
        return role

    def update(self, instance, validated_data):
        codenames = validated_data.pop("permission_codenames", None)
        if instance.is_system:
            raise serializers.ValidationError(
                {"nom": "Les rôles système ne peuvent pas être modifiés."}
            )
        for field, value in validated_data.items():
            setattr(instance, field, value)
        if "nom" in validated_data and Role.objects.filter(
            business=instance.business, nom=validated_data["nom"]
        ).exclude(id=instance.id).exists():
            raise serializers.ValidationError({"nom": "Ce rôle existe déjà."})
        instance.save()
        permissions = self._validated_permissions(codenames)
        if permissions is not None:
            instance.permissions.set(permissions)
        return instance


class MemberInviteSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role_id = serializers.UUIDField(required=False)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)

    def validate_role_id(self, value):
        business = self.context["business"]
        role = Role.objects.filter(id=value, business=business).first()
        if role is None:
            raise serializers.ValidationError("Rôle invalide pour ce business.")
        return role


class MemberWriteSerializer(serializers.Serializer):
    role_id = serializers.UUIDField(required=False)
    statut = serializers.ChoiceField(
        choices=BusinessMember.Statut.choices, required=False
    )
    business = serializers.UUIDField(required=False, write_only=True)

    def validate_role_id(self, value):
        business = self.context["business"]
        role = Role.objects.filter(id=value, business=business).first()
        if role is None:
            raise serializers.ValidationError("Rôle invalide pour ce business.")
        return role


class BusinessMemberSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    role = RoleSerializer(read_only=True)
    invited_by = UserSerializer(read_only=True)

    class Meta:
        model = BusinessMember
        fields = ["id", "user", "role", "statut", "invited_by", "invited_at"]


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ["codename", "libelle", "description"]


# --- Sprint 2 : Catalogue ---------------------------------------------------


class CategorySerializer(serializers.ModelSerializer):
    item_count = serializers.SerializerMethodField()
    parent_id = serializers.UUIDField(
        source="parent", required=False, allow_null=True
    )
    entretien_requis = serializers.BooleanField(required=False, allow_null=True)
    procedure_id = serializers.UUIDField(
        source="procedure", required=False, allow_null=True
    )
    image = serializers.ImageField(required=False, allow_null=True)
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = [
            "id", "nom", "description", "parent_id", "item_count",
            "entretien_requis", "procedure_id", "image", "image_url", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "image_url"]

    def get_item_count(self, obj):
        cached = getattr(obj, "item_count", None)
        if cached is not None:
            return cached
        return obj.items.count()

    def get_image_url(self, obj):
        if not obj.image:
            return None
        request = self.context.get("request")
        url = obj.image.url
        if request is not None:
            return request.build_absolute_uri(url)
        return url

    def validate_nom(self, value):
        business = self.context["business"]
        qs = Category.objects.filter(business=business, nom=value)
        if self.instance is not None:
            qs = qs.exclude(id=self.instance.id)
        if qs.exists():
            raise serializers.ValidationError("Cette catégorie existe déjà.")
        return value

    def validate_parent(self, value):
        if value is None:
            return value
        business = self.context["business"]
        if value.business_id != business.id:
            raise serializers.ValidationError("Catégorie parente invalide pour ce business.")
        if self.instance is not None and value.id == self.instance.id:
            raise serializers.ValidationError("Une catégorie ne peut pas être son propre parent.")
        return value

    def validate_procedure_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        procedure = Procedure.objects.filter(id=value, business=business).first()
        if procedure is None:
            raise serializers.ValidationError("Procédure invalide pour ce business.")
        return procedure


class PublicCategorySerializer(serializers.ModelSerializer):
    """Serializer public pour les catégories (lecture seule, sans auth)."""

    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = ["id", "nom", "description", "image_url"]
        read_only_fields = fields

    def get_image_url(self, obj):
        if not obj.image:
            return None
        request = self.context.get("request")
        url = obj.image.url
        if request is not None:
            return request.build_absolute_uri(url)
        return url


class ItemPhotoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ItemPhoto
        fields = ["id", "image", "caption", "order", "created_at"]
        read_only_fields = ["id", "created_at"]

    def validate_image(self, value):
        if value.size > MAX_ITEM_PHOTO_SIZE:
            raise serializers.ValidationError(
                f"Photo trop lourde : {value.size} octets (max {MAX_ITEM_PHOTO_SIZE})."
            )
        return value


class ItemSerializer(serializers.ModelSerializer):
    category = CategoryShortSerializer(read_only=True)
    category_id = serializers.UUIDField(write_only=True, required=False, allow_null=True)
    photos = ItemPhotoSerializer(many=True, read_only=True)
    entretien_requis = serializers.BooleanField(required=False, allow_null=True)
    initial_quantity = serializers.IntegerField(
        write_only=True, required=False, min_value=1, max_value=1_000_000
    )
    etat_entretien = serializers.SerializerMethodField()
    a_verifier = serializers.SerializerMethodField()
    procedure_id = serializers.UUIDField(
        source="procedure", write_only=True, required=False, allow_null=True
    )

    class Meta:
        model = Item
        fields = [
            "id", "nom", "reference", "description", "prix", "unite", "statut",
            "is_published",
            "characteristics", "category", "category_id", "photos",
            "entretien_requis", "initial_quantity", "etat_entretien",
            "a_verifier", "procedure_id",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_etat_entretien(self, obj):
        etats = self.context.get("etats")
        if etats and obj.id in etats:
            return etats[obj.id]
        return etat_entretien(obj)

    def get_a_verifier(self, obj):
        flags = self.context.get("a_verifier")
        if flags and obj.id in flags:
            return flags[obj.id]
        return a_verifier(obj)

    def validate_nom(self, value):
        return value.strip() or None

    def validate_reference(self, value):
        if not value:
            return None
        business = self.context["business"]
        qs = Item.objects.filter(business=business, reference=value)
        if self.instance is not None:
            qs = qs.exclude(id=self.instance.id)
        if qs.exists():
            raise serializers.ValidationError("Cette référence existe déjà.")
        return value

    def validate_procedure_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        procedure = Procedure.objects.filter(id=value, business=business).first()
        if procedure is None:
            raise serializers.ValidationError("Procédure invalide pour ce business.")
        return procedure

    def validate_category_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        category = Category.objects.filter(id=value, business=business).first()
        if category is None:
            raise serializers.ValidationError("Catégorie invalide pour ce business.")
        return category

    def validate_characteristics(self, value):
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise serializers.ValidationError("Les caractéristiques doivent être un objet.")
        if len(value) > 20:
            raise serializers.ValidationError("20 caractéristiques maximum.")
        for key, val in value.items():
            if not isinstance(key, str) or not key.strip() or len(key) > 50:
                raise serializers.ValidationError("Clé de caractéristique invalide.")
            if val is None:
                continue
            if not isinstance(val, (str, int, float, bool)):
                raise serializers.ValidationError(
                    "Valeur de caractéristique invalide (texte ou nombre attendu)."
                )
            if isinstance(val, str) and len(val) > 200:
                raise serializers.ValidationError("Valeur de caractéristique trop longue.")
        return value

    def create(self, validated_data):
        category = validated_data.pop("category_id", None)
        if category is not None:
            validated_data["category"] = category
        initial_quantity = validated_data.pop("initial_quantity", None)
        validated_data["business"] = self.context["business"]
        item = super().create(validated_data)
        if initial_quantity:
            from .stock import create_movement

            create_movement(
                business=self.context["business"],
                item=item,
                type=StockMovement.Type.ENTREE,
                quantite=initial_quantity,
                acteur=self.context.get("user"),
                motif="Stock initial",
            )
        return item

    def update(self, instance, validated_data):
        category = validated_data.pop("category_id", None)
        if category is not None:
            validated_data["category"] = category
        return super().update(instance, validated_data)
# --- Sprint 3 : Stock & tracabilite ----------------------------------------


class StockMovementSerializer(serializers.ModelSerializer):
    acteur = UserSerializer(read_only=True)
    item_id = serializers.UUIDField(write_only=True)
    related_to = serializers.UUIDField(write_only=True, required=False)
    retour_de = serializers.UUIDField(source="related_to_id", read_only=True, required=False)
    date = serializers.DateTimeField(source="created_at", read_only=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True)

    class Meta:
        model = StockMovement
        fields = [
            "id", "type", "quantite", "motif", "reference",
            "acteur", "date", "item_id", "item_nom", "related_to", "retour_de",
        ]
        read_only_fields = ["id"]

    def validate(self, attrs):
        mvt_type = attrs["type"]
        motif = attrs.get("motif") or ""
        if not motif.strip() and mvt_type != StockMovement.Type.ENTREE:
            raise serializers.ValidationError(
                {"motif": "Le motif est obligatoire pour ce type de mouvement."}
            )
        related_to = attrs.get("related_to")
        if related_to is not None:
            if mvt_type != StockMovement.Type.RETOUR:
                raise serializers.ValidationError(
                    {"related_to": "Un mouvement lié n'est permis que pour un RETOUR."}
                )
            business = self.context["business"]
            item = attrs.get("item_id")
            linked = StockMovement.objects.filter(
                id=related_to, business=business, item=item,
                type=StockMovement.Type.SORTIE,
            ).first()
            if linked is None:
                raise serializers.ValidationError(
                    {"related_to": "La sortie liée est introuvable pour cet article."}
                )
            attrs["related_to"] = linked
        return attrs

    def validate_item_id(self, value):
        business = self.context["business"]
        item = Item.objects.filter(id=value, business=business).first()
        if item is None:
            raise serializers.ValidationError("Article invalide pour ce business.")
        return item

    def validate_quantite(self, value):
        if value < 1:
            raise serializers.ValidationError("La quantité doit être d'au moins 1.")
        return value


# --- Sprint 4 : Entretien (US-13 à US-17) -----------------------------------


class ProcedureStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProcedureStep
        fields = ["id", "nom", "ordre", "obligatoire", "type", "description"]
        read_only_fields = ["id"]


class ProcedureSerializer(serializers.ModelSerializer):
    steps = ProcedureStepSerializer(many=True, read_only=True)
    steps_input = serializers.ListField(
        child=serializers.DictField(), write_only=True, required=False
    )

    class Meta:
        model = Procedure
        fields = [
            "id", "nom", "description", "est_actif",
            "steps", "steps_input", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate_nom(self, value):
        business = self.context["business"]
        qs = Procedure.objects.filter(business=business, nom=value)
        if self.instance is not None:
            qs = qs.exclude(id=self.instance.id)
        if qs.exists():
            raise serializers.ValidationError("Cette procédure existe déjà.")
        return value

    def _validated_steps(self, raw_steps):
        if raw_steps is None:
            return None
        if not raw_steps:
            raise serializers.ValidationError(
                {"steps_input": "Une procédure doit comporter au moins une étape."}
            )
        noms = []
        cleaned = []
        for index, raw in enumerate(raw_steps):
            if not isinstance(raw, dict):
                raise serializers.ValidationError(
                    {"steps_input": f"Étape {index + 1} invalide."}
                )
            nom = (raw.get("nom") or "").strip()
            if not nom:
                raise serializers.ValidationError(
                    {"steps_input": f"Étape {index + 1} : le nom est obligatoire."}
                )
            if len(nom) > 200:
                raise serializers.ValidationError(
                    {"steps_input": f"Étape {index + 1} : nom trop long."}
                )
            if nom in noms:
                raise serializers.ValidationError(
                    {"steps_input": f"Deux étapes portent le nom « {nom} »."}
                )
            noms.append(nom)
            step_type = raw.get("type") or ProcedureStep.Type.OPERATION
            if step_type not in ProcedureStep.Type.values:
                raise serializers.ValidationError(
                    {"steps_input": f"Étape {nom} : type inconnu ({step_type})."}
                )
            cleaned.append(
                {
                    "nom": nom,
                    "ordre": max(int(raw.get("ordre") or 0), 0),
                    "obligatoire": bool(raw.get("obligatoire", True)),
                    "type": step_type,
                    "description": (raw.get("description") or "").strip(),
                }
            )
        return cleaned

    def create(self, validated_data):
        raw_steps = validated_data.pop("steps_input", None)
        steps = self._validated_steps(raw_steps)
        procedure = Procedure.objects.create(**validated_data)
        if steps:
            ProcedureStep.objects.bulk_create(
                [ProcedureStep(procedure=procedure, **s) for s in steps]
            )
        return procedure

    def update(self, instance, validated_data):
        raw_steps = validated_data.pop("steps_input", None)
        steps = self._validated_steps(raw_steps)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        if steps is not None:
            instance.steps.all().delete()
            ProcedureStep.objects.bulk_create(
                [ProcedureStep(procedure=instance, **s) for s in steps]
            )
        return instance


# --- Sprint 5 : Disponibilité & fiabilité (US-18, US-22 à US-26) ------------


class InventorySerializer(serializers.ModelSerializer):
    avancement = serializers.SerializerMethodField()
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = Inventory
        fields = [
            "id", "libelle", "statut", "avancement",
            "created_by", "created_at", "closed_at",
        ]
        read_only_fields = ["id", "statut", "created_at", "closed_at"]

    def get_avancement(self, obj):
        total = obj.business.items.count()
        return progress(obj, total)


class InventoryCountSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True)
    declared_by = UserSerializer(read_only=True)
    ecart = serializers.IntegerField(read_only=True)

    class Meta:
        model = InventoryCount
        fields = [
            "id", "item_id", "item_nom", "quantite_theorique",
            "quantite_comptee", "fiabilite", "ecart",
            "declared_by", "declared_at",
        ]
        read_only_fields = fields


class InventoryCountWriteSerializer(serializers.Serializer):
    item_id = serializers.UUIDField()
    quantite_comptee = serializers.IntegerField(min_value=0)
    fiabilite = serializers.ChoiceField(
        choices=InventoryCount.Fiabilite.choices,
        default=InventoryCount.Fiabilite.NON_VERIFIE,
    )

    def validate_item_id(self, value):
        business = self.context["business"]
        item = Item.objects.filter(id=value, business=business).first()
        if item is None:
            raise serializers.ValidationError("Article invalide pour ce business.")
        return item


class StockAdjustmentSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True)
    inventory_id = serializers.UUIDField(read_only=True, allow_null=True)
    acteur = UserSerializer(read_only=True)
    date = serializers.DateTimeField(source="created_at", read_only=True)

    class Meta:
        model = StockAdjustment
        fields = [
            "id", "item_id", "item_nom", "inventory_id",
            "quantite_theorique", "quantite_comptee", "ecart",
            "motif", "reference", "acteur", "date",
        ]
        read_only_fields = fields


class StockAdjustmentWriteSerializer(serializers.Serializer):
    item_id = serializers.UUIDField()
    quantite_comptee = serializers.IntegerField(min_value=0)
    motif = serializers.CharField(required=False, allow_blank=True)
    reference = serializers.CharField(required=False, allow_blank=True)

    def validate_item_id(self, value):
        business = self.context["business"]
        item = Item.objects.filter(id=value, business=business).first()
        if item is None:
            raise serializers.ValidationError("Article invalide pour ce business.")
        return item


class TaskStepSerializer(serializers.ModelSerializer):
    done_by = UserSerializer(read_only=True)
    duree_reelle = serializers.SerializerMethodField()
    duree_estimee_secondes = serializers.SerializerMethodField()
    photos = serializers.SerializerMethodField()

    class Meta:
        model = TaskStep
        fields = [
            "id", "nom", "ordre", "obligatoire", "type",
            "statut", "started_at", "finished_at", "done_by",
            "duree_estimee", "duree_estimee_secondes", "duree_reelle", "photos",
        ]
        read_only_fields = fields

    def get_duree_reelle(self, obj):
        duree = obj.duree_reelle
        if duree:
            return int(duree.total_seconds())
        return None

    def get_duree_estimee_secondes(self, obj):
        if obj.duree_estimee:
            return int(obj.duree_estimee.total_seconds())
        return None

    def get_photos(self, obj):
        return TaskStepPhotoSerializer(obj.photos.all(), many=True).data


class TaskStepUpdateSerializer(serializers.Serializer):
    statut = serializers.ChoiceField(
        choices=[TaskStep.Statut.EN_COURS, TaskStep.Statut.TERMINE]
    )


class MaintenanceTaskSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True)
    procedure_id = serializers.UUIDField(read_only=True)
    etapes = serializers.SerializerMethodField()
    etat_article = serializers.SerializerMethodField()
    steps = TaskStepSerializer(many=True, read_only=True)
    # Attribution (Sprint 1)
    assigned_to = UserSerializer(read_only=True)
    assigned_by = UserSerializer(read_only=True)
    created_by = UserSerializer(read_only=True)
    # Coûts (Sprint 2)
    cout_total = serializers.SerializerMethodField()
    # Commentaires (Sprint 1)
    comments_count = serializers.SerializerMethodField()
    # Durée totale
    duree_totale = serializers.SerializerMethodField()

    class Meta:
        model = MaintenanceTask
        fields = [
            "id", "item_id", "item_nom", "procedure_id", "procedure_nom",
            "motif", "statut", "etapes", "etat_article", "steps",
            "assigned_to", "assigned_at", "assigned_by", "created_by",
            "cout_main_oeuvre", "cout_materiel", "cout_total",
            "comments_count", "duree_totale",
            "created_at", "updated_at",
        ]
        read_only_fields = fields

    def get_etapes(self, obj):
        from .maintenance import progress

        return progress(obj)

    def get_etat_article(self, obj):
        etats = self.context.get("etats")
        if etats and obj.item_id in etats:
            return etats[obj.item_id]
        return etat_entretien(obj.item)

    def get_cout_total(self, obj):
        main_oeuvre = obj.cout_main_oeuvre or 0
        materiel = obj.cout_materiel or 0
        total = main_oeuvre + materiel
        return float(total) if total > 0 else None

    def get_comments_count(self, obj):
        return obj.comments.count()

    def get_duree_totale(self, obj):
        total_seconds = 0
        for step in obj.steps.all():
            duree = step.duree_reelle
            if duree:
                total_seconds += int(duree.total_seconds())
        return total_seconds if total_seconds > 0 else None


class TaskCreateSerializer(serializers.Serializer):
    item_id = serializers.UUIDField()
    procedure_id = serializers.UUIDField(required=False)
    motif = serializers.CharField(required=False, allow_blank=True)
    # Attribution (Sprint 1)
    assigned_to_id = serializers.UUIDField(required=False, allow_null=True)
    # Coûts estimés (Sprint 2)
    cout_main_oeuvre = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )
    cout_materiel = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )

    def validate_item_id(self, value):
        business = self.context["business"]
        item = Item.objects.filter(id=value, business=business).first()
        if item is None:
            raise serializers.ValidationError("Article invalide pour ce business.")
        return item

    def validate_procedure_id(self, value):
        business = self.context["business"]
        procedure = Procedure.objects.filter(
            id=value, business=business, est_actif=True
        ).first()
        if procedure is None:
            raise serializers.ValidationError(
                "Procédure invalide ou désactivée pour ce business."
            )
        return procedure

    def validate_assigned_to_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        member = BusinessMember.objects.filter(
            business=business, user_id=value, statut=BusinessMember.Statut.ACTIF
        ).first()
        if member is None:
            raise serializers.ValidationError("Membre invalide pour ce business.")
        return member.user


# --- Sprint 6 : alertes, décisions & exceptions (US-19, US-20, US-21) ------


class BusinessRuleSerializer(serializers.ModelSerializer):
    libelle = serializers.CharField(source="get_code_display", read_only=True)

    class Meta:
        model = BusinessRule
        fields = ["id", "code", "libelle", "mode", "est_actif", "updated_at"]
        read_only_fields = ["id", "code", "libelle", "updated_at"]


class AlertSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True)
    acteur = UserSerializer(read_only=True)

    class Meta:
        model = Alert
        fields = [
            "id", "item_id", "item_nom", "code", "mode", "message",
            "quantite", "mouvement_id", "acteur", "created_at",
        ]
        read_only_fields = fields


class DecisionLogSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True)
    acteur = UserSerializer(read_only=True)

    class Meta:
        model = DecisionLog
        fields = [
            "id", "item_id", "item_nom", "code", "motif", "quantite",
            "mouvement_id", "acteur", "created_at",
        ]
        read_only_fields = fields


# --- Sprint 7 : activité & notifications (US-27, US-28) --------------------


class ActivityLogSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True, allow_null=True)
    acteur = UserSerializer(read_only=True)

    class Meta:
        model = ActivityLog
        fields = [
            "id", "action", "acteur", "item_id", "cible", "detail", "created_at",
        ]
        read_only_fields = fields


class NotificationSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = Notification
        fields = [
            "id", "code", "message", "item_id", "lu", "created_at",
        ]
        read_only_fields = ["id", "code", "message", "item_id", "created_at"]


# --- Sprint 8 : réservations (US-29, US-30, US-31) ---------------------------


class ReservationSerializer(serializers.ModelSerializer):
    item_id = serializers.UUIDField(read_only=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True)
    reserve_par = UserSerializer(read_only=True)
    livreur = UserSerializer(read_only=True)
    reprise_par = UserSerializer(read_only=True)

    class Meta:
        model = Reservation
        fields = [
            "id", "item_id", "item_nom", "reserve_par", "date_debut",
            "date_fin", "quantite", "motif", "statut", "created_at", "updated_at",
            # Localisation & livraison
            "lieu_nom", "lieu_adresse", "lieu_lat", "lieu_lng",
            "contact_nom", "contact_telephone",
            "livraison_prevue_le", "livraison_effectuee_le", "livreur",
            "reprise_prevue_le", "reprise_effectuee_le", "reprise_par",
            "statut_livraison", "notes_livraison",
            # Contrôle retour
            "quantite_retournee", "quantite_abimee", "quantite_perdue",
            "observations", "retourne_le",
        ]
        read_only_fields = fields


class ReservationFinishSerializer(serializers.Serializer):
    """Payload du contrôle de retour (Sprint 8 bis, US-31+)."""

    quantite_retournee = serializers.IntegerField(required=False, min_value=0)
    quantite_abimee = serializers.IntegerField(required=False, min_value=0)
    quantite_perdue = serializers.IntegerField(required=False, min_value=0)
    observations = serializers.CharField(required=False, allow_blank=True)


class ReservationCreateSerializer(serializers.Serializer):
    item_id = serializers.UUIDField()
    date_debut = serializers.DateField()
    date_fin = serializers.DateField()
    quantite = serializers.IntegerField(min_value=1, default=1)
    motif = serializers.CharField(required=False, allow_blank=True)
    # Localisation & livraison (optionnel à la création)
    lieu_nom = serializers.CharField(max_length=200, required=False, allow_blank=True)
    lieu_adresse = serializers.CharField(required=False, allow_blank=True)
    lieu_lat = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)
    lieu_lng = serializers.DecimalField(max_digits=9, decimal_places=6, required=False, allow_null=True)
    contact_nom = serializers.CharField(max_length=150, required=False, allow_blank=True)
    contact_telephone = serializers.CharField(max_length=30, required=False, allow_blank=True)
    livraison_prevue_le = serializers.DateTimeField(required=False, allow_null=True)
    reprise_prevue_le = serializers.DateTimeField(required=False, allow_null=True)
    notes_livraison = serializers.CharField(required=False, allow_blank=True)

    def validate_item_id(self, value):
        business = self.context["business"]
        item = Item.objects.filter(id=value, business=business).first()
        if item is None:
            raise serializers.ValidationError("Article invalide pour ce business.")
        return item

    def validate(self, attrs):
        if attrs["date_fin"] < attrs["date_debut"]:
            raise serializers.ValidationError(
                "La date de fin doit être postérieure ou égale à la date de début."
            )
        return attrs


class ReservationBulkItemSerializer(serializers.Serializer):
    item_id = serializers.UUIDField()
    quantite = serializers.IntegerField(min_value=1, default=1)
    # Localisation par item (optionnel)
    lieu_nom = serializers.CharField(max_length=200, required=False, allow_blank=True)
    lieu_adresse = serializers.CharField(required=False, allow_blank=True)
    contact_nom = serializers.CharField(max_length=150, required=False, allow_blank=True)
    contact_telephone = serializers.CharField(max_length=30, required=False, allow_blank=True)
    notes_livraison = serializers.CharField(required=False, allow_blank=True)


class ReservationBulkCreateSerializer(serializers.Serializer):
    """Réservation de plusieurs articles en un seul appel atomique (US-29)."""
    items = ReservationBulkItemSerializer(many=True)
    date_debut = serializers.DateField()
    date_fin = serializers.DateField()
    motif = serializers.CharField(required=False, allow_blank=True)
    # Livraison commune (optionnel)
    lieu_nom = serializers.CharField(max_length=200, required=False, allow_blank=True)
    lieu_adresse = serializers.CharField(required=False, allow_blank=True)
    contact_nom = serializers.CharField(max_length=150, required=False, allow_blank=True)
    contact_telephone = serializers.CharField(max_length=30, required=False, allow_blank=True)
    livraison_prevue_le = serializers.DateTimeField(required=False, allow_null=True)
    reprise_prevue_le = serializers.DateTimeField(required=False, allow_null=True)
    notes_livraison = serializers.CharField(required=False, allow_blank=True)

    def validate_items(self, value):
        if not value:
            raise serializers.ValidationError("Sélectionnez au moins un article.")
        business = self.context["business"]
        seen_ids = set()
        resolved = []
        for entry in value:
            item_id = entry["item_id"]
            if item_id in seen_ids:
                raise serializers.ValidationError(
                    "Un même article ne peut apparaître qu'une seule fois "
                    "dans la réservation."
                )
            seen_ids.add(item_id)
            item = Item.objects.filter(id=item_id, business=business).first()
            if item is None:
                raise serializers.ValidationError(
                    f"Article invalide pour ce business : {item_id}."
                )
            resolved.append((item, entry))
        return resolved

    def validate(self, attrs):
        if attrs["date_fin"] < attrs["date_debut"]:
            raise serializers.ValidationError(
                "La date de fin doit être postérieure ou égale à la date de début."
            )
        return attrs


# --- V2 : Booking Request (Demande location client) ----------------------------


class PublicBookingRequestCreateSerializer(serializers.Serializer):
    """Création d'une demande de location par un client externe (public, sans auth)."""

    item_id = serializers.UUIDField()
    client_nom = serializers.CharField(max_length=150)
    client_telephone = serializers.CharField(max_length=30, required=False, allow_blank=True)
    client_email = serializers.EmailField()
    date_debut = serializers.DateField()
    date_fin = serializers.DateField()
    quantite = serializers.IntegerField(min_value=1, default=1)
    message = serializers.CharField(required=False, allow_blank=True)
    # Localisation (optionnel)
    lieu_nom = serializers.CharField(max_length=200, required=False, allow_blank=True)
    lieu_adresse = serializers.CharField(required=False, allow_blank=True)
    contact_nom = serializers.CharField(max_length=150, required=False, allow_blank=True)
    contact_telephone = serializers.CharField(max_length=30, required=False, allow_blank=True)
    notes_livraison = serializers.CharField(required=False, allow_blank=True)
    # Mémoire client
    visitor_id = serializers.CharField(max_length=64, required=False, allow_blank=True)
    idempotency_key = serializers.CharField(max_length=100, required=False, allow_blank=True)

    def validate_item_id(self, value):
        business = self.context["business"]
        item = Item.objects.filter(
            id=value, business=business, is_published=True, statut=Item.Statut.ACTIF
        ).first()
        if item is None:
            raise serializers.ValidationError("Article introuvable ou non disponible.")
        return item

    def validate(self, attrs):
        if attrs["date_fin"] < attrs["date_debut"]:
            raise serializers.ValidationError(
                "La date de fin doit être postérieure ou égale à la date de début."
            )
        # Vérifier dispo basique
        item = attrs["item_id"]
        from .reservation import _chevauchant, _reservations_actives
        from django.db.models import Sum
        from .stock import snapshot

        stock = snapshot(item)
        total = stock["total"]
        reserves = _chevauchant(
            _reservations_actives(item), attrs["date_debut"], attrs["date_fin"]
        ).aggregate(total=Sum("quantite"))["total"] or 0

        # Aussi vérifier les booking requests en attente
        from .models import BookingRequest
        pending_br = _chevauchant(
            BookingRequest.objects.filter(
                business=item.business, item=item,
                statut__in=[BookingRequest.Statut.EN_ATTENTE, BookingRequest.Statut.ACCEPTEE]
            ), attrs["date_debut"], attrs["date_fin"]
        ).aggregate(total=Sum("quantite"))["total"] or 0

        dispo = max(total - reserves - pending_br, 0)
        if attrs["quantite"] > dispo:
            raise serializers.ValidationError(
                f"Quantité demandée ({attrs['quantite']}) > disponible ({dispo}) "
                f"sur cette période."
            )
        return attrs


class RecoverBookingRequestSerializer(serializers.Serializer):
    """Récupération d'une demande via email/téléphone/visitorId."""

    email = serializers.EmailField(required=False, allow_blank=True)
    phone = serializers.CharField(max_length=30, required=False, allow_blank=True)
    visitor_id = serializers.CharField(max_length=64, required=False, allow_blank=True)

    def validate(self, attrs):
        email = (attrs.get("email") or "").strip()
        phone = (attrs.get("phone") or "").strip()
        visitor_id = (attrs.get("visitor_id") or "").strip()
        if not email and not phone and not visitor_id:
            raise serializers.ValidationError("Fournissez email, téléphone ou visitorId.")
        return attrs


class ActiveRequestSerializer(serializers.Serializer):
    """Réponse pour hasActiveRequest."""

    hasActiveRequest = serializers.BooleanField()
    request = serializers.DictField(allow_null=True, required=False)


class PublicBookingRequestDetailSerializer(serializers.ModelSerializer):
    """Détail d'une demande pour le client (via token)."""

    item_nom = serializers.CharField(source="item.nom", read_only=True)
    item_prix = serializers.DecimalField(source="item.prix", max_digits=10, decimal_places=2, read_only=True)
    item_unite = serializers.CharField(source="item.unite", read_only=True)
    item_photo_url = serializers.SerializerMethodField()
    statut_display = serializers.CharField(source="get_statut_display", read_only=True)
    peut_annuler = serializers.SerializerMethodField()

    class Meta:
        model = BookingRequest
        fields = [
            "id", "item_id", "item_nom", "item_prix", "item_unite", "item_photo_url",
            "client_nom", "client_telephone", "client_email",
            "date_debut", "date_fin", "quantite", "message",
            "lieu_nom", "lieu_adresse", "contact_nom", "contact_telephone",
            "notes_livraison",
            "statut", "statut_display", "motif_refus",
            "contre_proposition", "peut_annuler",
            "created_at", "updated_at",
        ]
        read_only_fields = fields

    def get_item_photo_url(self, obj):
        request = self.context.get("request")
        if obj.item.photos.exists():
            return request.build_absolute_uri(obj.item.photos.first().image.url)
        return None

    def get_peut_annuler(self, obj):
        return obj.can_client_cancel


class BookingRequestTeamSerializer(serializers.ModelSerializer):
    """Détail d'une demande pour l'équipe (avec infos complètes)."""

    item_nom = serializers.CharField(source="item.nom", read_only=True)
    item_reference = serializers.CharField(source="item.reference", read_only=True)
    traite_par = UserSerializer(read_only=True)
    reservation_creee_id = serializers.UUIDField(source="reservation_creee.id", read_only=True)
    statut_display = serializers.CharField(source="get_statut_display", read_only=True)

    class Meta:
        model = BookingRequest
        fields = [
            "id", "item_id", "item_nom", "item_reference",
            "client_nom", "client_telephone", "client_email",
            "date_debut", "date_fin", "quantite", "message",
            "lieu_nom", "lieu_adresse", "contact_nom", "contact_telephone",
            "notes_livraison",
            "statut", "statut_display", "traite_par", "traite_le",
            "motif_refus", "contre_proposition",
            "reservation_creee_id",
            "created_at", "updated_at",
        ]
        read_only_fields = fields


class BookingRequestActionSerializer(serializers.Serializer):
    """Actions équipe : accepter, refuser, contre-proposer."""

    action = serializers.ChoiceField(choices=["accepter", "refuser", "contre_proposer"])
    # Pour refuser
    motif_refus = serializers.CharField(required=False, allow_blank=True)
    # Pour contre-proposer
    date_debut = serializers.DateField(required=False)
    date_fin = serializers.DateField(required=False)
    quantite = serializers.IntegerField(min_value=1, required=False)
    prix = serializers.DecimalField(max_digits=10, decimal_places=2, required=False)
    message = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        action = attrs["action"]
        if action == "refuser" and not attrs.get("motif_refus"):
            raise serializers.ValidationError({"motif_refus": "Motif obligatoire pour un refus."})
        if action == "contre_proposer":
            if not any(k in attrs for k in ["date_debut", "date_fin", "quantite", "prix"]):
                raise serializers.ValidationError(
                    "Au moins un champ doit être modifié pour une contre-proposition."
                )
            if "date_debut" in attrs and "date_fin" in attrs and attrs["date_fin"] < attrs["date_debut"]:
                raise serializers.ValidationError("date_fin doit être >= date_debut.")
        return attrs


# --- V3 : Client Counter-Proposal Response -----------------------------------


class PublicBookingRequestCounterResponseSerializer(serializers.Serializer):
    """Réponse du client à une contre-proposition (accepter/refuser)."""

    action = serializers.ChoiceField(choices=["accepter", "refuser"])
    # Pour refuser
    motif_refus = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        if attrs["action"] == "refuser" and not attrs.get("motif_refus"):
            raise serializers.ValidationError({"motif_refus": "Motif obligatoire pour un refus."})
        return attrs


# --- Sprint 1-3 : Collaboration avancée -------------------------------------


class TaskCommentSerializer(serializers.ModelSerializer):
    """Commentaire sur une tâche de maintenance (Sprint 1)."""

    auteur = UserSerializer(read_only=True)

    class Meta:
        model = TaskComment
        fields = ["id", "auteur", "contenu", "created_at", "updated_at"]
        read_only_fields = ["id", "auteur", "created_at", "updated_at"]


class TaskCommentCreateSerializer(serializers.Serializer):
    """Création d'un commentaire sur une tâche."""

    contenu = serializers.CharField(min_length=1, max_length=2000)


class TaskStepPhotoSerializer(serializers.ModelSerializer):
    """Photo d'une étape de tâche (Sprint 2)."""

    uploaded_by = UserSerializer(read_only=True)

    class Meta:
        model = TaskStepPhoto
        fields = ["id", "image", "type", "caption", "uploaded_by", "created_at"]
        read_only_fields = ["id", "uploaded_by", "created_at"]


class TaskStepPhotoCreateSerializer(serializers.Serializer):
    """Upload d'une photo sur une étape."""

    image = serializers.ImageField()
    type = serializers.ChoiceField(choices=TaskStepPhoto.Type.choices)
    caption = serializers.CharField(required=False, allow_blank=True, max_length=150)

    def validate_image(self, value):
        if value.size > MAX_ITEM_PHOTO_SIZE:
            raise serializers.ValidationError(
                f"Photo trop lourde : {value.size} octets (max {MAX_ITEM_PHOTO_SIZE})."
            )
        return value


class TaskAssignSerializer(serializers.Serializer):
    """Attribution d'une tâche à un membre (Sprint 1)."""

    assigned_to_id = serializers.UUIDField(allow_null=True)

    def validate_assigned_to_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        member = BusinessMember.objects.filter(
            business=business, user_id=value, statut=BusinessMember.Statut.ACTIF
        ).first()
        if member is None:
            raise serializers.ValidationError("Membre invalide pour ce business.")
        return member.user


class TaskUpdateSerializer(serializers.Serializer):
    """Mise à jour d'une tâche (coûts, attribution)."""

    assigned_to_id = serializers.UUIDField(required=False, allow_null=True)
    cout_main_oeuvre = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )
    cout_materiel = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )

    def validate_assigned_to_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        member = BusinessMember.objects.filter(
            business=business, user_id=value, statut=BusinessMember.Statut.ACTIF
        ).first()
        if member is None:
            raise serializers.ValidationError("Membre invalide pour ce business.")
        return member.user


# --- Sprint 3 : Planification périodique & Rappels --------------------------


class RecurringTaskSerializer(serializers.ModelSerializer):
    """Tâche récurrente (Sprint 3)."""

    item = serializers.SerializerMethodField()
    category = CategoryShortSerializer(read_only=True)
    procedure_nom = serializers.CharField(source="procedure.nom", read_only=True)
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = RecurringTask
        fields = [
            "id", "item", "category", "procedure", "procedure_nom",
            "frequence_jours", "prochaine_execution", "est_actif",
            "created_by", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_by", "created_at", "updated_at"]

    def get_item(self, obj):
        if obj.item:
            return {"id": str(obj.item.id), "nom": obj.item.nom}
        return None


class RecurringTaskCreateSerializer(serializers.Serializer):
    """Création d'une tâche récurrente."""

    item_id = serializers.UUIDField(required=False, allow_null=True)
    category_id = serializers.UUIDField(required=False, allow_null=True)
    procedure_id = serializers.UUIDField()
    frequence_jours = serializers.IntegerField(min_value=1, max_value=365)
    prochaine_execution = serializers.DateField()
    est_actif = serializers.BooleanField(default=True)

    def validate_item_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        item = Item.objects.filter(id=value, business=business).first()
        if item is None:
            raise serializers.ValidationError("Article invalide pour ce business.")
        return item

    def validate_category_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        category = Category.objects.filter(id=value, business=business).first()
        if category is None:
            raise serializers.ValidationError("Catégorie invalide pour ce business.")
        return category

    def validate_procedure_id(self, value):
        business = self.context["business"]
        procedure = Procedure.objects.filter(
            id=value, business=business, est_actif=True
        ).first()
        if procedure is None:
            raise serializers.ValidationError(
                "Procédure invalide ou désactivée pour ce business."
            )
        return procedure

    def validate(self, attrs):
        item = attrs.get("item_id")
        category = attrs.get("category_id")
        if not item and not category:
            raise serializers.ValidationError(
                "Vous devez spécifier un article ou une catégorie."
            )
        if item and category:
            raise serializers.ValidationError(
                "Spécifiez soit un article, soit une catégorie, pas les deux."
            )
        return attrs


class ReminderSerializer(serializers.ModelSerializer):
    """Rappel programmé (Sprint 3)."""

    user = UserSerializer(read_only=True)
    created_by = UserSerializer(read_only=True)
    task_id = serializers.UUIDField(read_only=True, allow_null=True)
    item_id = serializers.UUIDField(read_only=True, allow_null=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True, allow_null=True)

    class Meta:
        model = Reminder
        fields = [
            "id", "task_id", "item_id", "item_nom", "user",
            "rappel_a", "message", "envoye",
            "created_by", "created_at",
        ]
        read_only_fields = fields


class ReminderCreateSerializer(serializers.Serializer):
    """Création d'un rappel."""

    task_id = serializers.UUIDField(required=False, allow_null=True)
    item_id = serializers.UUIDField(required=False, allow_null=True)
    user_id = serializers.UUIDField()
    rappel_a = serializers.DateTimeField()
    message = serializers.CharField(max_length=255)

    def validate_task_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        task = MaintenanceTask.objects.filter(id=value, business=business).first()
        if task is None:
            raise serializers.ValidationError("Tâche invalide pour ce business.")
        return task

    def validate_item_id(self, value):
        if value is None:
            return None
        business = self.context["business"]
        item = Item.objects.filter(id=value, business=business).first()
        if item is None:
            raise serializers.ValidationError("Article invalide pour ce business.")
        return item

    def validate_user_id(self, value):
        business = self.context["business"]
        member = BusinessMember.objects.filter(
            business=business, user_id=value, statut=BusinessMember.Statut.ACTIF
        ).first()
        if member is None:
            raise serializers.ValidationError("Membre invalide pour ce business.")
        return member.user


# --- Sprint 9 : Alertes performance -----------------------------------------


class PerformanceAlertSerializer(serializers.ModelSerializer):
    """Alerte de performance (Sprint 9)."""

    item_id = serializers.UUIDField(read_only=True, allow_null=True)
    item_nom = serializers.CharField(source="item.nom", read_only=True, allow_null=True)
    resolved_by = UserSerializer(read_only=True)

    class Meta:
        model = PerformanceAlert
        fields = [
            "id", "type", "item_id", "item_nom",
            "seuil", "message", "resolved", "resolved_at", "resolved_by",
            "created_at",
        ]
        read_only_fields = fields


# --- Sprint 4 : Historique avec filtres -------------------------------------


class HistoryFilterSerializer(serializers.Serializer):
    """Filtres pour l'historique global."""

    type = serializers.ChoiceField(
        choices=["task", "stock", "reservation", "decision", "all"],
        required=False, default="all"
    )
    item_id = serializers.UUIDField(required=False)
    acteur_id = serializers.UUIDField(required=False)
    date_from = serializers.DateField(required=False)
    date_to = serializers.DateField(required=False)


class ProcedureUpdateSerializer(serializers.ModelSerializer):
    """Mise à jour d'une procédure avec coût estimé."""

    steps_input = serializers.ListField(
        child=serializers.DictField(), write_only=True, required=False
    )

    class Meta:
        model = Procedure
        fields = ["id", "nom", "description", "est_actif", "cout_estime", "steps_input"]
        read_only_fields = ["id"]


# --- Public Catalog (V1) ------------------------------------------------------


class PublicItemSerializer(serializers.ModelSerializer):
    """Serializer public pour le catalogue (lecture seule, sans auth)."""

    photo_url = serializers.SerializerMethodField()
    category_nom = serializers.CharField(source="category.nom", read_only=True)
    statut = serializers.CharField(read_only=True)
    is_published = serializers.BooleanField(read_only=True)
    characteristics = serializers.JSONField(read_only=True)
    public_description = serializers.SerializerMethodField()

    class Meta:
        model = Item
        fields = [
            "id",
            "nom",
            "reference",
            "public_description",
            "prix",
            "unite",
            "statut",
            "is_published",
            "photo_url",
            "category_nom",
            "characteristics",
            "qr_code",
        ]

    def get_public_description(self, obj):
        # Fallback: si public_description vide, exposer description interne
        # pour ne pas afficher une section vide côté client.
        if obj.public_description and obj.public_description.strip():
            return obj.public_description
        return obj.description or ""

    def get_photo_url(self, obj):
        request = self.context.get("request")
        if obj.photos.exists():
            return request.build_absolute_uri(obj.photos.first().image.url)
        return None


class PublicBusinessSerializer(serializers.ModelSerializer):
    """Serializer public pour les infos business (lecture seule, sans auth)."""

    logo_url = serializers.URLField(read_only=True)

    class Meta:
        model = Business
        fields = [
            "id",
            "slug",
            "nom",
            "public_name",
            "business_type",
            "adresse",
            "telephone",
            "email",
            "logo_url",
            "created_at",
        ]
        read_only_fields = fields


# --- V4 : Facturation ---------------------------------------------------------


class InvoiceSerializer(serializers.ModelSerializer):
    """Serializer pour les factures (équipe)."""

    reservation_id = serializers.UUIDField(source="reservation.id", read_only=True)
    item_nom = serializers.CharField(source="reservation.item.nom", read_only=True)
    pdf_url = serializers.SerializerMethodField()
    generee_par = UserSerializer(read_only=True)
    statut_display = serializers.CharField(source="get_statut_display", read_only=True)
    type_display = serializers.CharField(source="get_type_display", read_only=True)

    class Meta:
        model = Invoice
        fields = [
            "id", "numero", "type", "type_display", "statut", "statut_display",
            "reservation_id", "item_nom",
            "client_nom", "client_email", "client_telephone", "client_adresse",
            "lignes", "sous_total", "tva_taux", "tva_montant", "total_ttc",
            "pdf_url", "generee_le", "envoyee_le", "payee_le", "generee_par",
        ]
        read_only_fields = fields

    def get_pdf_url(self, obj):
        request = self.context.get("request")
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None


class InvoiceCreateSerializer(serializers.Serializer):
    """Création manuelle d'une facture (si besoin)."""

    reservation_id = serializers.UUIDField()
    type = serializers.ChoiceField(choices=Invoice.Type.choices, default=Invoice.Type.PROFORMA)
    tva_taux = serializers.DecimalField(max_digits=4, decimal_places=2, default=0)
    lignes = serializers.ListField(
        child=serializers.DictField(), required=False,
        help_text="[{description, quantite, prix_unitaire}] - auto-rempli depuis réservation si vide"
    )

    def validate_reservation_id(self, value):
        business = self.context["business"]
        reservation = Reservation.objects.filter(id=value, business=business).first()
        if reservation is None:
            raise serializers.ValidationError("Réservation introuvable.")
        if hasattr(reservation, "invoice"):
            raise serializers.ValidationError("Cette réservation a déjà une facture.")
        return reservation


class InvoicePublicSerializer(serializers.ModelSerializer):
    """Serializer public pour téléchargement client (via token)."""

    item_nom = serializers.CharField(source="reservation.item.nom", read_only=True)
    pdf_url = serializers.SerializerMethodField()

    class Meta:
        model = Invoice
        fields = [
            "id", "numero", "type", "statut",
            "client_nom", "client_email",
            "item_nom",
            "lignes", "sous_total", "tva_taux", "tva_montant", "total_ttc",
            "pdf_url", "generee_le",
        ]
        read_only_fields = fields

    def get_pdf_url(self, obj):
        request = self.context.get("request")
        if obj.pdf:
            return request.build_absolute_uri(obj.pdf.url)
        return None
