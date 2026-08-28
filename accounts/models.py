import uuid

from django import VERSION as DJANGO_VERSION
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """Manager sans username : l'email est l'identifiant (USERNAME_FIELD)."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("L'email est obligatoire")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Utilisateur de la plateforme (US-01)."""

    class Statut(models.TextChoices):
        ACTIF = "ACTIF"
        INACTIF = "INACTIF"

    email = models.EmailField(unique=True)
    telephone = models.CharField(max_length=30, blank=True)
    statut = models.CharField(
        max_length=10, choices=Statut.choices, default=Statut.ACTIF
    )
    google_sub = models.CharField(
        max_length=64, null=True, blank=True, unique=True
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email


class Permission(models.Model):
    """Permission atomique du catalogue RBAC (S 1-01)."""

    codename = models.CharField(max_length=100, unique=True)
    libelle = models.CharField(max_length=150)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["codename"]

    def __str__(self):
        return self.codename


class Business(models.Model):
    """Espace de travail multi-tenant (US-01, RM-01)."""

    class BusinessType(models.TextChoices):
        DECORATION_RENTAL = "DECORATION_RENTAL", "Location & Décoration d'événements"
        GENERAL_INVENTORY = "GENERAL_INVENTORY", "Gestion de Stock Général"
        # Futurs types : CONSTRUCTION, CANTEEN (ajout = simple clé + config rôles)

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nom = models.CharField(max_length=150)
    slug = models.SlugField(max_length=100, unique=True, null=True, blank=True)
    public_name = models.CharField(max_length=150, blank=True)
    business_type = models.CharField(
        max_length=50,
        choices=BusinessType.choices,
        default=BusinessType.DECORATION_RENTAL,
    )
    adresse = models.CharField(max_length=255, blank=True)
    telephone = models.CharField(max_length=30, blank=True)
    email = models.EmailField(blank=True)
    logo_url = models.URLField(blank=True)
    logo = models.ImageField(upload_to="businesses/logos/", blank=True, null=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="created_businesses"
    )
    members = models.ManyToManyField(
        User,
        through="BusinessMember",
        through_fields=("business", "user"),
        related_name="businesses",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.nom


class Role(models.Model):
    """Rôle au sens RM-16 = une responsabilité au sein d'un business."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="roles"
    )
    nom = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(
        Permission, through="RolePermission", related_name="roles", blank=True
    )
    is_system = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["business", "nom"], name="unique_role_per_business"
            )
        ]
        ordering = ["nom"]

    def __str__(self):
        return self.nom


class RolePermission(models.Model):
    """Table de liaison role_permissions (S 1-01, RM-19)."""

    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="role_permissions")
    permission = models.ForeignKey(
        Permission, on_delete=models.CASCADE, related_name="role_permissions"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "permission"], name="unique_role_permission"
            )
        ]


class BusinessMember(models.Model):
    """Membre d'un business avec son rôle et son statut (US-02, US-03).

    Un membership à l'état INVITE est aussi une invitation : il porte un code
    d'invitation (haché, jamais en clair), une date d'expiration et la date
    d'acceptation. CANCELLED = invitation annulée par l'inviteur ; EXPIRED est
    attribué dynamiquement à la validation (le champ statut peut être laissé
    à INVITE avec une expires_at dépassée).
    """

    class Statut(models.TextChoices):
        ACTIF = "ACTIF"
        INVITE = "INVITE"
        BLOQUE = "BLOQUE"
        CANCELLED = "CANCELLED"
        EXPIRED = "EXPIRED"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="memberships"
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="memberships"
    )
    role = models.ForeignKey(
        Role, on_delete=models.PROTECT, related_name="memberships", null=True, blank=True
    )
    statut = models.CharField(
        max_length=10, choices=Statut.choices, default=Statut.INVITE
    )
    invited_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    invited_at = models.DateTimeField(auto_now_add=True)
    code_hash = models.CharField(
        max_length=64, null=True, blank=True, unique=True
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    # Notifications push (Sprint 8 - Phase 5)
    fcm_token = models.CharField(
        max_length=255, null=True, blank=True,
        help_text="Token Firebase Cloud Messaging pour les notifications push"
    )
    device_type = models.CharField(
        max_length=10, null=True, blank=True,
        choices=[("IOS", "iOS"), ("ANDROID", "Android")],
        help_text="Type d'appareil pour les notifications push"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["business", "user"], name="unique_member_per_business"
            )
        ]
        ordering = ["-invited_at"]

    def __str__(self):
        return f"{self.user} @ {self.business}"


# --- Sprint 2 : Catalogue (US-05, US-06, US-07) -----------------------------

MAX_ITEM_PHOTOS = 5


class Category(models.Model):
    """Catégorie du catalogue, toujours rattachée à un business (RM-01)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="categories"
    )
    parent = models.ForeignKey(
        "self", on_delete=models.CASCADE, null=True, blank=True, related_name="children"
    )
    nom = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to="categories/%Y/%m/", blank=True, null=True)
    entretien_requis = models.BooleanField(null=True, blank=True)
    procedure = models.ForeignKey(
        "Procedure", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["business", "nom"], name="unique_category_per_business"
            )
        ]
        ordering = ["nom"]

    def __str__(self):
        return f"{self.nom} ({self.business_id})"


class Item(models.Model):
    """Article du catalogue avec ses caractéristiques (US-06, RM-21)."""

    class Statut(models.TextChoices):
        ACTIF = "ACTIF"
        INACTIF = "INACTIF"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="items"
    )
    category = models.ForeignKey(
        Category, on_delete=models.PROTECT, related_name="items", null=True, blank=True
    )
    nom = models.CharField(max_length=200)
    reference = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField(blank=True)
    public_description = models.TextField(blank=True)
    prix = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    unite = models.CharField(max_length=30, blank=True)
    statut = models.CharField(
        max_length=10, choices=Statut.choices, default=Statut.ACTIF
    )
    is_published = models.BooleanField(default=False)
    characteristics = models.JSONField(default=dict, blank=True)
    entretien_requis = models.BooleanField(
        null=True, blank=True,
        help_text="None = hérite de la catégorie (RM-08).",
    )
    procedure = models.ForeignKey(
        "Procedure", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    # QR Code (Sprint 6 - Phase 2)
    qr_code = models.CharField(
        max_length=100, unique=True, null=True, blank=True,
        help_text="Code QR unique pour identification rapide (auto-généré si vide)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.qr_code:
            self.qr_code = str(uuid.uuid4())
        super().save(*args, **kwargs)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["business", "reference"],
                name="unique_item_reference_per_business",
                condition=models.Q(reference__isnull=False),
            )
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return self.nom


class ItemPhoto(models.Model):
    """Photo d'un article (S 2-03, pluriel pour la fiche article)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    item = models.ForeignKey(
        Item, on_delete=models.CASCADE, related_name="photos"
    )
    image = models.ImageField(upload_to="photos/%Y/%m/")
    caption = models.CharField(max_length=150, blank=True)
    order = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["order", "created_at"]

    def __str__(self):
        return f"photo {self.item_id}"


# --- Sprint 3 : Stock & traçabilité (US-08 à US-12) ------------------------
#
# RM-02 / RM-03 : StockMovement est append-only. Aucun endpoint de
# modification/suppression n'existe : toute variation est un événement
# immuable (auteur, date, référence, motif). Le stock courant est TOUJOURS
# recalculé depuis l'historique (source unique de vérité).
# RM-04 : disponibilité (quantité utilisable) est distincte du total.


class StockMovement(models.Model):
    """Événement de variation de stock : entrée, sortie, retour, perte, dommage."""

    class Type(models.TextChoices):
        ENTREE = "ENTREE", "Entrée"
        SORTIE = "SORTIE", "Sortie"
        RETOUR = "RETOUR", "Retour"
        PERTE = "PERTE", "Perte"
        DOMMAGE = "DOMMAGE", "Dommage"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="stock_movements"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="movements"
    )
    type = models.CharField(max_length=10, choices=Type.choices)
    quantite = models.PositiveIntegerField()
    motif = models.TextField(blank=True)
    reference = models.CharField(max_length=100, blank=True)
    acteur = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="stock_movements"
    )
    related_to = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "item", "created_at"],
                name="idx_mvt_biz_item_date",
            )
        ]

    def __str__(self):
        return f"{self.type} {self.quantite} x {self.item_id}"


# --- Sprint 4 : Entretien (US-13 à US-17) ----------------------------------
#
# RM-08 : un article exige ou non un entretien (héritage catégorie -> article).
# RM-09 : une procédure comporte plusieurs étapes, obligatoires ou non.
# RM-10 : créer une tâche ne rend PAS l'article prêt : l'état réel est
#         dérivé de la dernière tâche clôturée.
# RM-11 : un entretien incomplet est accepté (tâche PARTIELLE) et reste
#         visible ; les tâches et leurs étapes sont conservées (traçabilité).


class Procedure(models.Model):
    """Procédure d'entretien reproductible, propre à un business (RM-09)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="procedures"
    )
    nom = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    est_actif = models.BooleanField(default=True)
    # Coût estimé (Sprint 2 - Traçabilité)
    cout_estime = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True,
        help_text="Coût estimé pour cette procédure"
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["business", "nom"], name="unique_procedure_per_business"
            )
        ]
        ordering = ["nom"]

    def __str__(self):
        return f"{self.nom} ({self.business_id})"


class ProcedureStep(models.Model):
    """Étape d'une procédure d'entretien (RM-09).

    Une étape est une opération (lavage, pliage...) ou un contrôle final.
    L'article n'est « prêt » que si les étapes obligatoires ET les contrôles
    de la dernière tâche sont terminés.
    """

    class Type(models.TextChoices):
        OPERATION = "OPERATION", "Opération"
        CONTROLE = "CONTROLE", "Contrôle"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    procedure = models.ForeignKey(
        Procedure, on_delete=models.CASCADE, related_name="steps"
    )
    nom = models.CharField(max_length=200)
    ordre = models.PositiveIntegerField(default=0)
    obligatoire = models.BooleanField(default=True)
    type = models.CharField(
        max_length=10, choices=Type.choices, default=Type.OPERATION
    )
    description = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["procedure", "nom"], name="unique_procedure_step_name"
            )
        ]
        ordering = ["ordre", "nom"]

    def __str__(self):
        return f"{self.nom} ({self.procedure_id})"


class MaintenanceTask(models.Model):
    """Tâche d'entretien sur un article (US-15, US-16, US-17).

    Les étapes de la procédure sont copiées dans TaskStep au moment de la
    création : une modification ultérieure de la procédure n'altère jamais
    l'historique d'une tâche passée (traçabilité RM-03).
    """

    class Statut(models.TextChoices):
        EN_COURS = "EN_COURS", "En cours"
        PARTIELLE = "PARTIELLE", "Partielle"
        TERMINEE = "TERMINEE", "Terminée"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="maintenance_tasks"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="maintenance_tasks"
    )
    procedure = models.ForeignKey(
        Procedure, on_delete=models.PROTECT, related_name="tasks"
    )
    procedure_nom = models.CharField(max_length=200)
    motif = models.TextField(blank=True)
    statut = models.CharField(
        max_length=10, choices=Statut.choices, default=Statut.EN_COURS
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    # Attribution de la tâche (Sprint 1 - Collaboration)
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="assigned_tasks",
        help_text="Membre assigné à cette tâche"
    )
    assigned_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Date d'assignation de la tâche"
    )
    assigned_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="+",
        help_text="Membre qui a assigné la tâche"
    )
    # Coûts de maintenance (Sprint 2 - Traçabilité)
    cout_main_oeuvre = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True,
        help_text="Coût de la main d'oeuvre"
    )
    cout_materiel = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True,
        help_text="Coût du matériel utilisé"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "item", "created_at"],
                name="idx_task_biz_item_date",
            )
        ]

    def __str__(self):
        return f"tâche {self.procedure_nom} x {self.item_id}"


class TaskStep(models.Model):
    """Copie d'une étape de procédure dans une tâche (US-16, US-17)."""

    class Statut(models.TextChoices):
        EN_ATTENTE = "EN_ATTENTE", "En attente"
        EN_COURS = "EN_COURS", "En cours"
        TERMINE = "TERMINE", "Terminé"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(
        MaintenanceTask, on_delete=models.CASCADE, related_name="steps"
    )
    nom = models.CharField(max_length=200)
    ordre = models.PositiveIntegerField(default=0)
    obligatoire = models.BooleanField(default=True)
    type = models.CharField(max_length=10, choices=ProcedureStep.Type.choices)
    statut = models.CharField(
        max_length=10, choices=Statut.choices, default=Statut.EN_ATTENTE
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    done_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    # Suivi du temps (Sprint 3 - Collaboration)
    duree_estimee = models.DurationField(
        null=True, blank=True,
        help_text="Durée estimée pour cette étape"
    )

    class Meta:
        ordering = ["ordre", "nom"]

    def __str__(self):
        return f"{self.nom} · {self.statut}"

    @property
    def duree_reelle(self):
        """Calcule la durée réelle si l'étape est terminée."""
        if self.started_at and self.finished_at:
            return self.finished_at - self.started_at
        return None


class TaskComment(models.Model):
    """Commentaire sur une tâche de maintenance (Sprint 1 - Collaboration)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(
        MaintenanceTask, on_delete=models.CASCADE, related_name="comments"
    )
    auteur = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="task_comments"
    )
    contenu = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Commentaire de {self.auteur_id} sur {self.task_id}"


class TaskStepPhoto(models.Model):
    """Photo attachée à une étape de tâche (Sprint 2 - Traçabilité).

    Permet de documenter l'état avant/après d'une opération de maintenance.
    """

    class Type(models.TextChoices):
        AVANT = "AVANT", "Avant"
        APRES = "APRES", "Après"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    step = models.ForeignKey(
        TaskStep, on_delete=models.CASCADE, related_name="photos"
    )
    image = models.ImageField(upload_to="task_photos/%Y/%m/")
    type = models.CharField(max_length=5, choices=Type.choices)
    caption = models.CharField(max_length=150, blank=True)
    uploaded_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Photo {self.type} - {self.step_id}"


# --- Sprint 5 : Disponibilité & fiabilité (US-18, US-22 à US-26) -----------
#
# RM-12 : une donnée « à vérifier » est identifiée comme telle et n'est pas
#         présentée comme certaine.
# RM-13 : un écart entre le théorique et le physique est un ÉVÉNEMENT
#         (StockAdjustment immuable, sans endpoint de modification).
# RM-14 : un comptage déclaré n'est pas vérifié tant qu'il n'est pas CERTAIN.
# RM-15 : une donnée estimée (ESTIME) n'est jamais présentée comme certaine.


class Inventory(models.Model):
    """Inventaire physique : lancement, comptages, clôture (US-22, US-23)."""

    class Statut(models.TextChoices):
        EN_COURS = "EN_COURS", "En cours"
        CLOTURE = "CLOTURE", "Clôturé"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="inventories"
    )
    libelle = models.CharField(max_length=200, blank=True)
    statut = models.CharField(
        max_length=10, choices=Statut.choices, default=Statut.EN_COURS
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"Inventaire {self.libelle or self.id} ({self.statut})"


class InventoryCount(models.Model):
    """Comptage physique d'un article lors d'un inventaire (US-22).

    Le comptage capture le stock théorique au moment de la saisie : l'écart
    est donc toujours calculable, même si du stock bouge ensuite (RM-13).
    """

    class Fiabilite(models.TextChoices):
        CERTAIN = "CERTAIN", "Certain"
        ESTIME = "ESTIME", "Estimé"
        NON_VERIFIE = "NON_VERIFIE", "Non vérifié"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    inventory = models.ForeignKey(
        Inventory, on_delete=models.CASCADE, related_name="counts"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="inventory_counts"
    )
    quantite_theorique = models.IntegerField()
    quantite_comptee = models.PositiveIntegerField()
    fiabilite = models.CharField(
        max_length=12, choices=Fiabilite.choices, default=Fiabilite.NON_VERIFIE
    )
    declared_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    declared_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["inventory", "item"], name="unique_count_per_inventory_item"
            )
        ]
        ordering = ["declared_at", "id"]

    @property
    def ecart(self):
        return self.quantite_comptee - self.quantite_theorique

    def __str__(self):
        return f"comptage {self.quantite_comptee} x {self.item_id}"


class StockAdjustment(models.Model):
    """Ajustement de stock — événement immuable (RM-13, US-24, US-26).

    Un écart d'inventaire devient un StockAdjustment à la clôture ; un
    ajustement manuel est aussi possible. L'ancien contexte (théorique,
    compté) est conservé : l'écart est toujours expliquable (RM-13).
    Aucun endpoint de modification/suppression n'existe.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="adjustments"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="adjustments"
    )
    inventory = models.ForeignKey(
        Inventory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="adjustments",
    )
    quantite_theorique = models.IntegerField()
    quantite_comptee = models.IntegerField()
    ecart = models.IntegerField()
    motif = models.TextField(blank=True)
    reference = models.CharField(max_length=100, blank=True)
    acteur = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="adjustments"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "item", "created_at"],
                name="idx_adj_biz_item_date",
            )
        ]

    def __str__(self):
        return f"ajustement {self.ecart:+d} x {self.item_id}"


# --- Sprint 6 : Alertes, décisions & exceptions (US-19, US-20, US-21) ------
#
# RM-05 : l'entretien n'interdit pas automatiquement l'utilisation : une
#         règle configurable décide d'avertir ou de bloquer.
# RM-06 : une décision exceptionnelle est traçable (qui, quand, quoi, motif).
# RM-07 : les règles métier sont configurables par business.
# RM-22 : Informer -> Avertir -> Décider -> Tracer. Un blocage est obligatoire
#         (aucun contournement) ; un avertissement peut être « utilisé quand
#         même » par un utilisateur autorisé, moyennant décision tracée.
#         Après la décision, le problème reste visible (état non masqué).


class BusinessRule(models.Model):
    """Règle métier configurable par business (RM-07, S 6-05).

    Une règle AVERTISSEMENT peut être dépassée (avec permission et décision
    tracée) ; une règle BLOCAGE est obligatoire : la demande est refusée.
    Les règles par défaut sont créées à la création du business.
    """

    class Code(models.TextChoices):
        ARTICLE_EN_ENTRETIEN = "ARTICLE_EN_ENTRETIEN", "Sortir un article en entretien"
        ENTRETIEN_PARTIEL = "ENTRETIEN_PARTIEL", "Sortir un article à l'entretien partiel"
        ARTICLE_A_VERIFIER = "ARTICLE_A_VERIFIER", "Sortir un article à vérifier"

    class Mode(models.TextChoices):
        AVERTISSEMENT = "AVERTISSEMENT", "Avertissement"
        BLOCAGE = "BLOCAGE", "Blocage"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="rules"
    )
    code = models.CharField(max_length=40, choices=Code.choices)
    mode = models.CharField(
        max_length=15, choices=Mode.choices, default=Mode.AVERTISSEMENT
    )
    est_actif = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["business", "code"], name="unique_rule_per_business"
            )
        ]
        ordering = ["code"]

    def __str__(self):
        return f"{self.code} ({self.mode}) @ {self.business_id}"


class Alert(models.Model):
    """Avertissement émis lors d'une opération (US-19, RM-22 « Avertir »).

    L'alerte est persistée et jamais masquée après une décision : le
    problème reste visible tant qu'il existe (critère d'acceptation).
    Aucun endpoint de modification/suppression n'existe.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="alerts"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="alerts"
    )
    rule = models.ForeignKey(
        BusinessRule, on_delete=models.PROTECT, related_name="alerts"
    )
    code = models.CharField(max_length=40)
    mode = models.CharField(max_length=15, choices=BusinessRule.Mode.choices)
    message = models.TextField()
    quantite = models.PositiveIntegerField(null=True, blank=True)
    mouvement = models.ForeignKey(
        StockMovement,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="alerts",
    )
    acteur = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "item", "created_at"],
                name="idx_alert_biz_item_date",
            )
        ]

    def __str__(self):
        return f"alerte {self.code} x {self.item_id}"


class DecisionLog(models.Model):
    """Décision exceptionnelle tracée (US-21, RM-06, RM-22 « Décider/Tracer »).

    Qui (acteur), quand (created_at), quoi (code, item, quantité) et pourquoi
    (motif obligatoire). Immuable : aucun endpoint de modification/suppression.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="decisions"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="decisions"
    )
    rule = models.ForeignKey(
        BusinessRule, on_delete=models.PROTECT, related_name="decisions"
    )
    code = models.CharField(max_length=40)
    motif = models.TextField()
    quantite = models.PositiveIntegerField(null=True, blank=True)
    mouvement = models.ForeignKey(
        StockMovement,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="decisions",
    )
    acteur = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="decisions"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "item", "created_at"],
                name="idx_dec_biz_item_date",
            )
        ]

    def __str__(self):
        return f"décision {self.code} x {self.item_id}"


# --- Sprint 7 : Collaboration & visibilité (US-27, US-28) ------------------
#
# RM-20 : l'activité de l'équipe est visible (qui a fait quoi, quand).
# RM-18 : équipe légère ; RM-01 / RM-21 : tout reste isolé par business.
# Le flux d'activité est un journal immuable (append-only, comme RM-02/03).


class ActivityLog(models.Model):
    """Événement du flux d'activité de l'équipe (US-27, S 7-01/03).

    Un événement est immuable : créé au fil des opérations métier, jamais
    modifié ni supprimé. L'acteur est conservé (RM-20, traçabilité).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="activities"
    )
    acteur = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="activities"
    )
    action = models.CharField(max_length=60)
    item = models.ForeignKey(
        Item, on_delete=models.SET_NULL, null=True, blank=True, related_name="activities"
    )
    cible = models.CharField(max_length=200, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "created_at"], name="idx_act_biz_date"
            ),
            models.Index(
                fields=["business", "item", "created_at"], name="idx_act_biz_item_date"
            ),
        ]

    def __str__(self):
        return f"{self.action} par {self.acteur_id} @ {self.business_id}"


class Notification(models.Model):
    """Notification destinée à un membre du business (US-28, S 7-08).

    Chaque membre reçoit SA propre notification (qui, quand, lue ou non) ;
    rien n'est visible en dehors du business (RM-01, RM-21).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="notifications"
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="notifications"
    )
    code = models.CharField(max_length=60)
    message = models.TextField()
    item = models.ForeignKey(
        Item, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    lu = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "user", "created_at"], name="idx_notif_biz_user_date"
            )
        ]

    def __str__(self):
        return f"{self.code} -> {self.user_id}"


def _check_constraint(condition, name):
    """CheckConstraint compatible Django >= 4.2 et >= 5.1.

    Django 4.2 attend `check=` ; Django 5.1+ l'a renommé `condition=` (et
    supprimé l'ancien). On ne peut pas passer le même mot-clé sur les deux.
    """
    if DJANGO_VERSION >= (5, 1):
        return models.CheckConstraint(condition=condition, name=name)
    return models.CheckConstraint(check=condition, name=name)


class Reservation(models.Model):
    """Réservation d'un article par un membre (Sprint 8, US-29 à US-31).

    Cycle de vie : EN_ATTENTE -> VALIDEE -> EN_COURS -> TERMINEE.
    L'annulation est possible sur EN_ATTENTE et VALIDEE.
    Le démarrage d'une réservation crée une sortie de stock,
    sa terminaison crée le retour (US-31).
    
    Traçabilité livraison/reprise : lieu, contact, horodatages, acteur.
    """

    class Statut(models.TextChoices):
        EN_ATTENTE = "EN_ATTENTE", "En attente de validation"
        VALIDEE = "VALIDEE", "Validée"
        EN_COURS = "EN_COURS", "En cours"
        TERMINEE = "TERMINEE", "Terminée"
        ANNULEE = "ANNULEE", "Annulée"

    class StatutLivraison(models.TextChoices):
        EN_ATTENTE = "EN_ATTENTE", "En attente de livraison"
        LIVREE = "LIVREE", "Livrée"
        REPRISE = "REPRISE", "Reprise (retour client)"
        RETOURNEE = "RETOURNEE", "Retournée au dépôt"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="reservations"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="reservations"
    )
    reserve_par = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="reservations"
    )
    date_debut = models.DateField()
    date_fin = models.DateField()
    quantite = models.PositiveIntegerField(default=1)
    motif = models.TextField(blank=True)
    # --- Localisation & traçabilité livraison/reprise ---
    lieu_nom = models.CharField(max_length=200, blank=True, help_text="Nom du lieu (ex: Salle des fêtes, Hôtel XYZ)")
    lieu_adresse = models.TextField(blank=True, help_text="Adresse complète de livraison/reprise")
    lieu_lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, help_text="Latitude GPS")
    lieu_lng = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, help_text="Longitude GPS")
    contact_nom = models.CharField(max_length=150, blank=True, help_text="Personne contact sur place")
    contact_telephone = models.CharField(max_length=30, blank=True, help_text="Téléphone contact sur place")
    livraison_prevue_le = models.DateTimeField(null=True, blank=True, help_text="Date/heure prévue de livraison")
    livraison_effectuee_le = models.DateTimeField(null=True, blank=True, help_text="Date/heure réelle de livraison")
    livreur = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="livraisons_effectuees",
        help_text="Membre qui a effectué la livraison"
    )
    reprise_prevue_le = models.DateTimeField(null=True, blank=True, help_text="Date/heure prévue de reprise")
    reprise_effectuee_le = models.DateTimeField(null=True, blank=True, help_text="Date/heure réelle de reprise")
    reprise_par = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="reprises_effectuees",
        help_text="Membre qui a effectué la reprise"
    )
    statut_livraison = models.CharField(
        max_length=15, choices=StatutLivraison.choices, default=StatutLivraison.EN_ATTENTE
    )
    notes_livraison = models.TextField(blank=True, help_text="Instructions : étage, code porte, accès, etc.")
    # --- Contrôle retour (existant) ---
    quantite_retournee = models.PositiveIntegerField(
        blank=True, null=True, help_text="Unités rendues en bon état (contrôle de retour)."
    )
    quantite_abimee = models.PositiveIntegerField(
        blank=True, null=True, help_text="Unités rendues abîmées (contrôle de retour)."
    )
    quantite_perdue = models.PositiveIntegerField(
        blank=True, null=True, help_text="Unités perdues pendant la location."
    )
    observations = models.TextField(blank=True, default="")
    retourne_le = models.DateTimeField(
        blank=True, null=True, help_text="Moment du retour effectif au dépôt."
    )
    statut = models.CharField(
        max_length=15, choices=Statut.choices, default=Statut.EN_ATTENTE
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            _check_constraint(
                models.Q(date_fin__gte=models.F("date_debut")),
                name="reservation_dates_coherentes",
            )
        ]
        indexes = [
            models.Index(
                fields=["business", "created_at"], name="idx_res_biz_date"
            ),
            models.Index(
                fields=["business", "item", "date_debut"], name="idx_res_biz_item_debut"
            ),
        ]

    def __str__(self):
        return f"{self.statut} {self.quantite} x {self.item_id}"


# --- V2 : Demande de location client (Booking Request) ------------------------


class BookingRequest(models.Model):
    """Demande de location d'un client externe (V2).

    Parcours : EN_ATTENTE -> ACCEPTEE/REFUSEE -> CONVERTIE (Reservation)
    Accès client via token magique (sans compte utilisateur).
    """

    class Statut(models.TextChoices):
        DRAFT = "DRAFT", "Brouillon"
        EN_ATTENTE = "EN_ATTENTE", "En attente de traitement"
        ACCEPTEE = "ACCEPTEE", "Acceptée par l'équipe"
        REFUSEE = "REFUSEE", "Refusée"
        EXPIREE = "EXPIREE", "Expirée (pas de réponse)"
        ANNULEE_CLIENT = "ANNULEE_CLIENT", "Annulée par le client"
        CONVERTIE = "CONVERTIE", "Transformée en réservation"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="booking_requests"
    )
    item = models.ForeignKey(
        Item, on_delete=models.PROTECT, related_name="booking_requests"
    )

    # Client externe (pas d'User requis)
    client_nom = models.CharField(max_length=150)
    client_telephone = models.CharField(max_length=30)
    client_email = models.EmailField()

    date_debut = models.DateField()
    date_fin = models.DateField()
    quantite = models.PositiveIntegerField(default=1)
    message = models.TextField(blank=True, help_text="Message du client (besoin, occasion, etc.)")

    # Localisation (optionnel, pré-rempli si dispo)
    lieu_nom = models.CharField(max_length=200, blank=True)
    lieu_adresse = models.TextField(blank=True)
    contact_nom = models.CharField(max_length=150, blank=True)
    contact_telephone = models.CharField(max_length=30, blank=True)
    notes_livraison = models.TextField(blank=True)

    # Traitement équipe
    statut = models.CharField(
        max_length=20, choices=Statut.choices, default=Statut.EN_ATTENTE
    )
    traite_par = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="booking_requests_traitees"
    )
    traite_le = models.DateTimeField(null=True, blank=True)
    motif_refus = models.TextField(blank=True)
    contre_proposition = models.JSONField(
        null=True, blank=True,
        help_text="Contre-proposition : {date_debut, date_fin, quantite, prix, message}"
    )

    # Lien vers réservation créée
    reservation_creee = models.ForeignKey(
        Reservation, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="booking_request_origine"
    )

    # Token magique pour lien client (accès sans auth)
    access_token = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(help_text="Expiration du token d'accès (7 jours)")

    # Mémoire client : identification anonyme + idempotence
    visitor_id = models.CharField(max_length=64, blank=True, db_index=True, help_text="Identifiant anonyme du navigateur")
    idempotency_key = models.CharField(max_length=100, blank=True, db_index=True, help_text="Clé d'idempotence pour éviter les doublons")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(
                fields=["business", "statut", "created_at"], name="idx_br_biz_statut_date"
            ),
            models.Index(
                fields=["business", "item", "created_at"], name="idx_br_biz_item_date"
            ),
            models.Index(
                fields=["access_token"], name="idx_br_token"
            ),
            models.Index(fields=["visitor_id"], name="idx_br_visitor"),
            models.Index(fields=["idempotency_key"], name="idx_br_idem"),
            models.Index(
                fields=["business", "visitor_id", "statut"], name="idx_br_biz_vis_statut"
            ),
        ]

    def __str__(self):
        return f"{self.statut} {self.client_nom} - {self.item_id}"

    def save(self, *args, **kwargs):
        if not self.access_token:
            self.access_token = uuid.uuid4().hex
        if not self.expires_at:
            from django.utils import timezone
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at

    @property
    def can_client_cancel(self):
        return self.statut in (self.Statut.EN_ATTENTE, self.Statut.ACCEPTEE)

    @property
    def can_team_process(self):
        return self.statut == self.Statut.EN_ATTENTE


# --- Sprint 3 : Planification & Rappels (Phase 1 - Productivité) -----------

class RecurringTask(models.Model):
    """Tâche récurrente programmée (Sprint 3 - Planification périodique).

    Permet de planifier des maintenances périodiques (quotidiennes, hebdomadaires,
    mensuelles ou personnalisées) sur un article ou une catégorie entière.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="recurring_tasks"
    )
    item = models.ForeignKey(
        Item, on_delete=models.CASCADE, null=True, blank=True,
        related_name="recurring_tasks",
        help_text="Article spécifique (null = tous les articles de la catégorie)"
    )
    category = models.ForeignKey(
        Category, on_delete=models.CASCADE, null=True, blank=True,
        related_name="recurring_tasks",
        help_text="Catégorie (si item est null)"
    )
    procedure = models.ForeignKey(
        Procedure, on_delete=models.CASCADE, related_name="recurring_tasks"
    )
    frequence_jours = models.PositiveIntegerField(
        default=7,
        help_text="Fréquence en jours (7 = hebdomadaire, 30 = mensuel)"
    )
    prochaine_execution = models.DateField(
        help_text="Date de la prochaine exécution prévue"
    )
    est_actif = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["prochaine_execution"]
        indexes = [
            models.Index(
                fields=["business", "prochaine_execution"],
                name="idx_recurring_biz_next"
            )
        ]

    def __str__(self):
        cible = self.item or self.category
        return f"Récurrence {self.frequence_jours}j - {self.procedure.nom} sur {cible}"


class Reminder(models.Model):
    """Rappel programmé pour une tâche ou un article (Sprint 3 - Rappels).

    Permet de configurer un rappel qui sera envoyé via notification push
    à la date et heure spécifiées.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="reminders"
    )
    task = models.ForeignKey(
        MaintenanceTask, on_delete=models.CASCADE, null=True, blank=True,
        related_name="reminders",
        help_text="Tâche associée (optionnel)"
    )
    item = models.ForeignKey(
        Item, on_delete=models.CASCADE, null=True, blank=True,
        related_name="reminders",
        help_text="Article associé (optionnel)"
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="reminders",
        help_text="Destinataire du rappel"
    )
    rappel_a = models.DateTimeField(
        help_text="Date et heure du rappel"
    )
    message = models.CharField(max_length=255)
    envoye = models.BooleanField(
        default=False,
        help_text="Le rappel a-t-il été envoyé"
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["rappel_a"]
        indexes = [
            models.Index(
                fields=["business", "rappel_a", "envoye"],
                name="idx_reminder_biz_time"
            )
        ]

    def __str__(self):
        return f"Rappel {self.message[:30]} -> {self.user_id}"


# --- Sprint 9 : Alertes performance (Phase 4 - Analytics) ------------------

class PerformanceAlert(models.Model):
    """Alerte de performance détectée automatiquement (Sprint 9).

    Identifie les articles problématiques : entretien trop fréquent,
    durée anormale, faible taux de complétion.
    """

    class Type(models.TextChoices):
        FREQUENT_MAINTENANCE = "FREQUENT_MAINTENANCE", "Entretien trop fréquent"
        LONG_DURATION = "LONG_DURATION", "Durée anormale"
        LOW_COMPLETION = "LOW_COMPLETION", "Taux de complétion faible"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="performance_alerts"
    )
    type = models.CharField(max_length=25, choices=Type.choices)
    item = models.ForeignKey(
        Item, on_delete=models.CASCADE, null=True, blank=True,
        related_name="performance_alerts"
    )
    seuil = models.JSONField(
        default=dict,
        help_text="Configuration du seuil qui a déclenché l'alerte"
    )
    message = models.TextField()
    resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["business", "resolved", "created_at"],
                name="idx_perf_alert_biz_resolved"
            )
        ]

    def __str__(self):
        return f"Alerte {self.type} - {self.item_id or 'global'}"

class IdempotencyRecord(models.Model):
    """Réponse mémorisée d'une mutation portant un en-tête ``Idempotency-Key``.

    Support de l'architecture Offline-First côté serveur : un client qui rejoue
    une opération après une réponse perdue doit retrouver le **résultat de la
    première tentative**, pas créer un doublon. Voir ``accounts.idempotency``.

    La clé seule ne suffit pas comme identité : elle est cloisonnée par
    utilisateur, pour qu'un appareil ne puisse ni lire ni écraser la réponse
    d'un autre compte.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(max_length=200)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="idempotency_records",
    )
    # Empreinte de la requête : détecte une clé réutilisée pour une autre
    # opération, cas où rejouer la réponse d'origine serait faux.
    request_fingerprint = models.CharField(max_length=64)
    status_code = models.PositiveSmallIntegerField()
    response_body = models.TextField(blank=True)
    content_type = models.CharField(max_length=100, default="application/json")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["key", "user"], name="uniq_idempotency_key_user"
            )
        ]
        indexes = [
            models.Index(fields=["created_at"], name="idx_idem_created"),
        ]

    def is_expired(self):
        from .idempotency import RETENTION

        return timezone.now() - self.created_at > RETENTION

    def __str__(self):
        return f"{self.key} -> {self.status_code}"


# --- V4 : Facturation ---------------------------------------------------------


class Invoice(models.Model):
    """Facture (proforma ou définitive) liée à une réservation.

    Numérotation séquentielle par business : FAC-2026-0001, FAC-2026-0002...
    PDF généré automatiquement et stocké.
    """

    class Statut(models.TextChoices):
        BROUILLON = "BROUILLON", "Brouillon"
        PROFORMA = "PROFORMA", "Proforma"
        DEFINITIVE = "DEFINITIVE", "Définitive"
        PAYEE = "PAYEE", "Payée"
        ANNULEE = "ANNULEE", "Annulée"

    class Type(models.TextChoices):
        PROFORMA = "PROFORMA", "Proforma (à la validation réservation)"
        DEFINITIVE = "DEFINITIVE", "Définitive (à la fin réservation)"
        AVOIR = "AVOIR", "Avoir (remboursement/annulation)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="invoices"
    )
    reservation = models.OneToOneField(
        Reservation, on_delete=models.PROTECT, related_name="invoice"
    )

    numero = models.CharField(max_length=30, editable=False)
    type = models.CharField(max_length=15, choices=Type.choices, default=Type.PROFORMA)
    statut = models.CharField(max_length=15, choices=Statut.choices, default=Statut.BROUILLON)

    # Infos client (figées à la génération)
    client_nom = models.CharField(max_length=150)
    client_email = models.EmailField(blank=True)
    client_telephone = models.CharField(max_length=30, blank=True)
    client_adresse = models.TextField(blank=True)

    # Lignes de facture (JSON)
    lignes = models.JSONField(default=list, help_text="[{description, quantite, prix_unitaire, total}]")

    # Montants
    sous_total = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    tva_taux = models.DecimalField(max_digits=4, decimal_places=2, default=0, help_text="Ex: 18.00 pour 18%")
    tva_montant = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_ttc = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    # PDF généré
    pdf = models.FileField(upload_to="invoices/%Y/%m/", blank=True, null=True)

    # Dates
    generee_le = models.DateTimeField(auto_now_add=True)
    envoyee_le = models.DateTimeField(null=True, blank=True)
    payee_le = models.DateTimeField(null=True, blank=True)

    # Généré par
    generee_par = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        ordering = ["-generee_le"]
        indexes = [
            models.Index(fields=["business", "numero"], name="idx_inv_biz_num"),
            models.Index(fields=["business", "statut"], name="idx_inv_biz_statut"),
        ]
        constraints = [
            models.UniqueConstraint(fields=["business", "numero"], name="uniq_invoice_business_numero")
        ]

    def __str__(self):
        return f"{self.numero} ({self.statut})"

    def save(self, *args, **kwargs):
        from django.db import IntegrityError, transaction

        if not self.numero:
            # Tentative avec retry en cas de race sur le numéro séquentiel
            for attempt in range(3):
                if attempt > 0:
                    # Régénère un nouveau numéro après un conflit
                    self.numero = self._generer_numero()
                else:
                    self.numero = self._generer_numero()
                try:
                    with transaction.atomic():
                        return super().save(*args, **kwargs)
                except IntegrityError as e:
                    # Conflit sur (business, numero) ou (numero) unique legacy
                    if "numero" in str(e) or "uniq_invoice" in str(e) or "accounts_invoice_numero_key" in str(e):
                        if attempt == 2:
                            raise
                        continue
                    raise
            return

        super().save(*args, **kwargs)

    def _generer_numero(self):
        """Génère le numéro séquentiel : FAC-YYYY-NNNN"""
        from django.db.models import Max
        from django.utils import timezone
        year = timezone.now().year
        prefix = f"FAC-{year}-"
        last = Invoice.objects.filter(business=self.business, numero__startswith=prefix).aggregate(
            max_num=Max("numero")
        )["max_num"]
        if last:
            try:
                seq = int(last.split("-")[-1]) + 1
            except ValueError:
                seq = 1
        else:
            seq = 1
        return f"{prefix}{seq:04d}"

    def calculer_montants(self):
        """Recalcule sous_total, tva_montant, total_ttc depuis les lignes."""
        from decimal import Decimal
        self.sous_total = sum(Decimal(str(l.get("total", 0))) for l in self.lignes)
        self.tva_montant = (self.sous_total * Decimal(str(self.tva_taux)) / Decimal("100")).quantize(Decimal("0.01"))
        self.total_ttc = (self.sous_total + self.tva_montant).quantize(Decimal("0.01"))

    def generer_pdf(self):
        """Génère le PDF de la facture (à implémenter avec weasyprint/reportlab)."""
        # TODO: implémenter avec weasyprint
        pass

    def marquer_envoyee(self):
        self.envoyee_le = timezone.now()
        self.save(update_fields=["envoyee_le"])

    def marquer_payee(self):
        self.statut = self.Statut.PAYEE
        self.payee_le = timezone.now()
        self.save(update_fields=["statut", "payee_le"])


def generate_business_slug(sender, instance, created, **kwargs):
    if created and not instance.slug:
        base = slugify(instance.nom)
        unique_suffix = uuid.uuid4().hex[:6]
        instance.slug = f"{base}-{unique_suffix}"
        instance.save(update_fields=["slug"])


from django.db.models.signals import post_save
from django.utils.text import slugify

post_save.connect(generate_business_slug, sender=Business)
