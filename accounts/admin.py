from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (
    ActivityLog,
    Alert,
    Business,
    BusinessMember,
    BusinessRule,
    Category,
    DecisionLog,
    Inventory,
    InventoryCount,
    Item,
    ItemPhoto,
    MaintenanceTask,
    Notification,
    Permission,
    Procedure,
    ProcedureStep,
    Reservation,
    Role,
    RolePermission,
    StockAdjustment,
    StockMovement,
    TaskStep,
    User,
)


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ("email", "first_name", "last_name", "telephone", "statut", "is_active")
    ordering = ("email",)
    fieldsets = UserAdmin.fieldsets + (("Profil", {"fields": ("telephone", "statut")}),)
    add_fieldsets = UserAdmin.add_fieldsets + (("Profil", {"fields": ("telephone",)}),)


@admin.register(Business)
class BusinessAdmin(admin.ModelAdmin):
    list_display = ("nom", "telephone", "email", "created_by", "created_at")
    readonly_fields = ("id", "created_at")


@admin.register(BusinessMember)
class BusinessMemberAdmin(admin.ModelAdmin):
    list_display = ("user", "business", "role", "statut", "invited_by", "invited_at")
    readonly_fields = ("id", "invited_at")


class RolePermissionInline(admin.TabularInline):
    model = RolePermission
    extra = 0


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("nom", "business", "is_system")
    readonly_fields = ("id", "created_at")
    inlines = [RolePermissionInline]


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("codename", "libelle")


@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ("role", "permission")


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("nom", "business", "parent")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ("nom", "reference", "business", "category", "prix", "statut")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(ItemPhoto)
class ItemPhotoAdmin(admin.ModelAdmin):
    list_display = ("id", "item", "caption", "order", "created_at")
    readonly_fields = ("id", "created_at")


@admin.register(StockMovement)
class StockMovementAdmin(admin.ModelAdmin):
    list_display = ("type", "item", "quantite", "acteur", "reference", "created_at")
    readonly_fields = ("id", "created_at")
    list_filter = ("type",)


class ProcedureStepInline(admin.TabularInline):
    model = ProcedureStep
    extra = 0


@admin.register(Procedure)
class ProcedureAdmin(admin.ModelAdmin):
    list_display = ("nom", "business", "est_actif", "created_at")
    readonly_fields = ("id", "created_at", "updated_at")
    inlines = [ProcedureStepInline]


@admin.register(MaintenanceTask)
class MaintenanceTaskAdmin(admin.ModelAdmin):
    list_display = ("procedure_nom", "item", "business", "statut", "created_at")
    readonly_fields = ("id", "procedure_nom", "created_at", "updated_at")
    list_filter = ("statut",)


@admin.register(TaskStep)
class TaskStepAdmin(admin.ModelAdmin):
    list_display = ("nom", "task", "statut", "started_at", "finished_at")
    readonly_fields = ("id", "started_at", "finished_at")


class InventoryCountInline(admin.TabularInline):
    model = InventoryCount
    extra = 0
    readonly_fields = ("item", "declared_by")


@admin.register(Inventory)
class InventoryAdmin(admin.ModelAdmin):
    list_display = ("libelle", "business", "statut", "created_by", "created_at", "closed_at")
    readonly_fields = ("id", "created_at", "closed_at")
    list_filter = ("statut",)
    inlines = [InventoryCountInline]


@admin.register(StockAdjustment)
class StockAdjustmentAdmin(admin.ModelAdmin):
    list_display = ("item", "ecart", "quantite_theorique", "quantite_comptee",
                    "inventory", "acteur", "created_at")
    readonly_fields = ("id", "created_at")


@admin.register(BusinessRule)
class BusinessRuleAdmin(admin.ModelAdmin):
    list_display = ("code", "business", "mode", "est_actif", "updated_at")
    readonly_fields = ("id", "updated_at")
    list_filter = ("mode", "est_actif")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("code", "item", "business", "mode", "quantite", "created_at")
    readonly_fields = ("id", "created_at")
    list_filter = ("code", "mode")


@admin.register(DecisionLog)
class DecisionLogAdmin(admin.ModelAdmin):
    list_display = ("code", "item", "business", "motif", "quantite", "acteur", "created_at")
    readonly_fields = ("id", "created_at")
    list_filter = ("code",)


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ("action", "acteur", "item", "cible", "business", "created_at")
    readonly_fields = ("id", "created_at")
    list_filter = ("action",)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("code", "user", "business", "lu", "created_at")
    readonly_fields = ("id", "created_at")
    list_filter = ("lu", "code")


@admin.register(Reservation)
class ReservationAdmin(admin.ModelAdmin):
    list_display = (
        "statut", "item", "reserve_par", "date_debut", "date_fin",
        "quantite", "business", "created_at",
    )
    readonly_fields = ("id", "created_at", "updated_at")
    list_filter = ("statut", "business")