import base64
import io
import uuid as uuidlib
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from .models import (
    ActivityLog,
    Alert,
    Business,
    BusinessMember,
    BusinessRule,
    Category,
    DecisionLog,
    InventoryCount,
    Item,
    ItemPhoto,
    MaintenanceTask,
    Notification,
    Reservation,
    StockAdjustment,
    StockMovement,
    TaskStep,
)
from .fiabilite import a_verifier
from .ai import GeminiError
from .rbac import PERMISSIONS_CATALOG, Perm, RoleNom, seed_default_roles

User = get_user_model()

PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
    "AAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def register(client, email, password="motdepasse123"):
    return client.post(
        "/api/auth/register/",
        {"email": email, "password": password, "first_name": "Test"},
        format="json",
    )


def login_and_token(client, email, password="motdepasse123"):
    resp = client.post(
        "/api/auth/login/", {"email": email, "password": password}, format="json"
    )
    return resp.data["access"]


def make_business(client, token, nom="Business Test"):
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client.post("/api/businesses/", {"nom": nom}, format="json")


class BaseSetup(APITestCase):
    def setUp(self):
        self.user_a, self.token_a, self.user_b, self.token_b = self._setup()

    def _results(self, resp):
        return resp.data["results"]

    def _setup(self):
        register(self.client, "alice@demo.com")
        register(self.client, "bob@demo.com")
        token_a = login_and_token(self.client, "alice@demo.com")
        token_b = login_and_token(self.client, "bob@demo.com")
        return (
            User.objects.get(email="alice@demo.com"),
            token_a,
            User.objects.get(email="bob@demo.com"),
            token_b,
        )


class AuthTests(BaseSetup):
    def test_register_returns_tokens_and_user(self):
        resp = register(self.client, "carol@demo.com")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("access", resp.data)
        self.assertIn("refresh", resp.data)
        self.assertEqual(resp.data["user"]["email"], "carol@demo.com")
        self.assertTrue(User.objects.filter(email="carol@demo.com").exists())

    def test_register_duplicate_email_fails(self):
        resp = register(self.client, "alice@demo.com")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_with_email_succeeds(self):
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "alice@demo.com", "password": "motdepasse123"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("access", resp.data)
        self.assertIn("refresh", resp.data)

    def test_login_wrong_password_fails(self):
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "alice@demo.com", "password": "mauvais"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_account_requires_auth(self):
        self.client.credentials()
        resp = self.client.delete("/api/auth/me/")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_account_without_business(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.delete("/api/auth/me/")
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(email="alice@demo.com").exists())
        login = self.client.post(
            "/api/auth/login/",
            {"email": "alice@demo.com", "password": "motdepasse123"},
            format="json",
        )
        self.assertEqual(login.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_account_removes_sole_owned_business(self):
        business = make_business(self.client, self.token_a, "Agence Alpha").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.delete("/api/auth/me/")
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(email="alice@demo.com").exists())
        self.assertFalse(Business.objects.filter(id=business["id"]).exists())

    def test_delete_account_keeps_shared_business_and_other_users(self):
        business = make_business(self.client, self.token_a, "Agence Alpha").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        headers = {"HTTP_X_BUSINESS_ID": str(business["id"])}
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **headers
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]},
            format="json",
            **headers,
        ).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        accept = self.client.post(
            f"/api/businesses/{business['id']}/members/{invite['id']}/accept/",
            **headers,
        )
        self.assertEqual(accept.status_code, status.HTTP_200_OK)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.delete("/api/auth/me/")
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(email="alice@demo.com").exists())
        self.assertTrue(User.objects.filter(email="bob@demo.com").exists())
        saved = Business.objects.get(id=business["id"])
        self.assertEqual(saved.created_by_id, self.user_b.id)
        self.assertFalse(
            BusinessMember.objects.filter(
                business_id=business["id"], user=self.user_a
            ).exists()
        )


class BusinessTests(BaseSetup):
    def test_create_business_makes_owner(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        business = Business.objects.get(id=resp.data["id"])
        membership = BusinessMember.objects.get(user=self.user_a, business=business)
        self.assertEqual(membership.role.nom, RoleNom.OWNER)
        self.assertEqual(membership.statut, BusinessMember.Statut.ACTIF)

    def test_create_business_seeds_default_roles(self):
        resp = make_business(self.client, self.token_a)
        business = Business.objects.get(id=resp.data["id"])
        noms = set(business.roles.values_list("nom", flat=True))
        self.assertEqual(
            noms,
            {RoleNom.OWNER, RoleNom.ADMIN, RoleNom.MEMBER, "GESTIONNAIRE"},
        )
        for role in business.roles.all():
            self.assertTrue(role.is_system)
            self.assertTrue(role.permissions.exists())

    def test_business_type_saved_and_serialized(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.assertEqual(resp.data["business_type"], Business.BusinessType.DECORATION_RENTAL)
        saved = Business.objects.get(id=resp.data["id"])
        self.assertEqual(saved.business_type, Business.BusinessType.DECORATION_RENTAL)

    def test_business_type_general_inventory_keeps_light_roles(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.post(
            "/api/businesses/",
            {"nom": "Depot Central", "business_type": Business.BusinessType.GENERAL_INVENTORY},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        business = Business.objects.get(id=resp.data["id"])
        noms = set(business.roles.values_list("nom", flat=True))
        self.assertEqual(noms, {RoleNom.OWNER, RoleNom.ADMIN, RoleNom.MEMBER})

    def test_invalid_business_type_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.post(
            "/api/businesses/",
            {"nom": "Agence Alpha", "business_type": "EXTRA_HACK"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_business_types_catalog_is_closed_list(self):
        resp = self.client.get("/api/business-types/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        codes = [t["codename"] for t in self._results(resp)]
        self.assertEqual(
            codes, [Business.BusinessType.DECORATION_RENTAL, Business.BusinessType.GENERAL_INVENTORY]
        )
        labels = {t["codename"]: t["libelle"] for t in self._results(resp)}
        self.assertIn("Location & Décoration d'événements", labels.values())

    def test_business_creation_is_atomic(self):
        """Si la création des rôles échoue, aucun business ne doit rester en base."""
        from unittest import mock

        with mock.patch(
            "accounts.views.seed_default_roles", side_effect=Exception("boom")
        ):
            self.client.raise_request_exception = False
            resp = make_business(self.client, self.token_a, "Agence Alpha")
            self.client.raise_request_exception = True
        self.assertEqual(resp.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(Business.objects.count(), 0)

    def test_me_lists_businesses_with_role(self):
        make_business(self.client, self.token_a, "Agence Alpha")
        resp = self.client.get("/api/auth/me/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["businesses"][0]["role"], RoleNom.OWNER)
        self.assertEqual(resp.data["businesses"][0]["statut"], BusinessMember.Statut.ACTIF)

    def test_business_list_only_returns_mine(self):
        make_business(self.client, self.token_a, "Agence Alpha")
        make_business(self.client, self.token_b, "Societe Beta")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.get("/api/businesses/")
        self.assertEqual(len(self._results(resp)), 1)
        self.assertEqual(self._results(resp)[0]["nom"], "Agence Alpha")


class IsolationTests(BaseSetup):
    def test_rm01_user_b_cannot_see_business_a_data(self):
        business_a = make_business(self.client, self.token_a, "Agence Alpha").data
        business_b = make_business(self.client, self.token_b, "Societe Beta").data

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        headers_a = {"HTTP_X_BUSINESS_ID": str(business_a["id"])}
        resp = self.client.get(
            f"/api/businesses/{business_a['id']}/members/", **headers_a
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.json(), {"detail": "Accès refusé : business invalide ou permission manquante."})

        resp = self.client.get(
            f"/api/businesses/{business_b['id']}/members/",
            HTTP_X_BUSINESS_ID=str(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(self._results(resp)), 1)

    def test_rm01_missing_header_denied(self):
        business_a = make_business(self.client, self.token_a, "Agence Alpha").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.get(f"/api/businesses/{business_a['id']}/members/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_rm01_role_detail_scoped_to_business(self):
        business_a = make_business(self.client, self.token_a, "Agence Alpha").data
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.get(
            f"/api/businesses/{business_b['id']}/roles/{business_b and '00000000-0000-0000-0000-000000000000'}/",
            HTTP_X_BUSINESS_ID=str(business_a["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


class MemberTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def test_invite_existing_user_creates_invitation(self):
        business = self._make_business()
        role_member = business["id"] and None
        roles = {
            r["nom"]: r
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        resp = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]["id"]},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["statut"], BusinessMember.Statut.INVITE)
        self.assertEqual(resp.data["user"]["email"], "bob@demo.com")
        membership = BusinessMember.objects.get(
            business_id=business["id"], user=self.user_b
        )
        self.assertEqual(membership.invited_by, self.user_a)

    def test_invite_unknown_email_creates_user_account(self):
        business = self._make_business()
        resp = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "nouveau@demo.com"},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email="nouveau@demo.com").exists())
        self.assertEqual(
            resp.data["role"]["nom"], RoleNom.MEMBER
        )

    def test_invite_with_role_from_other_business_rejected(self):
        business = self._make_business()
        make_business(self.client, self.token_b, "Societe Beta")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        foreign_roles = Business.objects.get(
            created_by=self.user_b
        ).roles.values_list("id", flat=True)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": list(foreign_roles)[0]},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_member_accepts_invitation(self):
        business = self._make_business()
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]},
            format="json",
            **self._headers(business["id"]),
        ).data

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/members/{invite['id']}/accept/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], BusinessMember.Statut.ACTIF)

    def test_other_user_cannot_accept_invitation(self):
        business = self._make_business()
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]},
            format="json",
            **self._headers(business["id"]),
        ).data
        register(self.client, "eve@demo.com")
        token_eve = login_and_token(self.client, "eve@demo.com")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_eve}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/members/{invite['id']}/accept/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_owner_role_cannot_be_removed(self):
        business = self._make_business()
        owner_member = BusinessMember.objects.get(
            business_id=business["id"], user=self.user_a
        )
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/members/{owner_member.id}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_owner_cannot_be_changed(self):
        business = self._make_business()
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        owner_member = BusinessMember.objects.get(
            business_id=business["id"], user=self.user_a
        )
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/members/{owner_member.id}/",
            {"role_id": str(roles[RoleNom.ADMIN])},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_member_without_permission_cannot_remove(self):
        business = self._make_business()
        roles = {
            r["nom"]: r
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]["id"]},
            format="json",
            **self._headers(business["id"]),
        )
        member = BusinessMember.objects.get(
            business_id=business["id"], user=self.user_b
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/members/{member.id}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_blocked_member_has_no_access(self):
        business = self._make_business()
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.BLOQUE
        member.save()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.get(
            f"/api/businesses/{business['id']}/members/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_statut_update_requires_remove_permission(self):
        business = self._make_business()
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]},
            format="json",
            **self._headers(business["id"]),
        ).data
        register(self.client, "eve@demo.com")
        token_eve = login_and_token(self.client, "eve@demo.com")
        invite2 = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "eve@demo.com", "role_id": roles[RoleNom.MEMBER]},
            format="json",
            **self._headers(business["id"]),
        ).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_eve}")
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/members/{invite2['id']}/",
            {"statut": BusinessMember.Statut.BLOQUE},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


class RoleTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def test_owner_role_has_all_permissions(self):
        business = self._make_business()
        roles = self.client.get(
            f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
        ).data["results"]
        owner = next(r for r in roles if r["nom"] == RoleNom.OWNER)
        self.assertEqual(
            {p["codename"] for p in owner["permissions"]},
            {p[0] for p in PERMISSIONS_CATALOG},
        )

    def test_create_custom_role_with_selected_permissions(self):
        business = self._make_business()
        resp = self.client.post(
            f"/api/businesses/{business['id']}/roles/",
            {
                "nom": "COMPTABLE",
                "description": "Gère la compta",
                "permission_codenames": [Perm.BUSINESS_VIEW, Perm.MEMBER_VIEW],
            },
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            {p["codename"] for p in resp.data["permissions"]},
            {Perm.BUSINESS_VIEW, Perm.MEMBER_VIEW},
        )

    def test_create_role_unknown_permission_fails(self):
        business = self._make_business()
        resp = self.client.post(
            f"/api/businesses/{business['id']}/roles/",
            {"nom": "COMPTABLE", "permission_codenames": ["xxx.inconnu"]},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_duplicate_role_name_fails(self):
        business = self._make_business()
        resp = self.client.post(
            f"/api/businesses/{business['id']}/roles/",
            {"nom": RoleNom.ADMIN},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_system_role_cannot_be_deleted_or_edited(self):
        business = self._make_business()
        roles = self.client.get(
            f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
        ).data["results"]
        member_role = next(r for r in roles if r["nom"] == RoleNom.MEMBER)
        resp_del = self.client.delete(
            f"/api/businesses/{business['id']}/roles/{member_role['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp_del.status_code, status.HTTP_400_BAD_REQUEST)
        resp_put = self.client.put(
            f"/api/businesses/{business['id']}/roles/{member_role['id']}/",
            {"nom": "CHANGED"},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp_put.status_code, status.HTTP_400_BAD_REQUEST)

    def test_custom_role_in_use_cannot_be_deleted(self):
        business = self._make_business()
        created = self.client.post(
            f"/api/businesses/{business['id']}/roles/",
            {"nom": "COMPTABLE"},
            format="json",
            **self._headers(business["id"]),
        ).data
        self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": created["id"]},
            format="json",
            **self._headers(business["id"]),
        )
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/roles/{created['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT)

    def test_member_role_limited_by_rbac(self):
        business = self._make_business()
        roles = {
            r["nom"]: r
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": roles[RoleNom.MEMBER]["id"]},
            format="json",
            **self._headers(business["id"]),
        )
        member = BusinessMember.objects.get(
            business_id=business["id"], user=self.user_b
        )
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        # Peut lister les membres (member.view)
        resp = self.client.get(
            f"/api/businesses/{business['id']}/members/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        # Ne peut PAS inviter (member.invite)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "eve@demo.com"},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        # Ne peut PAS gérer les rôles (role.manage)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/roles/",
            {"nom": "HACKER"},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_random_user_not_member_denied(self):
        business = self._make_business()
        register(self.client, "eve@demo.com")
        token_eve = login_and_token(self.client, "eve@demo.com")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_eve}")
        resp = self.client.get(
            f"/api/businesses/{business['id']}/members/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


# --- Sprint 2 : Catalogue (S 2-08) -----------------------------------------


class CatalogTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_category(self, business, nom="Tentes"):
        return self.client.post(
            f"/api/businesses/{business['id']}/categories/",
            {"nom": nom},
            format="json",
            **self._headers(business["id"]),
        )

    def _make_item(self, business, category_id=None, nom="Tente 3x3", **kwargs):
        data = {"nom": nom, **kwargs}
        if category_id:
            data["category_id"] = str(category_id)
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            data,
            format="json",
            **self._headers(business["id"]),
        )

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    # --- Catégories (US-05) ---

    def test_create_and_list_category(self):
        business = self._make_business()
        resp = self._make_category(business, "Salles & Tentes")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["item_count"], 0)
        listing = self.client.get(
            f"/api/businesses/{business['id']}/categories/",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual([c["nom"] for c in listing], ["Salles & Tentes"])

    def test_duplicate_category_rejected(self):
        business = self._make_business()
        self._make_category(business, "Tentes")
        resp = self._make_category(business, "Tentes")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_category_search(self):
        business = self._make_business()
        self._make_category(business, "Tentes de réception")
        self._make_category(business, "Chaises")
        resp = self.client.get(
            f"/api/businesses/{business['id']}/categories/?search=tentes",
            **self._headers(business["id"]),
        )
        self.assertEqual(len(self._results(resp)), 1)
        self.assertEqual(self._results(resp)[0]["nom"], "Tentes de réception")

    def test_category_update(self):
        business = self._make_business()
        cat = self._make_category(business, "Tentes").data
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/categories/{cat['id']}/",
            {"description": "Tentes de réception"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["description"], "Tentes de réception")

    def test_category_delete_blocked_when_items_exist(self):
        business = self._make_business()
        cat = self._make_category(business, "Tentes").data
        self._make_item(business, category_id=cat["id"], nom="Tente 3x3")
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/categories/{cat['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT)

    def test_category_delete_when_empty(self):
        business = self._make_business()
        cat = self._make_category(business, "Vide").data
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/categories/{cat['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    def test_rm01_categories_isolated_per_business(self):
        business_a = self._make_business()
        self._make_category(business_a, "Tentes")
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.get(
            f"/api/businesses/{business_b['id']}/categories/",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(self._results(resp), [])

    def test_member_cannot_manage_categories(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/categories/",
            {"nom": "Hack"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # --- Articles (US-06, US-07) ---

    def test_create_item_with_characteristics_and_photos_ref(self):
        business = self._make_business()
        cat = self._make_category(business, "Tentes").data
        resp = self._make_item(
            business,
            category_id=cat["id"],
            nom="Tente 3x3 PLU",
            reference="TEN-3X3",
            prix="1200.00",
            unite="unité",
            characteristics={"matière": "polyester", "capacité": 10, "lavable": True},
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        data = resp.data
        self.assertEqual(data["reference"], "TEN-3X3")
        self.assertEqual(data["category"]["id"], str(cat["id"]))
        self.assertEqual(data["characteristics"]["matière"], "polyester")
        self.assertEqual(data["photos"], [])

    def test_create_item_with_initial_quantity_creates_stock(self):
        business = self._make_business()
        resp = self._make_item(
            business, nom="Tente 3x3", prix="1200.00", unite="pièce",
            initial_quantity=8,
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        item_id = resp.data["id"]
        stock_resp = self.client.get(
            f"/api/businesses/{business['id']}/items/{item_id}/stock/",
            **self._headers(business["id"]),
        )
        self.assertEqual(stock_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(stock_resp.data["disponibles"], 8)
        self.assertEqual(stock_resp.data["total"], 8)

    def test_create_item_without_initial_quantity_has_no_stock(self):
        business = self._make_business()
        resp = self._make_item(business, nom="Tente 5x5")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        item_id = resp.data["id"]
        stock_resp = self.client.get(
            f"/api/businesses/{business['id']}/items/{item_id}/stock/",
            **self._headers(business["id"]),
        )
        self.assertEqual(stock_resp.data["disponibles"], 0)

    def test_item_characteristics_must_be_object(self):
        business = self._make_business()
        resp = self._make_item(business, characteristics=["a", "b"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_duplicate_reference_rejected(self):
        business = self._make_business()
        self._make_item(business, nom="Tente 3x3", reference="TEN-3X3")
        resp = self._make_item(business, nom="Tente 5x5", reference="TEN-3X3")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_item_category_from_other_business_rejected(self):
        business_a = self._make_business()
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        foreign_cat = Category(
            business_id=business_b["id"], nom="Catégorie B"
        )
        foreign_cat.save()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self._make_item(business_a, category_id=foreign_cat.id)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_item_update(self):
        business = self._make_business()
        item = self._make_item(business, nom="Tente 3x3", prix="100").data
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            {"prix": "150.50", "statut": Item.Statut.INACTIF},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["prix"], "150.50")
        self.assertEqual(resp.data["statut"], Item.Statut.INACTIF)

    def test_item_search_and_filters(self):
        business = self._make_business()
        cat = self._make_category(business, "Tentes").data
        self._make_item(business, nom="Tente 3x3", category_id=cat["id"])
        self._make_item(business, nom="Tente 5x5", category_id=cat["id"])
        self._make_item(business, nom="Chaise Blanche")
        search = self.client.get(
            f"/api/businesses/{business['id']}/items/?search=tente",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(len(search), 2)
        by_cat = self.client.get(
            f"/api/businesses/{business['id']}/items/?category_id={cat['id']}",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(len(by_cat), 2)
        self.assertEqual(by_cat[0]["category"]["nom"], "Tentes")

    def test_rm01_item_isolated_per_business(self):
        business_a = self._make_business()
        self._make_item(business_a, nom="Tente 3x3")
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        listing = self.client.get(
            f"/api/businesses/{business_b['id']}/items/",
            **self._headers(business_b["id"]),
        ).data["results"]
        self.assertEqual(listing, [])
        # Un article du business A reste inaccessible depuis le business B
        item_a = Item.objects.get(business_id=business_a["id"])
        resp = self.client.get(
            f"/api/businesses/{business_b['id']}/items/{item_a.id}/",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_member_cannot_create_item(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/items/",
            {"nom": "Hack"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_gestionnaire_can_edit_items_but_not_delete(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        item = self._make_item(business, nom="Tente 3x3").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        # GESTIONNAIRE : item.edit OK (création)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/items/",
            {"nom": "Tente 5x5"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        # mais suppression = catalog.manage => refus
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        # et pas de gestion des catégories
        resp = self.client.post(
            f"/api/businesses/{business['id']}/categories/",
            {"nom": "Hack"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_item_delete_requires_catalog_manage(self):
        business = self._make_business()
        item = self._make_item(business, nom="Tente 3x3").data
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    # --- Photos (S 2-03) ---

    def _upload_photo(self, business, item_id, caption="photo principale"):
        return self.client.post(
            f"/api/businesses/{business['id']}/items/{item_id}/photos/",
            {"image": SimpleUploadedFile("pixel.png", PNG_1PX, content_type="image/png"),
             "caption": caption},
            format="multipart",
            **self._headers(business["id"]),
        )

    def test_upload_photo_and_photo_url_in_item(self):
        business = self._make_business()
        item = self._make_item(business, nom="Tente 3x3").data
        resp = self._upload_photo(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        photo_id = resp.data["id"]
        detail = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            **self._headers(business["id"]),
        ).data
        self.assertEqual(detail["photos"][0]["id"], photo_id)
        self.assertIn("media", detail["photos"][0]["image"])

    def test_photo_limit_5_per_item(self):
        business = self._make_business()
        item = self._make_item(business, nom="Tente 3x3").data
        for i in range(5):
            resp = self._upload_photo(business, item["id"], caption=f"photo {i}")
            self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        resp = self._upload_photo(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_photo(self):
        business = self._make_business()
        item = self._make_item(business, nom="Tente 3x3").data
        photo = self._upload_photo(business, item["id"]).data
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/items/{item['id']}/photos/{photo['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ItemPhoto.objects.filter(id=photo["id"]).exists())

    def test_upload_photo_requires_item_edit(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        item = self._make_item(business, nom="Tente 3x3").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self._upload_photo(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
# --- Sprint 3 : Stock & tracabilite (S 3-08) -------------------------------


class StockTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_item(self, business, nom="Tente 3x3"):
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            {"nom": nom}, format="json",
            **self._headers(business["id"]),
        ).data

    def _move(self, business, item_id, type, quantite, motif="motif", reference="", related_to=None):
        data = {
            "type": type, "item_id": str(item_id),
            "quantite": quantite, "motif": motif, "reference": reference,
        }
        if related_to:
            data["related_to"] = str(related_to)
        return self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            data, format="json",
            **self._headers(business["id"]),
        )

    def _stock(self, business, item_id):
        return self.client.get(
            f"/api/businesses/{business['id']}/items/{item_id}/stock/",
            **self._headers(business["id"]),
        ).data

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    def test_scenario_100_70_98_96(self):
        business = self._make_business()
        item = self._make_item(business)
        resp = self._move(business, item["id"], "ENTREE", 100, motif="")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["stock"]["total"], 100)
        self.assertEqual(resp.data["stock"]["disponibles"], 100)
        resp = self._move(business, item["id"], "SORTIE", 30, motif="Location mariage")
        self.assertEqual(resp.data["stock"]["disponibles"], 70)
        self.assertEqual(resp.data["stock"]["sorties"], 30)
        sortie = StockMovement.objects.get(item_id=item["id"], type="SORTIE")
        resp = self._move(business, item["id"], "RETOUR", 28, motif="Retour client",
                          related_to=sortie.id)
        self.assertEqual(resp.data["stock"]["disponibles"], 98)
        self.assertEqual(resp.data["stock"]["sorties"], 2)
        resp = self._move(business, item["id"], "DOMMAGE", 2, motif="Toile dechiree")
        self.assertEqual(resp.data["stock"]["disponibles"], 96)
        self.assertEqual(resp.data["stock"]["endommages"], 2)
        state = self._stock(business, item["id"])
        self.assertEqual(state["total"], 100)
        self.assertEqual(state["disponibles"], 96)
        self.assertEqual(state["sorties"], 2)
        self.assertEqual(state["endommages"], 2)
        self.assertEqual(state["perdus"], 0)

    def test_perte_reduit_le_total(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 100)
        resp = self._move(business, item["id"], "PERTE", 3, motif="Vol constate")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["stock"]["total"], 97)
        self.assertEqual(resp.data["stock"]["perdus"], 3)
        self.assertEqual(resp.data["stock"]["disponibles"], 97)

    def test_sortie_superieure_au_disponible_refusee(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 10)
        resp = self._move(business, item["id"], "SORTIE", 11, motif="Sortie")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_retour_superieur_aux_sorties_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 10)
        self._move(business, item["id"], "SORTIE", 5, motif="Sortie")
        resp = self._move(business, item["id"], "RETOUR", 6, motif="Retour")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_dommage_superieur_au_disponible_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        resp = self._move(business, item["id"], "DOMMAGE", 1, motif="Dommage")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_quantite_zero_refusee(self):
        business = self._make_business()
        item = self._make_item(business)
        resp = self._move(business, item["id"], "ENTREE", 0)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_motif_obligatoire_hors_entree(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 10, motif="")
        resp = self._move(business, item["id"], "SORTIE", 1, motif="")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("motif", resp.data)

    def test_acteur_enregistre(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 10)
        movement = StockMovement.objects.get(item_id=item["id"], type="ENTREE")
        self.assertEqual(movement.acteur_id, self.user_a.id)

    def test_retour_lie_a_une_sortie(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 10)
        sortie_id = self._move(business, item["id"], "SORTIE", 4, motif="Location").data[
            "movement"
        ]["id"]
        resp = self._move(business, item["id"], "RETOUR", 2, motif="Retour",
                          related_to=sortie_id)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["movement"]["retour_de"], sortie_id)

    def test_retour_lie_a_une_sortie_dun_autre_article_refuse(self):
        business = self._make_business()
        item_a = self._make_item(business, "Tente A")
        item_b = self._make_item(business, "Tente B")
        self._move(business, item_a["id"], "ENTREE", 10)
        self._move(business, item_b["id"], "ENTREE", 10)
        sortie_b = self._move(
            business, item_b["id"], "SORTIE", 5, motif="Sortie B"
        ).data["movement"]
        resp = self._move(business, item_a["id"], "RETOUR", 1, motif="Retour",
                          related_to=sortie_b["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_historique_immuable_aucun_endpoint_de_modification(self):
        business = self._make_business()
        item = self._make_item(business)
        mvt = self._move(business, item["id"], "ENTREE", 10).data["movement"]
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/stock/movements/{mvt['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        resp = self.client.put(
            f"/api/businesses/{business['id']}/stock/movements/{mvt['id']}/",
            {"quantite": 999}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(StockMovement.objects.get(id=mvt["id"]).quantite, 10)

    def test_historique_conserve_apres_dommage_et_perte(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 10)
        self._move(business, item["id"], "DOMMAGE", 2, motif="Casse")
        self._move(business, item["id"], "PERTE", 1, motif="Perdu")
        history = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/stock/history/",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(len(history), 3)
        types = {h["type"] for h in history}
        self.assertEqual(types, {"ENTREE", "DOMMAGE", "PERTE"})

    def test_historique_filtre_par_type(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move(business, item["id"], "ENTREE", 10)
        resp = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/stock/history/?type=SORTIE",
            **self._headers(business["id"]),
        )
        self.assertEqual(self._results(resp), [])

    def test_rm01_stock_est_isole_par_business(self):
        business_a = self._make_business()
        item_a = self._make_item(business_a, "Tente A")
        self._move(business_a, item_a["id"], "ENTREE", 50)
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        listing = self.client.get(
            f"/api/businesses/{business_b['id']}/stock/",
            **self._headers(business_b["id"]),
        ).data["results"]
        self.assertEqual(listing, [])
        resp = self.client.post(
            f"/api/businesses/{business_b['id']}/stock/movements/",
            {"type": "ENTREE", "item_id": str(item_a["id"]), "quantite": 10},
            format="json",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_membre_ne_peut_pas_creer_mais_voit_le_stock(self):
        business = self._make_business()
        item = self._make_item(business)
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        listing = self.client.get(
            f"/api/businesses/{business['id']}/stock/",
            **self._headers(business["id"]),
        )
        self.assertEqual(listing.status_code, status.HTTP_200_OK)
        resp = self._move(business, item["id"], "ENTREE", 1)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_gestionnaire_peut_tracer_les_mouvements(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        item = self._make_item(business)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self._move(business, item["id"], "ENTREE", 25)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["stock"]["disponibles"], 25)
        movement = StockMovement.objects.get(item_id=item["id"])
        self.assertEqual(movement.acteur_id, self.user_b.id)

    def test_liste_stock_globale_avec_etats(self):
        business = self._make_business()
        item = self._make_item(business, "Tente 3x3")
        self._move(business, item["id"], "ENTREE", 40)
        resp = self.client.get(
            f"/api/businesses/{business['id']}/stock/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        row = self._results(resp)[0]
        self.assertEqual(row["total"], 40)
        self.assertEqual(row["disponibles"], 40)
        self.assertEqual(row["reference"], None)


# --- Sprint 4 : Entretien (US-13 a US-17) ----------------------------------


class MaintenanceTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_category(self, business, nom, entretien_requis=None, procedure_id=None):
        data = {"nom": nom}
        if entretien_requis is not None:
            data["entretien_requis"] = entretien_requis
        if procedure_id is not None:
            data["procedure_id"] = str(procedure_id)
        return self.client.post(
            f"/api/businesses/{business['id']}/categories/",
            data, format="json",
            **self._headers(business["id"]),
        ).data

    def _make_item(self, business, nom="Tente 3x3", category_id=None,
                   entretien_requis=None, procedure_id=None):
        data = {"nom": nom}
        if category_id is not None:
            data["category_id"] = str(category_id)
        if entretien_requis is not None:
            data["entretien_requis"] = entretien_requis
        if procedure_id is not None:
            data["procedure_id"] = str(procedure_id)
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            data, format="json",
            **self._headers(business["id"]),
        ).data

    def _make_procedure(self, business, nom="Lavage complet", steps=None):
        data = {"nom": nom, "steps_input": steps or [
            {"nom": "Lavage", "ordre": 1, "obligatoire": True, "type": "OPERATION"},
            {"nom": "Sechage", "ordre": 2, "obligatoire": True, "type": "OPERATION"},
            {"nom": "Controle final", "ordre": 3, "obligatoire": True, "type": "CONTROLE"},
        ]}
        return self.client.post(
            f"/api/businesses/{business['id']}/procedures/",
            data, format="json",
            **self._headers(business["id"]),
        ).data

    def _make_task(self, business, item_id, procedure_id=None, motif="Routine"):
        data = {"item_id": str(item_id), "motif": motif}
        if procedure_id is not None:
            data["procedure_id"] = str(procedure_id)
        return self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/",
            data, format="json",
            **self._headers(business["id"]),
        )

    def _step(self, business, task_id, step_id, statut):
        return self.client.patch(
            f"/api/businesses/{business['id']}/maintenance/tasks/{task_id}/steps/{step_id}/",
            {"statut": statut}, format="json",
            **self._headers(business["id"]),
        )

    def _cloture(self, business, task_id, partielle=False):
        data = {"partielle": partielle} if partielle else {}
        return self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/{task_id}/cloturer/",
            data, format="json",
            **self._headers(business["id"]),
        )

    def _etat_item(self, business, item_id):
        resp = self.client.get(
            f"/api/businesses/{business['id']}/items/{item_id}/",
            **self._headers(business["id"]),
        )
        return resp.data["etat_entretien"]["code"]

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    # --- RM-08 : entretien requis ou non (héritage catégorie -> article) --

    def test_rm08_requis_par_categorie_puis_override_article(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        item_hers = self._make_item(business, "Tente A", category_id=category["id"])
        item_override = self._make_item(
            business, "Tente B", category_id=category["id"], entretien_requis=False
        )
        self.assertIsNone(item_hers["entretien_requis"])
        self.assertFalse(item_override["entretien_requis"])
        self.assertEqual(self._etat_item(business, item_hers["id"]), "A_ENTRETENIR")
        self.assertEqual(self._etat_item(business, item_override["id"]), "PRET")

    def test_rm08_article_sans_entretien_est_pret(self):
        business = self._make_business()
        item = self._make_item(business)
        self.assertEqual(self._etat_item(business, item["id"]), "PRET")
        stock = self.client.get(
            f"/api/businesses/{business['id']}/stock/",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(stock[0]["etat_entretien"]["code"], "PRET")
        self.assertEqual(stock[0]["entretien_requis"], False)

    # --- US-14 / RM-09 : procédure multi-étapes ----------------------------

    def test_us14_procedure_avec_etapes_obligatoires_et_controle(self):
        business = self._make_business()
        procedure = self._make_procedure(business)
        self.assertEqual(len(procedure["steps"]), 3)
        controles = [s for s in procedure["steps"] if s["type"] == "CONTROLE"]
        self.assertEqual(len(controles), 1)
        self.assertTrue(procedure["steps"][0]["obligatoire"])

    def test_procedure_sans_etapes_refusee(self):
        business = self._make_business()
        resp = self.client.post(
            f"/api/businesses/{business['id']}/procedures/",
            {"nom": "Vide", "steps_input": []}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_procedure_etapes_doublons_refusees(self):
        business = self._make_business()
        resp = self.client.post(
            f"/api/businesses/{business['id']}/procedures/",
            {"nom": "Doublon", "steps_input": [
                {"nom": "Lavage"}, {"nom": "Lavage"},
            ]}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_procedure_meme_nom_refusee(self):
        business = self._make_business()
        self._make_procedure(business, "Lavage complet")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/procedures/",
            {"nom": "Lavage complet", "steps_input": [{"nom": "Lavage"}]},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_procedure_suppression_bloquee_si_taches_existent(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        task = self._make_task(business, item["id"]).data
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/procedures/{procedure['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT)
        self.assertTrue(TaskStep.objects.filter(task_id=task["id"]).exists())

    # --- US-15 / RM-10 : création de tâche ---------------------------------

    def test_us15_creation_tache_copie_les_etapes(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        resp = self._make_task(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        task = resp.data
        self.assertEqual(task["procedure_nom"], "Lavage complet")
        self.assertEqual(len(task["steps"]), 3)
        self.assertEqual(task["etapes"]["total"], 3)
        self.assertEqual(task["etapes"]["faites"], 0)
        self.assertEqual(task["statut"], "EN_COURS")

    def test_rm10_tache_creee_ne_rend_pas_larticle_pret(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        self.assertEqual(self._etat_item(business, item["id"]), "A_ENTRETENIR")
        self._make_task(business, item["id"])
        self.assertEqual(self._etat_item(business, item["id"]), "EN_ENTRETIEN")

    def test_tache_sans_procedure_configuree_refusee(self):
        business = self._make_business()
        item = self._make_item(business)
        resp = self._make_task(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_deux_taches_en_cours_refusees(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        self._make_task(business, item["id"])
        resp = self._make_task(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_procedure_desactivee_refusee(self):
        business = self._make_business()
        procedure = self._make_procedure(business)
        self.client.patch(
            f"/api/businesses/{business['id']}/procedures/{procedure['id']}/",
            {"est_actif": False}, format="json",
            **self._headers(business["id"]),
        )
        item = self._make_item(business, "Tente", procedure_id=procedure["id"])
        resp = self._make_task(business, item["id"], procedure_id=procedure["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # --- US-16 : suivi des étapes ------------------------------------------

    def test_us16_etapes_avancement_et_cloture_terminee(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        task = self._make_task(business, item["id"]).data
        lavage, sechage, controle = task["steps"]

        resp = self._cloture(business, task["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

        resp = self._step(business, task["id"], lavage["id"], "EN_COURS")
        self.assertEqual(resp.data["statut"], "EN_COURS")
        resp = self._step(business, task["id"], lavage["id"], "TERMINE")
        self.assertEqual(resp.data["statut"], "TERMINE")

        task = self.client.get(
            f"/api/businesses/{business['id']}/maintenance/tasks/{task['id']}/",
            **self._headers(business["id"]),
        ).data
        self.assertEqual(task["etapes"]["faites"], 1)
        self.assertEqual(task["etapes"]["en_cours"], 0)
        self.assertEqual(task["etapes"]["restantes"], 2)

        self._step(business, task["id"], sechage["id"], "TERMINE")
        resp = self._cloture(business, task["id"])
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "TERMINEE")
        self.assertEqual(self._etat_item(business, item["id"]), "A_CONTROLER")
        self._step(business, task["id"], controle["id"], "TERMINE")
        self.assertEqual(self._etat_item(business, item["id"]), "PRET")

    def test_etape_modifiee_apres_cloture_refusee(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        task = self._make_task(business, item["id"]).data
        for step in task["steps"]:
            self._step(business, task["id"], step["id"], "TERMINE")
        self._cloture(business, task["id"])
        resp = self._step(business, task["id"], task["steps"][0]["id"], "EN_COURS")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # --- RM-11 : entretien partiel accepté et visible -----------------------

    def test_rm11_entretien_incomplet_accepte_et_visible(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        task = self._make_task(business, item["id"]).data
        self._step(business, task["id"], task["steps"][0]["id"], "TERMINE")
        resp = self._cloture(business, task["id"], partielle=True)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "PARTIELLE")
        self.assertEqual(self._etat_item(business, item["id"]), "PARTIEL")
        listing = self.client.get(
            f"/api/businesses/{business['id']}/maintenance/tasks/?statut=PARTIELLE",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["etat_article"]["code"], "PARTIEL")

    def test_cloture_complete_dun_entretien_incomplet_passe_terminee(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        task = self._make_task(business, item["id"]).data
        for step in task["steps"]:
            self._step(business, task["id"], step["id"], "TERMINE")
        resp = self._cloture(business, task["id"], partielle=True)
        self.assertEqual(resp.data["statut"], "TERMINEE")

    # --- A_CONTROLER : travail fini mais contrôle non fait ------------------

    def test_a_controler_puis_pret_apres_controle(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        task = self._make_task(business, item["id"]).data
        self._step(business, task["id"], task["steps"][0]["id"], "TERMINE")
        self._step(business, task["id"], task["steps"][1]["id"], "TERMINE")
        resp = self._cloture(business, task["id"])
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "TERMINEE")
        self.assertEqual(self._etat_item(business, item["id"]), "A_CONTROLER")
        self._step(business, task["id"], task["steps"][2]["id"], "TERMINE")
        self.assertEqual(self._etat_item(business, item["id"]), "PRET")

    def test_auto_tache_au_retour_de_location(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", category_id=category["id"],
                               procedure_id=procedure["id"])
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._move_stock(business, item["id"], "SORTIE", 3, motif="Location mariage")
        self._move_stock(business, item["id"], "RETOUR", 3, motif="Retour client")
        task = MaintenanceTask.objects.get(item_id=item["id"])
        self.assertEqual(task.statut, MaintenanceTask.Statut.EN_COURS)
        self.assertIn("Retour de location", task.motif)
        self.assertEqual(self._etat_item(business, item["id"]), "EN_ENTRETIEN")

    def test_pas_de_tache_auto_sans_procedure(self):
        business = self._make_business()
        category = self._make_category(business, "Tentes", entretien_requis=True)
        item = self._make_item(business, "Tente A", category_id=category["id"])
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._move_stock(business, item["id"], "SORTIE", 3, motif="Location")
        self._move_stock(business, item["id"], "RETOUR", 3, motif="Retour client")
        self.assertFalse(MaintenanceTask.objects.filter(item_id=item["id"]).exists())

    def _move_stock(self, business, item_id, type, quantite, motif="motif"):
        resp = self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": type, "item_id": str(item_id), "quantite": quantite, "motif": motif},
            format="json",
            **self._headers(business["id"]),
        )
        return resp

    # --- RM-01 : isolation multi-tenant -------------------------------------

    def test_rm01_procedures_et_taches_isolees_par_business(self):
        business_a = self._make_business()
        procedure_a = self._make_procedure(business_a, "Procedure Alpha")
        item_a = self._make_item(business_a, "Tente A",
                                 procedure_id=procedure_a["id"])
        self._make_task(business_a, item_a["id"])

        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        procedures = self.client.get(
            f"/api/businesses/{business_b['id']}/procedures/",
            **self._headers(business_b["id"]),
        ).data["results"]
        self.assertEqual(procedures, [])
        tasks = self.client.get(
            f"/api/businesses/{business_b['id']}/maintenance/tasks/",
            **self._headers(business_b["id"]),
        ).data["results"]
        self.assertEqual(tasks, [])

        resp = self.client.post(
            f"/api/businesses/{business_b['id']}/maintenance/tasks/",
            {"item_id": str(item_a["id"]), "motif": "Fraude"},
            format="json",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_rm01_procedure_etrangere_refusee_sur_article(self):
        business_a = self._make_business()
        procedure_a = self._make_procedure(business_a, "Procedure Alpha")
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        item_b = self._make_item(business_b, "Tente B")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self._make_task(
            business_a, item_b["id"], procedure_id=procedure_a["id"]
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_rm01_etape_dune_tache_dun_autre_business_introuvable(self):
        business_a = self._make_business()
        procedure_a = self._make_procedure(business_a)
        item_a = self._make_item(business_a, "Tente A",
                                 procedure_id=procedure_a["id"])
        task_a = self._make_task(business_a, item_a["id"]).data
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self._step(
            business_b, task_a["id"], task_a["steps"][0]["id"], "TERMINE"
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    # --- RBAC ----------------------------------------------------------------

    def test_rbac_membre_voit_mais_ne_gere_pas(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        procedure = self._make_procedure(business)
        item = self._make_item(business, "Tente A", procedure_id=procedure["id"])
        self._make_task(business, item["id"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        listing = self.client.get(
            f"/api/businesses/{business['id']}/maintenance/tasks/",
            **self._headers(business["id"]),
        )
        self.assertEqual(listing.status_code, status.HTTP_200_OK)
        procedures = self.client.get(
            f"/api/businesses/{business['id']}/procedures/",
            **self._headers(business["id"]),
        )
        self.assertEqual(procedures.status_code, status.HTTP_200_OK)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/procedures/",
            {"nom": "Sans droit", "steps_input": [{"nom": "Lavage"}]},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        task = MaintenanceTask.objects.first()
        resp = self._cloture(business, task.id)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_rbac_gestionnaire_gere_lentretien(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        item = self._make_item(business, "Tente A")
        procedure = self._make_procedure(business)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self._make_task(business, item["id"], procedure_id=procedure["id"])
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            MaintenanceTask.objects.get(item_id=item["id"]).created_by_id,
            self.user_b.id,
        )
# --- Sprint 5 : Disponibilite & fiabilite (US-18, US-22 a US-26) ------------


class FiabiliteTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_item(self, business, nom="Tente 3x3"):
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            {"nom": nom}, format="json",
            **self._headers(business["id"]),
        ).data

    def _move_stock(self, business, item_id, type, quantite, motif="motif"):
        return self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": type, "item_id": str(item_id), "quantite": quantite, "motif": motif},
            format="json",
            **self._headers(business["id"]),
        )

    def _launch_inventory(self, business, libelle="Inventaire de fin de mois"):
        resp = self.client.post(
            f"/api/businesses/{business['id']}/inventories/",
            {"libelle": libelle}, format="json",
            **self._headers(business["id"]),
        )
        return resp

    def _count(self, business, inventory_id, item_id, quantite, fiabilite="NON_VERIFIE"):
        return self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory_id}/counts/",
            {"item_id": str(item_id), "quantite_comptee": quantite, "fiabilite": fiabilite},
            format="json",
            **self._headers(business["id"]),
        )

    def _cloture(self, business, inventory_id):
        return self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory_id}/cloturer/",
            {}, format="json",
            **self._headers(business["id"]),
        )

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    # --- US-18 / US-22 : disponibilite reelle et comptage -------------------

    def test_us22_lancement_inventaire_et_avancement(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resp = self._launch_inventory(business)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["statut"], "EN_COURS")
        self.assertEqual(resp.data["avancement"]["comptes"], 0)
        self.assertEqual(resp.data["avancement"]["total"], 1)

        resp = self._count(business, resp.data["id"], item["id"], 8)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["quantite_theorique"], 10)
        self.assertEqual(resp.data["quantite_comptee"], 8)
        self.assertEqual(resp.data["ecart"], -2)
        self.assertEqual(resp.data["fiabilite"], "NON_VERIFIE")

    def test_us22_recomptage_remplace_sans_doublon(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 8)
        resp = self._count(business, inventory["id"], item["id"], 9)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(InventoryCount.objects.filter(
            inventory_id=inventory["id"], item_id=item["id"]
        ).count(), 1)
        self.assertEqual(resp.data["quantite_comptee"], 9)

    def test_us22_theorique_capture_a_la_saisie(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 9)
        self._move_stock(business, item["id"], "ENTREE", 5)
        count = InventoryCount.objects.get(inventory_id=inventory["id"])
        self.assertEqual(count.quantite_theorique, 10)
        self.assertEqual(count.ecart, -1)

    # --- US-23 / RM-13 : ecart -> evenement --------------------------------

    def test_us23_cloture_cree_ajustements_pour_ecarts_non_nuls(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 100)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 95)
        resp = self._cloture(business, inventory["id"])
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "CLOTURE")
        self.assertEqual(resp.data["bilan"]["comptages"], 1)
        self.assertEqual(resp.data["bilan"]["ecarts"], 1)
        self.assertEqual(resp.data["bilan"]["ajustements"], 1)
        adjustment = StockAdjustment.objects.get(item_id=item["id"])
        self.assertEqual(adjustment.ecart, -5)
        self.assertEqual(adjustment.quantite_theorique, 100)
        self.assertEqual(adjustment.quantite_comptee, 95)
        self.assertEqual(adjustment.inventory_id, uuidlib.UUID(str(inventory["id"])))

    def test_rm04_disponibilite_reelle_apres_ajustement(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 100)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 95)
        self._cloture(business, inventory["id"])
        stock = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/stock/",
            **self._headers(business["id"]),
        ).data
        self.assertEqual(stock["ajustements"], -5)
        self.assertEqual(stock["total"], 95)
        self.assertEqual(stock["disponibles"], 95)

    def test_cloture_sans_ecart_aucun_ajustement(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 50)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 50, fiabilite="CERTAIN")
        resp = self._cloture(business, inventory["id"])
        self.assertEqual(resp.data["bilan"]["ajustements"], 0)
        self.assertFalse(StockAdjustment.objects.filter(item_id=item["id"]).exists())

    def test_cloture_sans_comptage_refusee(self):
        business = self._make_business()
        self._make_item(business)
        inventory = self._launch_inventory(business).data
        resp = self._cloture(business, inventory["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_double_cloture_refusee(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 10)
        self._cloture(business, inventory["id"])
        resp = self._cloture(business, inventory["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_comptage_apres_cloture_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 10)
        self._cloture(business, inventory["id"])
        resp = self._count(business, inventory["id"], item["id"], 12)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # --- US-24 / US-26 : ajustement manuel et historique --------------------

    def test_us24_ajustement_manuel_trace(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 40)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/adjustments/",
            {"item_id": str(item["id"]), "quantite_comptee": 42, "motif": "Recompte"},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["ecart"], 2)
        self.assertEqual(resp.data["quantite_theorique"], 40)
        self.assertEqual(resp.data["inventory_id"], None)
        stock = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/stock/",
            **self._headers(business["id"]),
        ).data
        self.assertEqual(stock["total"], 42)

    def test_ajustement_manuel_sans_motif_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 40)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/adjustments/",
            {"item_id": str(item["id"]), "quantite_comptee": 42},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_us26_ajustements_immuables_sans_endpoint_de_modification(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        adjustment = StockAdjustment.objects.create(
            business=Business.objects.get(id=business["id"]),
            item=Item.objects.get(id=item["id"]),
            quantite_theorique=10, quantite_comptee=13, ecart=3,
            motif="Test", acteur=self.user_a,
        )
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/adjustments/{adjustment.id}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        resp = self.client.put(
            f"/api/businesses/{business['id']}/adjustments/{adjustment.id}/",
            {"ecart": 99}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(
            StockAdjustment.objects.get(id=adjustment.id).ecart, 3
        )

    def test_historique_ajustements_filtrable_par_article(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self.client.post(
            f"/api/businesses/{business['id']}/adjustments/",
            {"item_id": str(item["id"]), "quantite_comptee": 8, "motif": "Perte detectee"},
            format="json",
            **self._headers(business["id"]),
        )
        adjustments = self.client.get(
            f"/api/businesses/{business['id']}/adjustments/?item_id={item['id']}",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(len(adjustments), 1)
        self.assertEqual(adjustments[0]["ecart"], -2)
        self.assertEqual(adjustments[0]["acteur"]["email"], "alice@demo.com")

    # --- RM-12 / RM-14 / RM-15 : fiabilite ----------------------------------

    def test_rm14_comptage_non_verifie_marque_a_verifier(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 9)
        detail = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            **self._headers(business["id"]),
        ).data
        self.assertTrue(detail["a_verifier"])
        stock = self.client.get(
            f"/api/businesses/{business['id']}/stock/",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertTrue(stock[0]["a_verifier"])

    def test_rm15_estime_nest_jamais_certain(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 9, fiabilite="ESTIME")
        detail = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            **self._headers(business["id"]),
        ).data
        self.assertTrue(detail["a_verifier"])
        self.assertEqual(detail["etat_entretien"]["code"], "PRET")

    def test_rm12_redevient_sain_apres_comptage_certain(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        self._count(business, inventory["id"], item["id"], 9)
        self.assertTrue(a_verifier(Item.objects.get(id=item["id"])))
        self._count(business, inventory["id"], item["id"], 10, fiabilite="CERTAIN")
        detail = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            **self._headers(business["id"]),
        ).data
        self.assertFalse(detail["a_verifier"])

    def test_rm14_verifie_ou_pas_change_la_fiabilite_sans_effacer_je_historique(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self._launch_inventory(business).data
        count = self._count(
            business, inventory["id"], item["id"], 9, fiabilite="NON_VERIFIE"
        ).data
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/counts/{count['id']}/",
            {"fiabilite": "CERTAIN"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["fiabilite"], "CERTAIN")
        self.assertEqual(resp.data["quantite_comptee"], 9)

    # --- RBAC et RM-01 ------------------------------------------------------

    def test_rbac_membre_voit_mais_ne_compte_pas(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        item = self._make_item(business)
        inventory = self._launch_inventory(business).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        listing = self.client.get(
            f"/api/businesses/{business['id']}/inventories/",
            **self._headers(business["id"]),
        )
        self.assertEqual(listing.status_code, status.HTTP_200_OK)
        resp = self._count(business, inventory["id"], item["id"], 9)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/inventories/",
            {"libelle": "Sans droit"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_rbac_gestionnaire_compte_et_cloture(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 20)
        inventory = self._launch_inventory(business).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self._count(business, inventory["id"], item["id"], 19, fiabilite="CERTAIN")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        resp = self._cloture(business, inventory["id"])
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        adjustment = StockAdjustment.objects.get(item_id=item["id"])
        self.assertEqual(adjustment.acteur_id, self.user_b.id)

    def test_rm01_inventaires_et_ajustements_isoles(self):
        business_a = self._make_business()
        item_a = self._make_item(business_a, "Tente A")
        self._move_stock(business_a, item_a["id"], "ENTREE", 10)
        inventory_a = self._launch_inventory(business_a).data

        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        inventories = self.client.get(
            f"/api/businesses/{business_b['id']}/inventories/",
            **self._headers(business_b["id"]),
        ).data["results"]
        self.assertEqual(inventories, [])
        resp = self._count(business_b, inventory_a["id"], item_a["id"], 5)
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        resp = self.client.post(
            f"/api/businesses/{business_b['id']}/adjustments/",
            {"item_id": str(item_a["id"]), "quantite_comptee": 8, "motif": "Fraude"},
            format="json",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_rm01_detail_inventaire_etranger_introuvable(self):
        business_a = self._make_business()
        inventory_a = self._launch_inventory(business_a).data
        business_b = make_business(self.client, self.token_b, "Societe Beta").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.get(
            f"/api/businesses/{business_b['id']}/inventories/{inventory_a['id']}/",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)# --- Sprint 6 : alertes, dÃ©cisions & exceptions (US-19 Ã  US-21) ------------
# RM-05, RM-06, RM-07, RM-22 : avertir (alerte persistÃ©e), dÃ©cider (permission
# stock.exception + motif), tracer (journal immuable). Le problÃ¨me reste
# visible aprÃ¨s la dÃ©cision (critÃ¨re d'acceptation).


class AlertesTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_item(self, business, nom="Tente 3x3", entretien_requis=None,
                   procedure_id=None):
        data = {"nom": nom}
        if entretien_requis is not None:
            data["entretien_requis"] = entretien_requis
        if procedure_id is not None:
            data["procedure_id"] = str(procedure_id)
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            data, format="json",
            **self._headers(business["id"]),
        ).data

    def _make_procedure(self, business, nom="Lavage complet", steps=None):
        data = {"nom": nom, "steps_input": steps or [
            {"nom": "Lavage", "ordre": 1, "obligatoire": True, "type": "OPERATION"},
            {"nom": "Sechage", "ordre": 2, "obligatoire": True, "type": "OPERATION"},
            {"nom": "Controle final", "ordre": 3, "obligatoire": True, "type": "CONTROLE"},
        ]}
        return self.client.post(
            f"/api/businesses/{business['id']}/procedures/",
            data, format="json",
            **self._headers(business["id"]),
        ).data

    def _make_task(self, business, item_id, motif="Routine"):
        return self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/",
            {"item_id": str(item_id), "motif": motif}, format="json",
            **self._headers(business["id"]),
        )

    def _step(self, business, task_id, step_id, statut):
        return self.client.patch(
            f"/api/businesses/{business['id']}/maintenance/tasks/{task_id}/steps/{step_id}/",
            {"statut": statut}, format="json",
            **self._headers(business["id"]),
        )

    def _cloture(self, business, task_id, partielle=False):
        data = {"partielle": partielle} if partielle else {}
        return self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/{task_id}/cloturer/",
            data, format="json",
            **self._headers(business["id"]),
        )

    def _item_en_entretien(self, business):
        procedure = self._make_procedure(business)
        item = self._make_item(
            business, entretien_requis=True, procedure_id=procedure["id"]
        )
        self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "ENTREE", "item_id": str(item["id"]), "quantite": 10},
            format="json", **self._headers(business["id"]),
        )
        resp = self._make_task(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        return item

    def _item_entretien_partiel(self, business):
        procedure = self._make_procedure(business)
        item = self._make_item(
            business, entretien_requis=True, procedure_id=procedure["id"]
        )
        self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "ENTREE", "item_id": str(item["id"]), "quantite": 10},
            format="json", **self._headers(business["id"]),
        )
        task = self._make_task(business, item["id"]).data
        lavage = next(s for s in task["steps"] if s["nom"] == "Lavage")
        self._step(business, task["id"], lavage["id"], "TERMINE")
        resp = self._cloture(business, task["id"], partielle=True)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "PARTIELLE")
        return item

    def _item_a_verifier(self, business):
        item = self._make_item(business)
        self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "ENTREE", "item_id": str(item["id"]), "quantite": 5},
            format="json", **self._headers(business["id"]),
        )
        inventory = self.client.post(
            f"/api/businesses/{business['id']}/inventories/",
            {}, format="json", **self._headers(business["id"]),
        ).data
        self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/counts/",
            {"item_id": str(item["id"]), "quantite_comptee": 5}, format="json",
            **self._headers(business["id"]),
        )
        return item

    def _sortie(self, business, item_id, quantite=1, motif="sortie",
                bypass=False, bypass_motif="besoin client urgent"):
        data = {
            "type": "SORTIE",
            "item_id": str(item_id),
            "quantite": quantite,
            "motif": motif,
        }
        if bypass:
            data["ignorer_avertissements"] = True
            data["motif_exception"] = bypass_motif
        return self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            data, format="json",
            **self._headers(business["id"]),
        )

    def _rules(self, business, as_user=None):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        resp = self.client.get(
            f"/api/businesses/{business['id']}/rules/",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    def _set_rule_mode(self, business, code, mode):
        rules = {
            r["code"]: r["id"] for r in self._rules(business).data["results"]
        }
        return self.client.patch(
            f"/api/businesses/{business['id']}/rules/{rules[code]}/",
            {"mode": mode}, format="json",
            **self._headers(business["id"]),
        )

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    def _add_custom_role(self, business, nom, codenames):
        resp = self.client.post(
            f"/api/businesses/{business['id']}/roles/",
            {"nom": nom, "permission_codenames": codenames}, format="json",
            **self._headers(business["id"]),
        )
        return resp.data

    # --- RM-07 / S6-05 : rÃ¨gles configurables par business ------------------

    def test_s6_regles_par_defaut_creees_a_demarrage(self):
        business = self._make_business()
        regles = self._rules(business).data["results"]
        self.assertEqual(len(regles), 3)
        self.assertEqual(
            {r["code"] for r in regles},
            {"ARTICLE_EN_ENTRETIEN", "ENTRETIEN_PARTIEL", "ARTICLE_A_VERIFIER"},
        )
        for r in regles:
            self.assertEqual(r["mode"], "AVERTISSEMENT")
            self.assertTrue(r["est_actif"])
        self.assertEqual(BusinessRule.objects.filter(business_id=business["id"]).count(), 3)

    def test_s6_changement_mode_et_activation(self):
        business = self._make_business()
        resp = self._set_rule_mode(business, "ARTICLE_EN_ENTRETIEN", "BLOCAGE")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["mode"], "BLOCAGE")

    def test_s6_regles_independantes_entre_business(self):
        business_a = self._make_business()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        business_b = make_business(self.client, self.token_b, "Agence Bravo").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        self._set_rule_mode(business_a, "ARTICLE_EN_ENTRETIEN", "BLOCAGE")
        for rules in self._rules(business_b, as_user="bob").data["results"]:
            if rules["code"] == "ARTICLE_EN_ENTRETIEN":
                self.assertEqual(rules["mode"], "AVERTISSEMENT")

    def test_s6_member_ne_configure_pas_les_regles(self):
        business = self._make_business()
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        resp = self._rules(business, as_user="bob")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # --- US-19 / RM-22 Â« Avertir Â» : alerte persistÃ©e ----------------------

    def test_us19_sortie_article_en_entretien_emet_avertissement(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        resp = self._sortie(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        avertissements = resp.data["avertissements"]
        self.assertEqual(len(avertissements), 1)
        self.assertEqual(avertissements[0]["code"], "ARTICLE_EN_ENTRETIEN")
        self.assertEqual(avertissements[0]["mode"], "AVERTISSEMENT")
        self.assertIn("alert_id", avertissements[0])
        self.assertEqual(StockMovement.objects.filter(
            item_id=item["id"], type="SORTIE").count(), 0)
        self.assertEqual(Alert.objects.filter(
            item_id=item["id"], code="ARTICLE_EN_ENTRETIEN").count(), 1)

    def test_us19_sortie_sans_probleme_aucune_alerte(self):
        business = self._make_business()
        item = self._make_item(business)
        self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "ENTREE", "item_id": str(item["id"]), "quantite": 5},
            format="json", **self._headers(business["id"]),
        )
        resp = self._sortie(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertNotIn("avertissements", resp.data)
        self.assertEqual(Alert.objects.filter(item_id=item["id"]).count(), 0)

    def test_us19_alerte_pour_entretien_partiel(self):
        business = self._make_business()
        item = self._item_entretien_partiel(business)
        resp = self._sortie(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            resp.data["avertissements"][0]["code"], "ENTRETIEN_PARTIEL"
        )

    def test_us19_alerte_pour_article_a_verifier(self):
        business = self._make_business()
        item = self._item_a_verifier(business)
        resp = self._sortie(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            resp.data["avertissements"][0]["code"], "ARTICLE_A_VERIFIER"
        )

    def test_s6_entree_non_eevaluee_par_les_regles(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        resp = self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "ENTREE", "item_id": str(item["id"]), "quantite": 3},
            format="json", **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Alert.objects.filter(item_id=item["id"]).count(), 0)

    # --- US-20 / RM-06 Â« DÃ©cider puis Tracer Â» -----------------------------

    def test_us20_bypass_cree_mouvement_alerte_liee_et_decision(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        resp = self._sortie(business, item["id"], bypass=True)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(StockMovement.objects.filter(
            item_id=item["id"], type="SORTIE").count(), 1)
        self.assertEqual(len(resp.data["avertissements"]), 1)
        decisions = resp.data["decisions"]
        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision["code"], "ARTICLE_EN_ENTRETIEN")
        self.assertEqual(decision["motif"], "besoin client urgent")
        self.assertEqual(decision["quantite"], 1)
        self.assertEqual(decision["acteur"]["email"], "alice@demo.com")
        self.assertEqual(
            str(decision["mouvement_id"]), str(resp.data["movement"]["id"])
        )
        alert = Alert.objects.get(id=resp.data["avertissements"][0]["alert_id"])
        self.assertEqual(str(alert.mouvement_id), str(resp.data["movement"]["id"]))

    def test_us20_bypass_sans_motif_refuse(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        resp = self._sortie(business, item["id"], bypass=True, bypass_motif="  ")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(StockMovement.objects.filter(
            item_id=item["id"], type="SORTIE").count(), 0)

    def test_rm19_membre_sans_permission_decision_refuse(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        operateur = self._add_custom_role(
            business, "OPERATEUR",
            [Perm.CATALOG_VIEW, Perm.STOCK_VIEW, Perm.STOCK_MOUVEMENT],
        )
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": operateur["id"]},
            format="json", **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self._sortie(
            {"id": business["id"]}, item["id"], bypass=True,
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("avertissements", resp.data)
        self.assertEqual(StockMovement.objects.filter(
            item_id=item["id"], type="SORTIE").count(), 0)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def test_rm19_gestionnaire_peut_passer_outre(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self._sortie(
            {"id": business["id"]}, item["id"], bypass=True,
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def test_us20_une_decision_par_regle_declenchee(self):
        business = self._make_business()
        item = self._item_entretien_partiel(business)
        inventory = self.client.post(
            f"/api/businesses/{business['id']}/inventories/",
            {}, format="json", **self._headers(business["id"]),
        ).data
        self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/counts/",
            {"item_id": str(item["id"]), "quantite_comptee": 1}, format="json",
            **self._headers(business["id"]),
        )
        resp = self._sortie(business, item["id"], bypass=True)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        codes = {a["code"] for a in resp.data["avertissements"]}
        self.assertEqual(codes, {"ENTRETIEN_PARTIEL", "ARTICLE_A_VERIFIER"})
        self.assertEqual(len(resp.data["decisions"]), 2)
        for decision in resp.data["decisions"]:
            self.assertEqual(decision["motif"], "besoin client urgent")

    def test_s6_le_probleme_reste_visible_apres_decision(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        self._sortie(business, item["id"], bypass=True)
        etat = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            **self._headers(business["id"]),
        ).data["etat_entretien"]["code"]
        self.assertEqual(etat, "EN_ENTRETIEN")
        alertes = self.client.get(
            f"/api/businesses/{business['id']}/alerts/",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(len(alertes), 1)

    # --- S6-05 / RM-22 : blocage obligatoire --------------------------------

    def test_s6_blocage_obligatoire_ignore_le_bypass(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        self._set_rule_mode(business, "ARTICLE_EN_ENTRETIEN", "BLOCAGE")
        resp = self._sortie(business, item["id"], bypass=True)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("bloque", resp.data)
        self.assertEqual(resp.data["bloque"][0]["mode"], "BLOCAGE")
        self.assertEqual(StockMovement.objects.filter(
            item_id=item["id"], type="SORTIE").count(), 0)
        self.assertEqual(DecisionLog.objects.filter(
            item_id=item["id"]).count(), 0)
        self.assertEqual(Alert.objects.filter(
            item_id=item["id"], code="ARTICLE_EN_ENTRETIEN", mode="BLOCAGE").count(), 1)

    # --- US-21 : journal des dÃ©cisions --------------------------------------

    def test_us21_journal_decisions_filtrable(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        self._sortie(business, item["id"], bypass=True)
        journal = self.client.get(
            f"/api/businesses/{business['id']}/decisions/",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(len(journal), 1)
        self.assertEqual(str(journal[0]["item_id"]), str(item["id"]))
        self.assertEqual(journal[0]["acteur"]["email"], "alice@demo.com")
        self.assertIn("created_at", journal[0])

    def test_s6_alertes_et_decisions_immuables(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        self._sortie(business, item["id"], bypass=True)
        alert = Alert.objects.get(item_id=item["id"])
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/alerts/{alert.id}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        decision = DecisionLog.objects.get(item_id=item["id"])
        resp = self.client.put(
            f"/api/businesses/{business['id']}/decisions/{decision.id}/",
            {"motif": "modifie"}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_s6_alertes_filtrables_par_item_et_code(self):
        business = self._make_business()
        item = self._item_en_entretien(business)
        self._sortie(business, item["id"], bypass=True)
        resp = self.client.get(
            f"/api/businesses/{business['id']}/alerts/?code=ARTICLE_A_VERIFIER",
            **self._headers(business["id"]),
        )
        self.assertEqual(self._results(resp), [])
        resp = self.client.get(
            f"/api/businesses/{business['id']}/alerts/?item_id={item['id']}",
            **self._headers(business["id"]),
        )
        self.assertEqual(len(self._results(resp)), 1)

    # --- RM-01 : isolation multi-tenant -------------------------------------

    def test_rm01_alertes_et_decisions_isolees_par_business(self):
        business_a = self._make_business()
        item = self._item_en_entretien(business_a)
        self._sortie(business_a, item["id"], bypass=True)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        business_b = make_business(self.client, self.token_b, "Agence Bravo").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        alertes_b = self.client.get(
            f"/api/businesses/{business_b['id']}/alerts/",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(self._results(alertes_b), [])
        decisions_b = self.client.get(
            f"/api/businesses/{business_b['id']}/decisions/",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(self._results(decisions_b), [])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def test_rm01_sortie_avec_bypass_isolee_par_business(self):
        business_a = self._make_business()
        item_a = self._item_en_entretien(business_a)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        business_b = make_business(self.client, self.token_b, "Agence Bravo").data
        item_b = self.client.post(
            f"/api/businesses/{business_b['id']}/items/",
            {"nom": "Chaise"}, format="json",
            **self._headers(business_b["id"]),
        ).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

        resp = self._sortie(business_a, item_a["id"], bypass=True)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Alert.objects.filter(
            item_id=item_a["id"]).count(), 1)
        self.assertEqual(Alert.objects.filter(
            item_id=item_b["id"]).count(), 0)
        self.assertEqual(DecisionLog.objects.filter(
            business_id=business_b["id"]).count(), 0)
# --- Sprint 7 : collaboration & visibilité (US-27, US-28) ------------------
# RM-20 (flux d'activité visible), US-28 (notifications par membre, lues ou
# non), RM-01 / RM-21 (isolation par business).


class ActiviteTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_item(self, business, nom="Tente 3x3", entretien_requis=None,
                   procedure_id=None):
        data = {"nom": nom}
        if entretien_requis is not None:
            data["entretien_requis"] = entretien_requis
        if procedure_id is not None:
            data["procedure_id"] = str(procedure_id)
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            data, format="json",
            **self._headers(business["id"]),
        ).data

    def _move_stock(self, business, item_id, type, quantite, motif="motif"):
        return self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": type, "item_id": str(item_id), "quantite": quantite, "motif": motif},
            format="json",
            **self._headers(business["id"]),
        )

    def _make_procedure(self, business, nom="Lavage complet"):
        return self.client.post(
            f"/api/businesses/{business['id']}/procedures/",
            {"nom": nom, "steps_input": [
                {"nom": "Lavage", "ordre": 1, "obligatoire": True, "type": "OPERATION"},
                {"nom": "Controle final", "ordre": 2, "obligatoire": True, "type": "CONTROLE"},
            ]},
            format="json",
            **self._headers(business["id"]),
        ).data

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    def _activities(self, business, as_user=None, **params):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        resp = self.client.get(
            f"/api/businesses/{business['id']}/activities/?{qs}",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    def _notifications(self, business, as_user="alice", **params):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        resp = self.client.get(
            f"/api/businesses/{business['id']}/notifications/?{qs}",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    # --- US-27 / RM-20 : flux d'activité -----------------------------------

    def test_us27_mouvement_genere_activite(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resp = self._move_stock(business, item["id"], "SORTIE", 2)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        resp = self._activities(business)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        actions = [a["action"] for a in resp.data["results"]]
        self.assertIn("STOCK.ENTREE", actions)
        self.assertIn("STOCK.SORTIE", actions)
        sortie = next(
            a for a in resp.data["results"] if a["action"] == "STOCK.SORTIE"
        )
        self.assertEqual(sortie["acteur"]["email"], "alice@demo.com")
        self.assertEqual(sortie["item_id"], item["id"])
        self.assertEqual(sortie["detail"]["quantite"], 2)

    def test_us27_activite_filtrable(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 5)
        resp = self._activities(business, action="STOCK.SORTIE")
        self.assertEqual(resp.data["results"], [])
        resp = self._activities(business, action="STOCK.ENTREE")
        self.assertEqual(len(resp.data["results"]), 1)
        resp = self._activities(business, item_id=item["id"])
        self.assertEqual(len(resp.data["results"]), 2)
        resp = self._activities(business, user_id=self.user_a.id)
        self.assertEqual(len(resp.data["results"]), 3)

    def test_us27_business_item_membre_catalogue_logues(self):
        business = self._make_business()
        item = self._make_item(business)
        self.client.patch(
            f"/api/businesses/{business['id']}/items/{item['id']}/",
            {"description": "nouvelle"}, format="json",
            **self._headers(business["id"]),
        )
        self.client.post(
            f"/api/businesses/{business['id']}/categories/",
            {"nom": "Tentes"}, format="json",
            **self._headers(business["id"]),
        )
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        actions = {a["action"] for a in self._activities(business).data["results"]}
        self.assertIn("BUSINESS.CREATE", actions)
        self.assertIn("ITEM.CREATE", actions)
        self.assertIn("ITEM.UPDATE", actions)
        self.assertIn("CATEGORY.CREATE", actions)
        self.assertIn("MEMBER.INVITE", actions)

    def test_rm20_member_voit_l_activite(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 3)
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        resp = self._activities(business, as_user="bob")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 4)

    def test_rm19_role_sans_activity_view_est_refuse(self):
        business = self._make_business()
        role = self.client.post(
            f"/api/businesses/{business['id']}/roles/",
            {"nom": "OBSERVATEUR_MINIMAL", "permission_codenames": ["catalog.view"]},
            format="json", **self._headers(business["id"]),
        ).data
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": "bob@demo.com", "role_id": role["id"]},
            format="json", **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()
        resp = self._activities(business, as_user="bob")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_s7_activite_immuable(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 3)
        activity = ActivityLog.objects.filter(business_id=business["id"]).first()
        resp = self.client.delete(
            f"/api/businesses/{business['id']}/activities/{activity.id}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    # --- US-28 / S7-08 : notifications -------------------------------------

    def test_us28_decision_exceptionnelle_notifie_l_equipe(self):
        business = self._make_business()
        item = self._make_item(business, entretien_requis=True,
                               procedure_id=self._make_procedure(business)["id"])
        self._move_stock(business, item["id"], "ENTREE", 10)
        self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/",
            {"item_id": str(item["id"])}, format="json",
            **self._headers(business["id"]),
        )
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "SORTIE", "item_id": str(item["id"]), "quantite": 1,
             "ignorer_avertissements": True, "motif_exception": "client attend", "motif": "sortie"},
            format="json", **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        notif_bob = self._notifications(business, as_user="bob")
        self.assertEqual(len(notif_bob.data["results"]), 1)
        self.assertEqual(notif_bob.data["results"][0]["code"], "DECISION.EXCEPTION")
        self.assertFalse(notif_bob.data["results"][0]["lu"])
        notif_alice = self._notifications(business, as_user="alice")
        self.assertEqual(notif_alice.data["results"], [])

    def test_s7_tache_auto_au_retour_notifie_les_gestionnaires(self):
        business = self._make_business()
        item = self._make_item(business, entretien_requis=True,
                               procedure_id=self._make_procedure(business)["id"])
        self._move_stock(business, item["id"], "ENTREE", 5)
        self._move_stock(business, item["id"], "SORTIE", 2)
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        resp = self._move_stock(business, item["id"], "RETOUR", 2)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        notif_bob = self._notifications(business, as_user="bob")
        self.assertEqual(len(notif_bob.data["results"]), 1)
        self.assertEqual(notif_bob.data["results"][0]["code"], "TASK.AUTO")

    def test_s7_inventaire_cloture_avec_ecarts_notifie(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self.client.post(
            f"/api/businesses/{business['id']}/inventories/",
            {}, format="json", **self._headers(business["id"]),
        ).data
        self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/counts/",
            {"item_id": str(item["id"]), "quantite_comptee": 8}, format="json",
            **self._headers(business["id"]),
        )
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/cloturer/",
            {}, format="json", **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        notif_bob = self._notifications(business, as_user="bob")
        self.assertEqual(len(notif_bob.data["results"]), 1)
        self.assertEqual(notif_bob.data["results"][0]["code"], "INVENTORY.ECARTS")

    def test_s7_inventaire_sans_ecart_pas_de_notification(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self.client.post(
            f"/api/businesses/{business['id']}/inventories/",
            {}, format="json", **self._headers(business["id"]),
        ).data
        self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/counts/",
            {"item_id": str(item["id"]), "quantite_comptee": 10,
             "fiabilite": "CERTAIN"}, format="json",
            **self._headers(business["id"]),
        )
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/cloturer/",
            {}, format="json", **self._headers(business["id"]),
        )
        notif_bob = self._notifications(business, as_user="bob")
        self.assertEqual(notif_bob.data["results"], [])

    def test_us28_mark_read_et_tout_lire(self):
        business = self._make_business()
        item = self._make_item(business, entretien_requis=True,
                               procedure_id=self._make_procedure(business)["id"])
        self._move_stock(business, item["id"], "ENTREE", 10)
        self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/",
            {"item_id": str(item["id"])}, format="json",
            **self._headers(business["id"]),
        )
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "SORTIE", "item_id": str(item["id"]), "quantite": 1,
             "ignorer_avertissements": True, "motif_exception": "urgent", "motif": "sortie"},
            format="json", **self._headers(business["id"]),
        )
        self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "SORTIE", "item_id": str(item["id"]), "quantite": 1,
             "ignorer_avertissements": True, "motif_exception": "urgent", "motif": "sortie"},
            format="json", **self._headers(business["id"]),
        )
        notif = self._notifications(business, as_user="bob").data["results"][0]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/notifications/{notif['id']}/",
            {"lu": True}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(resp.data["lu"])
        resp = self.client.post(
            f"/api/businesses/{business['id']}/notifications/mark-all-read/",
            {}, format="json", **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["marquees_lues"], 1)
        restantes = self.client.get(
            f"/api/businesses/{business['id']}/notifications/?lu=false",
            **self._headers(business["id"]),
        ).data["results"]
        self.assertEqual(restantes, [])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def test_us28_notification_propre_a_chaque_utilisateur(self):
        business = self._make_business()
        item = self._make_item(business, entretien_requis=True,
                               procedure_id=self._make_procedure(business)["id"])
        self._move_stock(business, item["id"], "ENTREE", 10)
        self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/",
            {"item_id": str(item["id"])}, format="json",
            **self._headers(business["id"]),
        )
        self._promote(business, "bob@demo.com", "GESTIONNAIRE")
        self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "SORTIE", "item_id": str(item["id"]), "quantite": 1,
             "ignorer_avertissements": True, "motif_exception": "urgent", "motif": "sortie"},
            format="json", **self._headers(business["id"]),
        )
        notif = Notification.objects.get(user=self.user_b)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/notifications/{notif.id}/",
            {"lu": True}, format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_rm01_activite_et_notifications_isolees_par_business(self):
        business_a = self._make_business()
        item = self._make_item(business_a)
        self._move_stock(business_a, item["id"], "ENTREE", 3)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        business_b = make_business(self.client, self.token_b, "Agence Bravo").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self._activities(business_a, as_user="bob")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        resp = self._notifications(business_a, as_user="bob")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # --- S 7-04 : dashboard ------------------------------------------------

    def test_s7_dashboard_synthese(self):
        business = self._make_business()
        item = self._make_item(business, entretien_requis=True,
                               procedure_id=self._make_procedure(business)["id"])
        item2 = self._make_item(business, nom="Chaise")
        self._move_stock(business, item["id"], "ENTREE", 10)
        self.client.post(
            f"/api/businesses/{business['id']}/maintenance/tasks/",
            {"item_id": str(item["id"])}, format="json",
            **self._headers(business["id"]),
        )
        self._move_stock(business, item2["id"], "ENTREE", 4)
        self._move_stock(business, item2["id"], "SORTIE", 1)
        resp = self.client.get(
            f"/api/businesses/{business['id']}/dashboard/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.data
        self.assertEqual(data["articles"]["total"], 2)
        self.assertEqual(data["articles"]["en_entretien"], 1)
        self.assertEqual(data["articles"]["a_verifier"], 0)
        self.assertEqual(data["taches_en_cours"], 1)
        self.assertEqual(len(data["mouvements_recents"]), 3)
        self.assertEqual(len(data["activite_recents"]), 8)
        self.assertIsNone(data["inventaire_actif"])

    def test_s7_dashboard_inventaire_actif_et_avancement(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        inventory = self.client.post(
            f"/api/businesses/{business['id']}/inventories/",
            {}, format="json", **self._headers(business["id"]),
        ).data
        self.client.post(
            f"/api/businesses/{business['id']}/inventories/{inventory['id']}/counts/",
            {"item_id": str(item["id"]), "quantite_comptee": 9}, format="json",
            **self._headers(business["id"]),
        )
        data = self.client.get(
            f"/api/businesses/{business['id']}/dashboard/",
            **self._headers(business["id"]),
        ).data
        actif = data["inventaire_actif"]
        self.assertEqual(actif["statut"], "EN_COURS")
        self.assertEqual(actif["avancement"]["comptes"], 1)
        self.assertEqual(actif["avancement"]["total"], 1)
        self.assertEqual(len(actif["counts"]), 1)

    def test_s7_dashboard_member_accede(self):
        business = self._make_business()
        self._make_item(business)
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.get(
            f"/api/businesses/{business['id']}/dashboard/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")





# --- Sprint 8 : réservations (US-29, US-30, US-31) -------------------------


class ReservationTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _make_business_b(self):
        resp = make_business(self.client, self.token_b, "Agence Bravo")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_item(self, business, nom="Tente 3x3"):
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            {"nom": nom}, format="json",
            **self._headers(business["id"]),
        ).data

    def _move_stock(self, business, item_id, type, quantite, motif="motif"):
        return self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": type, "item_id": str(item_id), "quantite": quantite, "motif": motif},
            format="json",
            **self._headers(business["id"]),
        )

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/", **self._headers(business["id"])
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    def _reserver(self, business, item_id, date_debut="2026-09-01",
                  date_fin="2026-09-10", quantite=1, motif="Salon pro",
                  as_user="alice"):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/reservations/",
            {"item_id": str(item_id), "date_debut": date_debut,
             "date_fin": date_fin, "quantite": quantite, "motif": motif},
            format="json",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    def _action(self, business, reservation_id, action, data=None, as_user="alice"):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/reservations/{reservation_id}/{action}/",
            data or {}, format="json",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    def _reservations_list(self, business, as_user="alice", **params):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        resp = self.client.get(
            f"/api/businesses/{business['id']}/reservations/?{qs}",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    def _activities(self, business, action=None):
        qs = f"?action={action}" if action else ""
        return self.client.get(
            f"/api/businesses/{business['id']}/activities/{qs}",
            **self._headers(business["id"]),
        )

    def _notifications(self, business, as_user="bob"):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        resp = self.client.get(
            f"/api/businesses/{business['id']}/notifications/",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    # --- US-29 : le membre réserve un article ------------------------------

    def test_us29_membre_creer_une_reservation(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        resp = self._reserver(business, item["id"], as_user="bob")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["statut"], "EN_ATTENTE")
        self.assertEqual(resp.data["item_id"], item["id"])
        self.assertEqual(resp.data["reserve_par"]["email"], "bob@demo.com")
        self.assertEqual(resp.data["quantite"], 1)
        self.assertEqual(resp.data["date_debut"], "2026-09-01")
        self.assertEqual(resp.data["date_fin"], "2026-09-10")

    def test_us29_creer_une_reservation_avec_quantite_et_motif(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resp = self._reserver(business, item["id"], quantite=4, motif="Mariage Juin")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["quantite"], 4)

    def test_us29_quantite_inferieure_a_un_refusee(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resp = self._reserver(business, item["id"], quantite=0)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_us29_dates_incoherentes_refusees(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resp = self._reserver(business, item["id"],
                              date_debut="2026-09-10", date_fin="2026-09-01")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_us29_article_dun_autre_business_refuse(self):
        business_a = self._make_business()
        business_b = self._make_business_b()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        item_b = self.client.post(
            f"/api/businesses/{business_b['id']}/items/",
            {"nom": "Tente B"}, format="json",
            **self._headers(business_b["id"]),
        ).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        self._move_stock(business_a, item_b["id"], "ENTREE", 5)
        resp = self._reserver(business_a, item_b["id"])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_us29_chevauchement_accepte_si_capacite_suffisante(self):
        """Deux réservations peuvent chevaucher sur le même article tant que
        la capacité totale n'est pas dépassée (exposition pleine, pas un
        blocage binaire sur le simple chevauchement)."""
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        first = self._reserver(business, item["id"], quantite=7)
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        resp = self._reserver(business, item["id"], quantite=3,
                              date_debut="2026-09-05", date_fin="2026-09-15")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_us29_chevauchement_refuse_si_capacite_depassee(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        first = self._reserver(business, item["id"], quantite=7)
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        second = self._reserver(business, item["id"], quantite=3,
                                date_debut="2026-09-05", date_fin="2026-09-15")
        self.assertEqual(second.status_code, status.HTTP_201_CREATED)
        # 7 + 3 = 10 (capacité) ; +1 supplémentaire sur une plage chevauchante
        # dépasse la capacité et doit être refusé.
        resp = self._reserver(business, item["id"], quantite=1,
                              date_debut="2026-09-08", date_fin="2026-09-12")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("disponibilité insuffisante", str(resp.data[0]).lower())

    def test_us29_plages_disjointes_acceptees(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        first = self._reserver(business, item["id"])
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        resp = self._reserver(business, item["id"],
                              date_debut="2026-09-11", date_fin="2026-09-20")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        resp = self._reserver(business, item["id"],
                              date_debut="2026-08-20", date_fin="2026-08-31")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_us29_exposition_pleine_refusee(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 3)
        resp = self._reserver(business, item["id"], quantite=4)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Exposition pleine", str(resp.data[0]))
        resp = self._reserver(business, item["id"], quantite=3)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        resp = self._reserver(business, item["id"], quantite=2,
                              date_debut="2026-09-11", date_fin="2026-09-20")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_us29_annulee_ou_terminee_ne_bloque_pas_la_plage(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        first = self._reserver(business, item["id"]).data
        self.assertEqual(
            self._action(business, first["id"], "annuler").status_code,
            status.HTTP_200_OK,
        )
        resp = self._reserver(business, item["id"])
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    # --- US-29 bis : réservation atomique de plusieurs articles ------------

    def _reserver_bulk(self, business, items, date_debut="2026-09-01",
                       date_fin="2026-09-10", motif="Événement", as_user="alice"):
        token = self.token_b if as_user == "bob" else self.token_a
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/reservations/bulk/",
            {
                "items": [
                    {"item_id": str(item_id), "quantite": quantite}
                    for item_id, quantite in items
                ],
                "date_debut": date_debut,
                "date_fin": date_fin,
                "motif": motif,
            },
            format="json",
            **self._headers(business["id"]),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp

    def test_us29bis_bulk_cree_plusieurs_reservations(self):
        business = self._make_business()
        chaises = self._make_item(business, "Chaises")
        tables = self._make_item(business, "Tables")
        self._move_stock(business, chaises["id"], "ENTREE", 20)
        self._move_stock(business, tables["id"], "ENTREE", 10)
        resp = self._reserver_bulk(
            business, [(chaises["id"], 20), (tables["id"], 10)]
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(len(resp.data), 2)
        qtes = {r["item_id"]: r["quantite"] for r in resp.data}
        self.assertEqual(qtes[chaises["id"]], 20)
        self.assertEqual(qtes[tables["id"]], 10)
        # Les deux réservations sont bien persistées.
        listing = self._reservations_list(business)
        self.assertEqual(len(self._results(listing)), 2)

    def test_us29bis_bulk_est_atomique_si_un_article_echoue(self):
        """Si un seul article de la demande dépasse sa capacité, AUCUNE
        réservation n'est créée (pas de réservation partielle)."""
        business = self._make_business()
        chaises = self._make_item(business, "Chaises")
        nappes = self._make_item(business, "Nappes")
        self._move_stock(business, chaises["id"], "ENTREE", 20)
        self._move_stock(business, nappes["id"], "ENTREE", 5)
        resp = self._reserver_bulk(
            business, [(chaises["id"], 20), (nappes["id"], 50)]
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        listing = self._reservations_list(business)
        self.assertEqual(
            len(self._results(listing)), 0,
            "aucune réservation ne doit être créée si un article échoue",
        )

    def test_us29bis_bulk_refuse_article_en_double(self):
        business = self._make_business()
        chaises = self._make_item(business, "Chaises")
        self._move_stock(business, chaises["id"], "ENTREE", 20)
        resp = self._reserver_bulk(
            business, [(chaises["id"], 5), (chaises["id"], 5)]
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_us29bis_bulk_refuse_liste_vide(self):
        business = self._make_business()
        resp = self._reserver_bulk(business, [])
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_us29_liste_filtrable_par_statut(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._reserver(business, item["id"])
        resp = self._reservations_list(business, statut="EN_ATTENTE")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(self._results(resp)), 1)
        resp = self._reservations_list(business, statut="VALIDEE")
        self.assertEqual(self._results(resp), [])

    def test_us29_activite_reservation_creee(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._reserver(business, item["id"], motif="Salon pro")
        resp = self._activities(business, action="RESERVATION.CREATE")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 1)
        self.assertEqual(resp.data["results"][0]["item_id"], item["id"])
        self.assertEqual(resp.data["results"][0]["detail"]["quantite"], 1)

    # --- US-30 : validation et annulation par le gestionnaire --------------

    def test_us30_gestionnaire_valide_reservation(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        resa = self._reserver(business, item["id"], as_user="bob").data
        resp = self._action(business, resa["id"], "valider")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "VALIDEE")
        resp = self._activities(business, action="RESERVATION.VALIDEE")
        self.assertEqual(len(resp.data["results"]), 1)

    def test_us30_membre_recoit_notification_validation(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        resa = self._reserver(business, item["id"], as_user="bob").data
        resp = self._action(business, resa["id"], "valider")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp = self._notifications(business, as_user="bob")
        codes = [n["code"] for n in resp.data["results"]]
        self.assertIn("RESERVATION.VALIDEE", codes)
        resp = self._notifications(business, as_user="alice")
        self.assertNotIn(
            "RESERVATION.VALIDEE", [n["code"] for n in resp.data["results"]]
        )

    def test_us30_sans_permission_manage_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._promote(business, "bob@demo.com", RoleNom.MEMBER)
        resa = self._reserver(business, item["id"], as_user="bob").data
        resp = self._action(business, resa["id"], "valider", as_user="bob")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_us30_annulation_gestionnaire(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resa = self._reserver(business, item["id"]).data
        resp = self._action(business, resa["id"], "annuler", {"motif": "annule client"})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "ANNULEE")
        resp = self._activities(business, action="RESERVATION.ANNULEE")
        self.assertEqual(len(resp.data["results"]), 1)
        resp = self._action(business, resa["id"], "annuler")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # --- US-31 : démarrage (sortie) et terminaison (retour) -----------------

    def test_us31_demarrer_cree_sortie_de_stock(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resa = self._reserver(business, item["id"], quantite=3).data
        self._action(business, resa["id"], "valider")
        resp = self._action(business, resa["id"], "demarrer")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "EN_COURS")
        stock = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/stock/",
            **self._headers(business["id"]),
        ).data
        self.assertEqual(stock["sorties"], 3)
        self.assertEqual(stock["disponibles"], 7)
        resp = self._activities(business, action="RESERVATION.EN_COURS")
        self.assertEqual(len(resp.data["results"]), 1)

    def test_us31_terminer_cree_retour_de_stock(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resa = self._reserver(business, item["id"], quantite=3).data
        self._action(business, resa["id"], "valider")
        self._action(business, resa["id"], "demarrer")
        resp = self._action(business, resa["id"], "terminer")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "TERMINEE")
        stock = self.client.get(
            f"/api/businesses/{business['id']}/items/{item['id']}/stock/",
            **self._headers(business["id"]),
        ).data
        self.assertEqual(stock["sorties"], 0)
        self.assertEqual(stock["disponibles"], 10)
        resp = self._activities(business, action="RESERVATION.TERMINEE")
        self.assertEqual(len(resp.data["results"]), 1)

    def test_us31_transitions_invalides(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resa = self._reserver(business, item["id"]).data
        resp = self._action(business, resa["id"], "demarrer")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        resp = self._action(business, resa["id"], "terminer")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self._action(business, resa["id"], "valider")
        resp = self._action(business, resa["id"], "terminer")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_us31_demarrer_sortie_impossible_si_stock_insuffisant(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self._move_stock(business, item["id"], "SORTIE", 8)
        resa = self._reserver(business, item["id"], quantite=5).data
        self._action(business, resa["id"], "valider")
        resp = self._action(business, resa["id"], "demarrer")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        resa_db = Reservation.objects.get(id=resa["id"])
        self.assertEqual(resa_db.statut, "VALIDEE")

    # --- RM-01 : isolation par business ------------------------------------

    def test_rm01_reservation_invisible_hors_du_business(self):
        business_a = self._make_business()
        business_b = self._make_business_b()
        item = self._make_item(business_a)
        self._move_stock(business_a, item["id"], "ENTREE", 10)
        resa = self._reserver(business_a, item["id"]).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.get(
            f"/api/businesses/{business_b['id']}/reservations/",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["results"], [])
        resp = self.client.get(
            f"/api/businesses/{business_b['id']}/reservations/{resa['id']}/",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def test_rm01_non_membre_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.post(
            f"/api/businesses/{business['id']}/reservations/",
            {"item_id": str(item["id"]), "date_debut": "2026-09-01",
             "date_fin": "2026-09-10"},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def test_rm01_actions_404_hors_business(self):
        business_a = self._make_business()
        business_b = self._make_business_b()
        item = self._make_item(business_a)
        self._move_stock(business_a, item["id"], "ENTREE", 10)
        resa = self._reserver(business_a, item["id"]).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.post(
            f"/api/businesses/{business_b['id']}/reservations/{resa['id']}/valider/",
            {}, format="json",
            **self._headers(business_b["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    # --- Dashboard ----------------------------------------------------------

    def test_s8_dashboard_compteurs_reservations(self):
        business = self._make_business()
        item = self._make_item(business)
        self._move_stock(business, item["id"], "ENTREE", 10)
        resa1 = self._reserver(business, item["id"]).data
        resa2 = self._reserver(business, item["id"],
                               date_debut="2026-09-11", date_fin="2026-09-20").data
        self._action(business, resa1["id"], "valider")
        resp = self.client.get(
            f"/api/businesses/{business['id']}/dashboard/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["reservations"]["en_attente"], 1)
        self.assertEqual(resp.data["reservations"]["validees"], 1)
        self.assertEqual(resp.data["reservations"]["en_cours"], 0)


# --- Sprint 9 : stabilisation production ------------------------------------
# Enveloppe de pagination standard {count, next, previous, results} sur toutes
# les listes GET, limites de payload et de taille de photo.


class StabilisationTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _make_business_b(self):
        resp = make_business(self.client, self.token_b, "Agence Bravo")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_item(self, business, nom="Tente 3x3"):
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            {"nom": nom}, format="json",
            **self._headers(business["id"]),
        ).data

    def _items_list(self, business, **params):
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        return self.client.get(
            f"/api/businesses/{business['id']}/items/?{qs}",
            **self._headers(business["id"]),
        )

    def test_s9_toutes_les_listes_renvoient_l_enveloppe(self):
        business = self._make_business()
        self._make_item(business, "Tente A")
        resp = self._items_list(business)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(
            set(resp.data.keys()), {"count", "next", "previous", "results"}
        )
        self.assertEqual(resp.data["count"], 1)
        self.assertIsNone(resp.data["next"])
        self.assertIsNone(resp.data["previous"])
        self.assertEqual(resp.data["results"][0]["nom"], "Tente A")

    def test_s9_page_size_et_pagination_reelle(self):
        business = self._make_business()
        for i in range(3):
            self._make_item(business, f"Tente {i}")
        page1 = self._items_list(business, page_size=2)
        self.assertEqual(page1.data["count"], 3)
        self.assertEqual(len(page1.data["results"]), 2)
        self.assertIsNotNone(page1.data["next"])
        self.assertIsNone(page1.data["previous"])
        page2 = self._items_list(business, page_size=2, page=2)
        self.assertEqual(len(page2.data["results"]), 1)
        self.assertIsNone(page2.data["next"])
        self.assertIsNotNone(page2.data["previous"])

    def test_s9_page_size_borne_a_1000(self):
        business = self._make_business()
        self._make_item(business)
        resp = self._items_list(business, page_size=5000)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["count"], 1)

    def _make_jpeg(self, n_bytes):
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (800, 600), "red").save(buf, "JPEG", quality=85)
        data = buf.getvalue()
        if len(data) < n_bytes:
            data = data + b"\x00" * (n_bytes - len(data))
        return data[:n_bytes]

    def test_s9_photo_au_dela_de_5_mo_refusee(self):
        business = self._make_business()
        item = self._make_item(business)
        heavy = SimpleUploadedFile(
            "lourde.jpg",
            self._make_jpeg(5 * 1024 * 1024 + 100),
            content_type="image/jpeg",
        )
        resp = self.client.post(
            f"/api/businesses/{business['id']}/items/{item['id']}/photos/",
            {"image": heavy}, format="multipart",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("trop lourde", str(resp.data["image"][0]).lower())

    def test_s9_photo_5_mo_acceptee(self):
        business = self._make_business()
        item = self._make_item(business)
        ok = SimpleUploadedFile(
            "ok.jpg",
            self._make_jpeg(5 * 1024 * 1024),
            content_type="image/jpeg",
        )
        resp = self.client.post(
            f"/api/businesses/{business['id']}/items/{item['id']}/photos/",
            {"image": ok}, format="multipart",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_s9_payload_json_au_dela_de_2_mo_refuse(self):
        business = self._make_business()
        self.client.raise_request_exception = False
        resp = self.client.post(
            f"/api/businesses/{business['id']}/categories/",
            {"nom": "x" * (2 * 1024 * 1024 + 1000)},
            format="json",
            **self._headers(business["id"]),
        )
        self.client.raise_request_exception = True
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


# --- Sprint 10/11 : invitations par lien + code + email -----------------------
# POST /members/ renvoie un invitation_code et un invitation_link et envoie
# un email ; l'invité valide son code (POST /invitations/validate/) puis
# POST /invitations/accept/ pose son mot de passe et active son adhésion
# (octets JWT = connexion immédiate). Le lien signé reste supporté.


class InvitationFlowTests(BaseSetup):
    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _invite(self, business, email, **extra):
        return self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, **extra},
            format="json",
            **self._headers(business["id"]),
        )

    def _token_from_link(self, link):
        return link.split("token=", 1)[1]

    def test_invite_renvoie_code_et_envoie_email(self):
        business = self._make_business()
        resp = self._invite(business, "nouveau@demo.com")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("invitation_code", resp.data)
        code = resp.data["invitation_code"]
        self.assertRegex(code, r"^DODO-[A-Z2-9]{6}$")
        self.assertIn("invitation_link", resp.data)
        self.assertIn("token=", resp.data["invitation_link"])
        self.assertIn("invitation_expires_at", resp.data)
        self.assertTrue(resp.data["invitation_email_sent"])
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["nouveau@demo.com"])
        self.assertIn(code, msg.body)
        self.assertIn("Agence Alpha", msg.body)
        membership = BusinessMember.objects.get(
            user__email="nouveau@demo.com"
        )
        self.assertEqual(membership.statut, BusinessMember.Statut.INVITE)
        self.assertIsNotNone(membership.code_hash)
        self.assertIsNotNone(membership.expires_at)
        self.assertNotIn(code, membership.code_hash)

    def test_invite_membre_existant_renvoie_aussi_un_code(self):
        business = self._make_business()
        resp = self._invite(business, "bob@demo.com")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertRegex(resp.data["invitation_code"], r"^DODO-[A-Z2-9]{6}$")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["bob@demo.com"])

    def test_invite_codes_uniques(self):
        business = self._make_business()
        codes = {
            self._invite(business, f"user{i}@demo.com").data["invitation_code"]
            for i in range(5)
        }
        self.assertEqual(len(codes), 5)

    def test_preview_public_du_lien(self):
        business = self._make_business()
        resp = self._invite(business, "nouveau@demo.com")
        token = self._token_from_link(resp.data["invitation_link"])
        self.client.credentials()
        preview = self.client.get(f"/api/invitations/{token}/")
        self.assertEqual(preview.status_code, status.HTTP_200_OK)
        self.assertEqual(preview.data["email"], "nouveau@demo.com")
        self.assertEqual(preview.data["business_nom"], "Agence Alpha")
        self.assertEqual(preview.data["inviteur"], "alice@demo.com")
        self.assertEqual(preview.data["role"], RoleNom.MEMBER)
        self.assertEqual(preview.data["statut"], BusinessMember.Statut.INVITE)

    def test_preview_token_invalide_404(self):
        self.client.credentials()
        resp = self.client.get("/api/invitations/tokenbidon/")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_accept_active_membre_pose_mot_de_passe_et_connecte(self):
        business = self._make_business()
        resp = self._invite(business, "nouveau@demo.com")
        token = self._token_from_link(resp.data["invitation_link"])
        self.client.credentials()
        accepted = self.client.post(
            "/api/invitations/accept/",
            {
                "token": token,
                "password": "nouveaumotdepasse",
                "first_name": "Koffi",
                "last_name": "Agbo",
            },
            format="json",
        )
        self.assertEqual(accepted.status_code, status.HTTP_200_OK)
        self.assertIn("access", accepted.data)
        self.assertIn("refresh", accepted.data)
        self.assertEqual(accepted.data["user"]["email"], "nouveau@demo.com")
        self.assertEqual(accepted.data["user"]["first_name"], "Koffi")
        self.assertEqual(accepted.data["user"]["last_name"], "Agbo")
        membership = BusinessMember.objects.get(
            user__email="nouveau@demo.com"
        )
        self.assertEqual(membership.statut, BusinessMember.Statut.ACTIF)
        user = User.objects.get(email="nouveau@demo.com")
        self.assertTrue(user.check_password("nouveaumotdepasse"))
        login = self.client.post(
            "/api/auth/login/",
            {"email": "nouveau@demo.com", "password": "nouveaumotdepasse"},
            format="json",
        )
        self.assertEqual(login.status_code, status.HTTP_200_OK)

    def test_accept_token_deja_utilise_refuse(self):
        business = self._make_business()
        resp = self._invite(business, "nouveau@demo.com")
        token = self._token_from_link(resp.data["invitation_link"])
        self.client.credentials()
        payload = {"token": token, "password": "nouveaumotdepasse"}
        first = self.client.post(
            "/api/invitations/accept/", payload, format="json"
        )
        self.assertEqual(first.status_code, status.HTTP_200_OK)
        replay = self.client.post(
            "/api/invitations/accept/", payload, format="json"
        )
        self.assertEqual(replay.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("déjà", replay.data["detail"].lower())

    def test_accept_token_invalide_refuse(self):
        self.client.credentials()
        resp = self.client.post(
            "/api/invitations/accept/",
            {"token": "tokenbidon", "password": "nouveaumotdepasse"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_accept_invitation_bloquee_refuse(self):
        business = self._make_business()
        resp = self._invite(business, "nouveau@demo.com")
        token = self._token_from_link(resp.data["invitation_link"])
        BusinessMember.objects.filter(
            user__email="nouveau@demo.com"
        ).update(statut=BusinessMember.Statut.BLOQUE)
        self.client.credentials()
        accepted = self.client.post(
            "/api/invitations/accept/",
            {"token": token, "password": "nouveaumotdepasse"},
            format="json",
        )
        self.assertEqual(accepted.status_code, status.HTTP_409_CONFLICT)

    def test_accept_mot_de_passe_trop_faible_refuse(self):
        business = self._make_business()
        resp = self._invite(business, "nouveau@demo.com")
        token = self._token_from_link(resp.data["invitation_link"])
        self.client.credentials()
        weak = self.client.post(
            "/api/invitations/accept/",
            {"token": token, "password": "12345678"},
            format="json",
        )
        self.assertEqual(weak.status_code, status.HTTP_400_BAD_REQUEST)
        low = self.client.post(
            "/api/invitations/accept/",
            {"token": token, "password": "abc"},
            format="json",
        )
        self.assertEqual(low.status_code, status.HTTP_400_BAD_REQUEST)


# --- Sprint 11 : invitations par code -------------------------------------------
# POST /members/ génère un code DODO-XXXXXX (haché en base) ; l'invité valide
# le code, puis l'accepte (avec mot de passe si non connecté, ou connecté sur
# le compte invité). Le code ne peut être utilisé qu'une seule fois.


class InvitationCodeFlowTests(InvitationFlowTests):
    def _validate(self, code):
        self.client.credentials()
        return self.client.post(
            "/api/invitations/validate/", {"code": code}, format="json"
        )

    def _accept_code(self, code, **extra):
        self.client.credentials()
        return self.client.post(
            "/api/invitations/accept/",
            {"code": code, **extra},
            format="json",
        )

    def test_validation_du_code_valide(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        resp = self._validate(code)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(resp.data["valid"])
        inv = resp.data["invitation"]
        self.assertEqual(inv["business_nom"], "Agence Alpha")
        self.assertEqual(inv["role"], RoleNom.MEMBER)
        self.assertEqual(inv["inviteur"], "Test")
        self.assertEqual(inv["email"], "nouveau@demo.com")
        self.assertIn("expires_at", inv)

    def test_validation_code_insensible_a_la_casse_et_aux_separateurs(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        for saisie in (code.lower(), code.replace("-", ""), f" {code} "):
            resp = self._validate(saisie)
            self.assertEqual(
                resp.status_code, status.HTTP_200_OK, msg=f"saisie={saisie!r}"
            )

    def test_validation_code_inexistant_404(self):
        resp = self._validate("DODO-AAAAAA")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn("Code invalide", resp.data["detail"])

    def test_validation_code_expire_410(self):
        business = self._make_business()
        resp = self._invite(business, "nouveau@demo.com")
        code = resp.data["invitation_code"]
        BusinessMember.objects.filter(
            user__email="nouveau@demo.com"
        ).update(
            expires_at=timezone.now() - timezone.timedelta(seconds=1)
        )
        r = self._validate(code)
        self.assertEqual(r.status_code, status.HTTP_410_GONE)
        self.assertIn("expiré", r.data["detail"])

    def test_validation_code_annule_409(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        BusinessMember.objects.filter(
            user__email="nouveau@demo.com"
        ).update(statut=BusinessMember.Statut.CANCELLED)
        r = self._validate(code)
        self.assertEqual(r.status_code, status.HTTP_409_CONFLICT)
        self.assertIn("plus valide", r.data["detail"])

    def test_validation_code_deja_utilise_400(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        accepted = self._accept_code(code, password="nouveaumotdepasse")
        self.assertEqual(accepted.status_code, status.HTTP_200_OK)
        r = self._validate(code)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("déjà été utilisée", r.data["detail"])

    def test_accept_avec_code_et_mot_de_passe_active_le_membre(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        accepted = self._accept_code(
            code,
            password="nouveaumotdepasse",
            first_name="Koffi",
            last_name="Agbo",
        )
        self.assertEqual(accepted.status_code, status.HTTP_200_OK)
        self.assertIn("access", accepted.data)
        self.assertIn("refresh", accepted.data)
        self.assertEqual(accepted.data["user"]["email"], "nouveau@demo.com")
        membership = BusinessMember.objects.get(
            user__email="nouveau@demo.com"
        )
        self.assertEqual(membership.statut, BusinessMember.Statut.ACTIF)
        self.assertIsNotNone(membership.accepted_at)
        self.assertEqual(membership.business.nom, "Agence Alpha")
        self.assertEqual(membership.role.nom, RoleNom.MEMBER)
        user = User.objects.get(email="nouveau@demo.com")
        self.assertTrue(user.check_password("nouveaumotdepasse"))

    def test_accept_avec_code_sans_mot_de_passe_refuse(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        resp = self._accept_code(code)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("mot de passe est requis", resp.data["detail"])

    def test_accept_connecte_compte_invite_sans_mot_de_passe(self):
        register(self.client, "jean@demo.com")
        business = self._make_business()
        code = self._invite(business, "jean@demo.com").data["invitation_code"]
        token = login_and_token(self.client, "jean@demo.com")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        accepted = self.client.post(
            "/api/invitations/accept/", {"code": code}, format="json"
        )
        self.assertEqual(accepted.status_code, status.HTTP_200_OK)
        membership = BusinessMember.objects.get(user__email="jean@demo.com")
        self.assertEqual(membership.statut, BusinessMember.Statut.ACTIF)
        self.assertIsNotNone(membership.accepted_at)
        self.assertEqual(membership.role.nom, RoleNom.MEMBER)
        jean = User.objects.get(email="jean@demo.com")
        self.assertTrue(jean.check_password("motdepasse123"))

    def test_accept_connecte_mauvais_email_refuse(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        token = login_and_token(self.client, "alice@demo.com")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        resp = self.client.post(
            "/api/invitations/accept/", {"code": code}, format="json"
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("autre compte", resp.data["detail"])
        membership = BusinessMember.objects.get(
            user__email="nouveau@demo.com"
        )
        self.assertEqual(membership.statut, BusinessMember.Statut.INVITE)

    def test_code_impossible_a_reutiliser(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        payload = {"code": code, "password": "nouveaumotdepasse"}
        first = self.client.post(
            "/api/invitations/accept/", payload, format="json"
        )
        self.assertEqual(first.status_code, status.HTTP_200_OK)
        replay = self.client.post(
            "/api/invitations/accept/", payload, format="json"
        )
        self.assertEqual(replay.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("déjà été utilisée", replay.data["detail"])

    def test_annulation_puis_reinvitation_regenerent_un_code(self):
        business = self._make_business()
        first = self._invite(business, "nouveau@demo.com")
        code1 = first.data["invitation_code"]
        membership = BusinessMember.objects.get(
            user__email="nouveau@demo.com"
        )
        member_id = membership.id
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        cancelled = self.client.patch(
            f"/api/businesses/{business['id']}/members/{member_id}/",
            {"statut": BusinessMember.Statut.CANCELLED},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(cancelled.status_code, status.HTTP_200_OK)
        r = self._validate(code1)
        self.assertEqual(r.status_code, status.HTTP_409_CONFLICT)

        second = self._invite(business, "nouveau@demo.com")
        code2 = second.data["invitation_code"]
        self.assertNotEqual(code1, code2)
        same = BusinessMember.objects.get(id=member_id)
        self.assertEqual(same.statut, BusinessMember.Statut.INVITE)
        r = self._validate(code2)
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_annuler_membre_actif_refuse(self):
        business = self._make_business()
        code = self._invite(business, "nouveau@demo.com").data[
            "invitation_code"
        ]
        accepted = self._accept_code(code, password="nouveaumotdepasse")
        self.assertEqual(accepted.status_code, status.HTTP_200_OK)
        membership = BusinessMember.objects.get(
            user__email="nouveau@demo.com"
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.patch(
            f"/api/businesses/{business['id']}/members/{membership.id}/",
            {"statut": BusinessMember.Statut.CANCELLED},
            format="json",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


# --- Sprint 10 : description d'image par Gemini ----------------------------------
# POST /api/ai/image-description/ reçoit une photo d'article, appelle Gemini
# (clé côté serveur) et renvoie {"nom", "description"} pour pré-remplir le
# formulaire de création d'article. Les appels réseau sont mockés ; l'appel
# réel est validé manuellement avec le serveur de dev.


class AiDescriptionTests(BaseSetup):
    def setUp(self):
        super().setUp()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def _jpeg(self, n_bytes=8 * 1024):
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (400, 300), "blue").save(buf, "JPEG", quality=80)
        data = buf.getvalue()
        if len(data) < n_bytes:
            data = data + b"\x00" * (n_bytes - len(data))
        return data[:n_bytes]

    def _upload(self, image):
        return self.client.post(
            "/api/ai/image-description/",
            {"image": image},
            format="multipart",
        )

    @patch("accounts.views.describe_image")
    def test_describe_image_autofill_nom_description(self, mock_describe):
        mock_describe.return_value = {
            "nom": "Tente 3x3",
            "description": "Tente de camping 3 places, couleur verte avec housse.",
        }
        resp = self._upload(
            SimpleUploadedFile("tente.jpg", self._jpeg(), content_type="image/jpeg")
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["nom"], "Tente 3x3")
        self.assertIn("Tente", resp.data["description"])

    def test_requires_authentification(self):
        self.client.credentials()
        resp = self._upload(
            SimpleUploadedFile("tente.jpg", self._jpeg(), content_type="image/jpeg")
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_image_invalide_refusee(self):
        resp = self._upload(
            SimpleUploadedFile("fake.jpg", b"pas une image", content_type="image/jpeg")
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(GEMINI_API_KEY="")
    def test_cle_non_configuree_503(self):
        resp = self._upload(
            SimpleUploadedFile("tente.jpg", self._jpeg(), content_type="image/jpeg")
        )
        self.assertEqual(resp.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)

    @patch("accounts.views.describe_image", side_effect=GeminiError("Gemini a répondu 429.", http_code=429, retryable=True))
    def test_erreur_gemini_temporaire_503(self, mock_describe):
        resp = self._upload(
            SimpleUploadedFile("tente.jpg", self._jpeg(), content_type="image/jpeg")
        )
        self.assertEqual(resp.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertIn("temporairement indisponible", resp.data["detail"])

    @patch("accounts.views.describe_image", side_effect=GeminiError("Réponse Gemini vide ou inattendue."))
    def test_erreur_gemini_502(self, mock_describe):
        resp = self._upload(
            SimpleUploadedFile("tente.jpg", self._jpeg(), content_type="image/jpeg")
        )
        self.assertEqual(resp.status_code, status.HTTP_502_BAD_GATEWAY)

    def test_parse_reponse_contrainte(self):
        from .ai import _parse

        result = _parse("NOM: Tente 3x3\nDESCRIPTION: Tente de camping.")
        self.assertEqual(result["nom"], "Tente 3x3")
        self.assertEqual(result["description"], "Tente de camping.")
        vide = _parse("NOM: \nDESCRIPTION: Impossible d'identifier un article.")
        self.assertEqual(vide["nom"], "")
        self.assertIn("Impossible", vide["description"])

    @patch("accounts.ai.urllib.request.urlopen")
    def test_appel_gemini_bien_forme(self, mock_open):
        import json as jsonlib

        from django.conf import settings

        from . import ai

        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = lambda *a: None
        mock_open.return_value.read.return_value = jsonlib.dumps(
            {
                "candidates": [
                    {"content": {"parts": [{"text": "NOM: Couteau\nDESCRIPTION: Couteau de cuisine inox."}]}}
                ]
            }
        ).encode("utf-8")
        result = ai.describe_image(b"photo", "image/jpeg")
        self.assertEqual(result["nom"], "Couteau")
        request = mock_open.call_args.args[0]
        body = jsonlib.loads(request.data)
        self.assertEqual(body["contents"][0]["parts"][1]["inline_data"]["mime_type"], "image/jpeg")
        self.assertEqual(
            request.headers["X-goog-api-key"], settings.GEMINI_API_KEY
        )
        self.assertIn(settings.GEMINI_MODEL, request.full_url)

    @patch("accounts.ai.time.sleep")
    @patch("accounts.ai._call_gemini")
    def test_retry_sur_503(self, mock_call, mock_sleep):
        from .ai import GeminiError, describe_image

        mock_call.side_effect = [
            GeminiError("high demand", http_code=503, retryable=True),
            {"nom": "Chaise", "description": "Chaise blanche."},
        ]
        result = describe_image(b"photo", "image/jpeg")
        self.assertEqual(result["nom"], "Chaise")
        self.assertEqual(mock_call.call_count, 2)
        mock_sleep.assert_called_once_with(1.0)


# --- Sprint 12 : la suggestion IA est reliée au catalogue ------------------
# L'analyse ne renvoie plus seulement un nom et une description : elle classe
# l'article dans une catégorie existante du business et propose une référence
# libre, pour que le formulaire mobile arrive pré-rempli et cohérent.


class AiSuggestionCatalogueTests(BaseSetup):
    def setUp(self):
        super().setUp()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        self.business = make_business(self.client, self.token_a).data
        self.categorie = self.client.post(
            f"/api/businesses/{self.business['id']}/categories/",
            {"nom": "Vaisselle"},
            format="json",
            **self._headers(self.business["id"]),
        ).data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _jpeg(self):
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (400, 300), "blue").save(buf, "JPEG", quality=80)
        return buf.getvalue()

    def _photo(self):
        return SimpleUploadedFile(
            "photo.jpg", self._jpeg(), content_type="image/jpeg"
        )

    def _upload(self, avec_business=True):
        extra = self._headers(self.business["id"]) if avec_business else {}
        return self.client.post(
            "/api/ai/image-description/",
            {"image": self._photo()},
            format="multipart",
            **extra,
        )

    def _suggestion(self, **surcharges):
        base = {
            "nom": "Tasse bleue",
            "description": "Tasse en céramique bleue.",
            "categorie": "Vaisselle",
            "unite": "pièce",
            "etat": "NEUF",
            "caracteristiques": {"Couleur": "Bleu"},
            "confiance": "HAUTE",
        }
        base.update(surcharges)
        return base

    @patch("accounts.views.describe_image")
    def test_categorie_existante_est_rattachee(self, mock_describe):
        mock_describe.return_value = self._suggestion()
        resp = self._upload()
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["category_id"], str(self.categorie["id"]))
        self.assertEqual(resp.data["categorie"], "Vaisselle")

    @patch("accounts.views.describe_image")
    def test_categorie_rattachee_malgre_casse_et_espaces(self, mock_describe):
        mock_describe.return_value = self._suggestion(categorie="  vaisselle ")
        resp = self._upload()
        self.assertEqual(resp.data["category_id"], str(self.categorie["id"]))
        # Le libellé renvoyé est celui du catalogue, pas celui du modèle.
        self.assertEqual(resp.data["categorie"], "Vaisselle")

    @patch("accounts.views.describe_image")
    def test_categorie_inconnue_reste_une_proposition(self, mock_describe):
        mock_describe.return_value = self._suggestion(categorie="Outillage")
        resp = self._upload()
        self.assertIsNone(resp.data["category_id"])
        self.assertEqual(resp.data["categorie"], "Outillage")

    @patch("accounts.views.describe_image")
    def test_reference_suggeree_evite_les_doublons(self, mock_describe):
        mock_describe.return_value = self._suggestion()
        Item.objects.create(
            business=Business.objects.get(id=self.business["id"]),
            nom="Autre tasse",
            reference="TAS-BLE-001",
        )
        resp = self._upload()
        self.assertEqual(resp.data["reference"], "TAS-BLE-002")

    @patch("accounts.views.describe_image")
    def test_categories_du_business_transmises_au_modele(self, mock_describe):
        mock_describe.return_value = self._suggestion()
        self._upload()
        self.assertEqual(mock_describe.call_args.args[2], ["Vaisselle"])

    @patch("accounts.views.describe_image")
    def test_sans_header_business_pas_de_rattachement(self, mock_describe):
        mock_describe.return_value = self._suggestion()
        resp = self._upload(avec_business=False)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsNone(resp.data["category_id"])
        self.assertEqual(resp.data["reference"], "")
        self.assertEqual(mock_describe.call_args.args[2], [])

    @patch("accounts.views.describe_image")
    def test_business_d_un_autre_membre_ignore(self, mock_describe):
        # Un header X-Business-ID pointant un business dont on n'est pas
        # membre ne donne accès ni aux catégories ni aux références (RM-01).
        mock_describe.return_value = self._suggestion()
        autre = make_business(self.client, self.token_b, "Business de Bob").data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        resp = self.client.post(
            "/api/ai/image-description/",
            {"image": self._photo()},
            format="multipart",
            **self._headers(autre["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsNone(resp.data["category_id"])
        self.assertEqual(resp.data["reference"], "")

    def test_parse_json_structure(self):
        import json as jsonlib

        from .ai import _parse

        result = _parse(
            jsonlib.dumps(
                {
                    "nom": "Chaise pliante",
                    "description": "Chaise en bois.",
                    "categorie": "Mobilier",
                    "unite": "pièce",
                    "etat": "BON",
                    "caracteristiques": [
                        {"libelle": "Matière", "valeur": "Bois"},
                        {"libelle": "Matière", "valeur": "Doublon ignoré"},
                        {"libelle": "", "valeur": "Sans libellé"},
                    ],
                    "confiance": "HAUTE",
                }
            )
        )
        self.assertEqual(result["nom"], "Chaise pliante")
        self.assertEqual(result["etat"], "BON")
        self.assertEqual(result["caracteristiques"], {"Matière": "Bois"})
        self.assertEqual(result["confiance"], "HAUTE")

    def test_parse_json_valeurs_hors_enum_ramenees_au_defaut(self):
        import json as jsonlib

        from .ai import _parse

        result = _parse(
            jsonlib.dumps(
                {
                    "nom": "Objet",
                    "description": "Description.",
                    "etat": "PARFAIT",
                    "confiance": "TOTALE",
                }
            )
        )
        self.assertEqual(result["etat"], "INCONNU")
        self.assertEqual(result["confiance"], "MOYENNE")

    def test_parse_repli_sur_ancien_format_texte(self):
        from .ai import _parse

        result = _parse("NOM: Tente 3x3\nDESCRIPTION: Tente de camping.")
        self.assertEqual(result["nom"], "Tente 3x3")
        self.assertEqual(result["description"], "Tente de camping.")
        self.assertEqual(result["confiance"], "FAIBLE")

    def test_suggerer_reference(self):
        from .ai import suggerer_reference

        self.assertEqual(
            suggerer_reference("Chaise pliante en bois", []), "CHA-PLI-BOI-001"
        )
        # Les mots vides ne polluent pas le préfixe.
        self.assertEqual(suggerer_reference("Nappe pour table", []), "NAP-TAB-001")
        # Les accents sont retirés.
        self.assertEqual(suggerer_reference("Théière", []), "THE-001")
        # Sans nom exploitable, pas de suggestion.
        self.assertEqual(suggerer_reference("", []), "")
        self.assertEqual(suggerer_reference("de la", []), "")

    @patch("accounts.ai.urllib.request.urlopen")
    def test_categories_injectees_dans_le_prompt(self, mock_open):
        import json as jsonlib

        from . import ai

        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = lambda *a: None
        mock_open.return_value.read.return_value = jsonlib.dumps(
            {"candidates": [{"content": {"parts": [{"text": "{}"}]}}]}
        ).encode("utf-8")
        ai.describe_image(b"photo", "image/jpeg", ["Mobilier", "Vaisselle"])
        body = jsonlib.loads(mock_open.call_args.args[0].data)
        prompt = body["contents"][0]["parts"][0]["text"]
        self.assertIn('"Mobilier"', prompt)
        self.assertIn('"Vaisselle"', prompt)
        # La sortie est contrainte par un schéma JSON.
        self.assertEqual(
            body["generationConfig"]["responseMimeType"], "application/json"
        )


class ControleRetourTests(BaseSetup):
    """Sprint 8 bis : contrôle de retour à la terminaison d'une location.

    Décompte retourné / abîmé / perdu, observations, et reclassification
    comptable du stock (RETOUR global puis DOMMAGE/PERTE).
    """

    def _make_business(self):
        resp = make_business(self.client, self.token_a, "Agence Alpha")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        return resp.data

    def _headers(self, business_id):
        return {"HTTP_X_BUSINESS_ID": str(business_id)}

    def _make_item(self, business, nom="Tente 3x3"):
        return self.client.post(
            f"/api/businesses/{business['id']}/items/",
            {"nom": nom}, format="json",
            **self._headers(business["id"]),
        ).data

    def _entree(self, business, item_id, quantite):
        return self.client.post(
            f"/api/businesses/{business['id']}/stock/movements/",
            {"type": "ENTREE", "item_id": str(item_id), "quantite": quantite,
             "motif": "achat"},
            format="json",
            **self._headers(business["id"]),
        )

    def _promote(self, business, email, role_nom):
        roles = {
            r["nom"]: r["id"]
            for r in self.client.get(
                f"/api/businesses/{business['id']}/roles/",
                **self._headers(business["id"]),
            ).data["results"]
        }
        invite = self.client.post(
            f"/api/businesses/{business['id']}/members/",
            {"email": email, "role_id": roles[role_nom]},
            format="json",
            **self._headers(business["id"]),
        ).data
        member = BusinessMember.objects.get(id=invite["id"])
        member.statut = BusinessMember.Statut.ACTIF
        member.save()

    def _reserver(self, business, item_id, quantite):
        resp = self.client.post(
            f"/api/businesses/{business['id']}/reservations/",
            {"item_id": str(item_id), "date_debut": "2026-09-01",
             "date_fin": "2026-09-10", "quantite": quantite, "motif": "Salon pro"},
            format="json",
            **self._headers(business["id"]),
        )
        return resp.data

    def _en_cours(self, business, reservation_id):
        self.client.post(
            f"/api/businesses/{business['id']}/reservations/{reservation_id}/valider/",
            {}, format="json",
            **self._headers(business["id"]),
        )
        return self.client.post(
            f"/api/businesses/{business['id']}/reservations/{reservation_id}/demarrer/",
            {}, format="json",
            **self._headers(business["id"]),
        ).data

    def _terminer(self, business, reservation_id, data):
        return self.client.post(
            f"/api/businesses/{business['id']}/reservations/{reservation_id}/terminer/",
            data, format="json",
            **self._headers(business["id"]),
        )

    def _stock(self, business, item_id):
        return self.client.get(
            f"/api/businesses/{business['id']}/items/{item_id}/stock/",
            **self._headers(business["id"]),
        ).data

    def _movements(self, item_id):
        return StockMovement.objects.filter(item_id=item_id).order_by("created_at")

    # --- décompte du retour ------------------------------------------------

    def test_retour_sans_controle_tout_est_rendu(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        resa = self._reserver(business, item["id"], 3)
        self._en_cours(business, resa["id"])
        resp = self._terminer(business, resa["id"], {})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["statut"], "TERMINEE")
        self.assertEqual(resp.data["quantite_retournee"], 3)
        self.assertEqual(resp.data["quantite_abimee"], 0)
        self.assertEqual(resp.data["quantite_perdue"], 0)
        self.assertIsNotNone(resp.data["retourne_le"])
        stock = self._stock(business, item["id"])
        self.assertEqual(stock["sorties"], 0)
        self.assertEqual(stock["disponibles"], 10)

    def test_retour_avec_abimes_et_perdus_decompte_le_stock(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        resa = self._reserver(business, item["id"], 10)
        self._en_cours(business, resa["id"])
        resp = self._terminer(business, resa["id"], {
            "quantite_retournee": 7,
            "quantite_abimee": 2,
            "quantite_perdue": 1,
            "observations": "Une tente déchirée, une autre jamais rendue.",
        })
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["quantite_retournee"], 7)
        self.assertEqual(resp.data["quantite_abimee"], 2)
        self.assertEqual(resp.data["quantite_perdue"], 1)
        self.assertEqual(
            resp.data["observations"], "Une tente déchirée, une autre jamais rendue."
        )
        stock = self._stock(business, item["id"])
        self.assertEqual(stock["total"], 9)
        self.assertEqual(stock["perdus"], 1)
        self.assertEqual(stock["endommages"], 2)
        self.assertEqual(stock["sorties"], 0)
        self.assertEqual(stock["disponibles"], 7)
        types = sorted(m.type for m in self._movements(item["id"]))
        self.assertEqual(types, ["DOMMAGE", "ENTREE", "PERTE", "RETOUR", "SORTIE"])
        retour = next(m for m in self._movements(item["id"]) if m.type == "RETOUR")
        self.assertEqual(retour.quantite, 10)

    def test_presque_tout_perdu(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        resa = self._reserver(business, item["id"], 10)
        self._en_cours(business, resa["id"])
        resp = self._terminer(business, resa["id"], {
            "quantite_retournee": 1,
            "quantite_abimee": 1,
            "quantite_perdue": 8,
        })
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        stock = self._stock(business, item["id"])
        self.assertEqual(stock["total"], 2)
        self.assertEqual(stock["perdus"], 8)
        self.assertEqual(stock["endommages"], 1)
        self.assertEqual(stock["disponibles"], 1)

    def test_decompte_inexact_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        resa = self._reserver(business, item["id"], 10)
        self._en_cours(business, resa["id"])
        resp = self._terminer(business, resa["id"], {
            "quantite_retournee": 7,
            "quantite_abimee": 1,
            "quantite_perdue": 1,
        })
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("décompte", str(resp.data).lower())

    def test_decompte_negatif_refuse(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        resa = self._reserver(business, item["id"], 10)
        self._en_cours(business, resa["id"])
        resp = self._terminer(business, resa["id"], {"quantite_retournee": -1})
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_activite_detail_du_controle(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        resa = self._reserver(business, item["id"], 10)
        self._en_cours(business, resa["id"])
        self._terminer(business, resa["id"], {
            "quantite_retournee": 7,
            "quantite_abimee": 2,
            "quantite_perdue": 1,
        })
        resp = self.client.get(
            f"/api/businesses/{business['id']}/activities/?action=RESERVATION.TERMINEE",
            **self._headers(business["id"]),
        )
        detail = resp.data["results"][0]["detail"]
        self.assertEqual(detail["retourne"], 7)
        self.assertEqual(detail["abime"], 2)
        self.assertEqual(detail["perdu"], 1)

    def test_notification_pertes_aux_managers(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        self._promote(business, "bob@demo.com", RoleNom.ADMIN)
        resa = self._reserver(business, item["id"], 10)
        self._en_cours(business, resa["id"])
        self._terminer(business, resa["id"], {
            "quantite_retournee": 8,
            "quantite_abimee": 1,
            "quantite_perdue": 1,
        })
        notifications = Notification.objects.filter(
            business_id=business["id"],
            user__email="bob@demo.com",
            code="RESERVATION.RETOUR",
        )
        self.assertEqual(notifications.count(), 1)
        self.assertIn("1 perdu", notifications.first().message)

    def test_reservation_sans_controle_affichait_champs_vides(self):
        business = self._make_business()
        item = self._make_item(business)
        self._entree(business, item["id"], 10)
        resa = self._reserver(business, item["id"], 2)
        resp = self.client.get(
            f"/api/businesses/{business['id']}/reservations/{resa['id']}/",
            **self._headers(business["id"]),
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIsNone(resp.data["quantite_retournee"])
        self.assertIsNone(resp.data["retourne_le"])

class HealthTests(APITestCase):
    """Sonde d'accessibilite du backend (Offline-First)."""

    def test_health_is_public_and_fast(self):
        resp = self.client.get("/api/health/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.json()["status"], "ok")

    def test_health_reports_server_time(self):
        # Le client s'en sert pour mesurer la derive d'horloge de l'appareil,
        # qui fausserait un arbitrage "derniere ecriture gagne".
        resp = self.client.get("/api/health/")
        self.assertIn("server_time", resp.json())


class IdempotencyTests(BaseSetup):
    """Rejeu des mutations : un reessai ne doit jamais creer de doublon.

    C'est la garantie qui rend la synchronisation hors ligne sure : sans elle,
    un client qui perd la reponse d'une creation doit choisir entre risquer un
    doublon et risquer de perdre l'operation.
    """

    def setUp(self):
        super().setUp()
        resp = make_business(self.client, self.token_a)
        self.business_id = resp.data["id"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        item = self.client.post(
            f"/api/businesses/{self.business_id}/items/",
            {"nom": "Perceuse"},
            format="json",
            HTTP_X_BUSINESS_ID=str(self.business_id),
        )
        self.assertEqual(item.status_code, status.HTTP_201_CREATED)
        self.item_id = item.data["id"]

    def _create_category(self, key=None, nom="Outillage"):
        headers = {"HTTP_X_BUSINESS_ID": str(self.business_id)}
        if key:
            headers["HTTP_IDEMPOTENCY_KEY"] = key
        return self.client.post(
            f"/api/businesses/{self.business_id}/categories/",
            {"nom": nom},
            format="json",
            **headers,
        )

    def test_replaying_a_create_does_not_duplicate(self):
        first = self._create_category(key="op-1")
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)

        # Meme cle : le client reessaie apres avoir perdu la reponse.
        second = self._create_category(key="op-1")
        self.assertEqual(second.status_code, status.HTTP_201_CREATED)
        self.assertEqual(second["Idempotent-Replay"], "true")
        self.assertEqual(second.json()["id"], first.json()["id"])

        listing = self.client.get(
            f"/api/businesses/{self.business_id}/categories/",
            HTTP_X_BUSINESS_ID=str(self.business_id),
        )
        names = [c["nom"] for c in listing.data["results"]]
        self.assertEqual(names.count("Outillage"), 1)

    def _create_movement(self, key=None, quantite=5):
        """Entree de stock : journal append-only, sans contrainte d'unicite.

        C'est le cas ou un doublon fait vraiment mal : deux entrees identiques
        rejouees faussent silencieusement le stock, sans aucune erreur visible.
        """
        headers = {"HTTP_X_BUSINESS_ID": str(self.business_id)}
        if key:
            headers["HTTP_IDEMPOTENCY_KEY"] = key
        return self.client.post(
            f"/api/businesses/{self.business_id}/stock/movements/",
            {
                "type": "ENTREE",
                "item_id": str(self.item_id),
                "quantite": quantite,
            },
            format="json",
            **headers,
        )

    def _movement_count(self):
        return StockMovement.objects.filter(item_id=self.item_id).count()

    def test_replaying_a_stock_movement_does_not_double_the_stock(self):
        first = self._create_movement(key="mv-1", quantite=5)
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)

        # Le client n'a pas recu la reponse et reessaie la meme operation.
        replay = self._create_movement(key="mv-1", quantite=5)
        self.assertEqual(replay["Idempotent-Replay"], "true")
        self.assertEqual(self._movement_count(), 1)

    def test_without_key_a_replay_duplicates_the_stock_movement(self):
        # Documente pourquoi la cle est necessaire : sans elle, le meme appel
        # repete enregistre bien deux entrees, et le stock est faux.
        self._create_movement(quantite=5)
        self._create_movement(quantite=5)
        self.assertEqual(self._movement_count(), 2)

    def test_same_key_different_body_is_rejected(self):
        self._create_category(key="op-2", nom="Premiere")
        resp = self._create_category(key="op-2", nom="Seconde")
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT)

    def test_keys_are_scoped_per_user(self):
        # La cle d'un appareil ne doit ni lire ni ecraser la reponse d'un autre
        # compte : bob reutilise la cle d'alice et obtient son propre resultat.
        self._create_category(key="shared", nom="Chez Alice")

        make_business(self.client, self.token_b, nom="Business de Bob")
        bob_business = Business.objects.get(nom="Business de Bob")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_b}")
        resp = self.client.post(
            f"/api/businesses/{bob_business.id}/categories/",
            {"nom": "Chez Bob"},
            format="json",
            HTTP_X_BUSINESS_ID=str(bob_business.id),
            HTTP_IDEMPOTENCY_KEY="shared",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.json()["nom"], "Chez Bob")

    def test_failed_mutations_are_not_memorised(self):
        # Un echec doit rester reessayable : le memoriser figerait l'erreur.
        bad = self.client.post(
            f"/api/businesses/{self.business_id}/categories/",
            {},
            format="json",
            HTTP_X_BUSINESS_ID=str(self.business_id),
            HTTP_IDEMPOTENCY_KEY="op-3",
        )
        self.assertGreaterEqual(bad.status_code, 400)

        good = self._create_category(key="op-3", nom="Apres correction")
        self.assertEqual(good.status_code, status.HTTP_201_CREATED)

    def test_expired_record_lets_the_operation_through(self):
        from datetime import timedelta

        from django.utils import timezone as dj_timezone

        from .idempotency import RETENTION
        from .models import IdempotencyRecord

        self._create_movement(key="mv-old")
        IdempotencyRecord.objects.update(
            created_at=dj_timezone.now() - RETENTION - timedelta(days=1)
        )

        # Au-dela de la retention, la cle ne protege plus : un client revenu
        # apres des semaines repart normalement plutot que d'etre bloque.
        resp = self._create_movement(key="mv-old")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertNotIn("Idempotent-Replay", resp)


class IdempotencyResilienceTests(BaseSetup):
    """Le middleware ne doit jamais faire echouer une requete par lui-meme.

    Regression constatee en conditions reelles : la table d'idempotence
    n'existait pas (migration non appliquee), et *toutes* les mutations
    renvoyaient 500. Une fonction de confort ne doit pas pouvoir provoquer une
    panne totale des ecritures.
    """

    def setUp(self):
        super().setUp()
        resp = make_business(self.client, self.token_a)
        self.business_id = resp.data["id"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def _create(self, nom):
        return self.client.post(
            f"/api/businesses/{self.business_id}/categories/",
            {"nom": nom},
            format="json",
            HTTP_X_BUSINESS_ID=str(self.business_id),
            HTTP_IDEMPOTENCY_KEY="cle-quelconque",
        )

    def test_lecture_impossible_laisse_passer_la_mutation(self):
        from unittest.mock import patch

        from django.db.utils import ProgrammingError

        with patch(
            "accounts.idempotency.IdempotencyMiddleware._lookup",
            side_effect=ProgrammingError("relation inexistante"),
        ):
            resp = self._create("Sans idempotence")

        # La protection contre les doublons est perdue, mais l'utilisateur peut
        # continuer a travailler.
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_memorisation_impossible_ne_casse_pas_la_reponse(self):
        from unittest.mock import patch

        from django.db.utils import DatabaseError

        with patch(
            "accounts.idempotency._remember",
            side_effect=DatabaseError("ecriture impossible"),
        ):
            resp = self._create("Reponse intacte")

        # La mutation a reussi : sa reponse doit partir telle quelle.
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.json()["nom"], "Reponse intacte")

    def test_une_requete_sans_cle_ne_touche_jamais_la_table(self):
        from unittest.mock import patch

        with patch(
            "accounts.idempotency.IdempotencyMiddleware._lookup"
        ) as lookup:
            resp = self.client.post(
                f"/api/businesses/{self.business_id}/categories/",
                {"nom": "Sans en-tete"},
                format="json",
                HTTP_X_BUSINESS_ID=str(self.business_id),
            )

        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        lookup.assert_not_called()


class ItemReferenceViewTests(BaseSetup):
    """Proposition de reference : sans IA, sans photo, sans cout."""

    def setUp(self):
        super().setUp()
        resp = make_business(self.client, self.token_a)
        self.business_id = resp.data["id"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def _headers(self):
        return {"HTTP_X_BUSINESS_ID": str(self.business_id)}

    def _next_reference(self, nom):
        return self.client.get(
            f"/api/businesses/{self.business_id}/items/next-reference/",
            {"nom": nom},
            **self._headers(),
        )

    def _create_item(self, nom, reference=None):
        data = {"nom": nom}
        if reference:
            data["reference"] = reference
        return self.client.post(
            f"/api/businesses/{self.business_id}/items/",
            data,
            format="json",
            **self._headers(),
        )

    def test_propose_une_reference_derivee_du_nom(self):
        resp = self._next_reference("Chaise pliante en bois")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.json()["reference"], "CHA-PLI-BOI-001")

    def test_la_reference_proposee_est_libre_dans_le_catalogue(self):
        self._create_item("Chaise pliante en bois", "CHA-PLI-BOI-001")
        resp = self._next_reference("Chaise pliante en bois")
        # La proposition doit tenir compte de ce qui est deja pris, sinon la
        # creation echouerait sur la contrainte d'unicite.
        self.assertEqual(resp.json()["reference"], "CHA-PLI-BOI-002")

    def test_sans_nom_la_proposition_est_vide_et_expliquee(self):
        resp = self._next_reference("")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.json()["reference"], "")
        self.assertTrue(resp.json()["detail"])

    def test_aucun_appel_ia_n_est_necessaire(self):
        # Garde-fou : cette route ne doit jamais dependre de Gemini. Si un jour
        # quelqu'un l'y branche, ce test tombe.
        from unittest.mock import patch

        with patch("accounts.ai._post_gemini") as gemini:
            resp = self._next_reference("Table ronde")

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        gemini.assert_not_called()

    def test_la_reference_reste_facultative_a_la_creation(self):
        # L'utilisateur doit pouvoir creer un article sans reference du tout.
        resp = self._create_item("Article sans reference")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn(resp.json().get("reference"), (None, ""))


class ItemDescriptionViewTests(BaseSetup):
    """Generation IA a partir d'un texte, sans photo."""

    def setUp(self):
        super().setUp()
        resp = make_business(self.client, self.token_a)
        self.business_id = resp.data["id"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")

    def _post(self, payload):
        return self.client.post(
            "/api/ai/item-description/",
            payload,
            format="json",
            HTTP_X_BUSINESS_ID=str(self.business_id),
        )

    def test_generation_a_partir_du_nom(self):
        from unittest.mock import patch

        faux = {
            "nom": "Chaise en bois",
            "description": "Chaise robuste en bois massif.",
            "unite": "piece",
            "categorie": "",
            "etat": "BON",
            "caracteristiques": {},
            "confiance": "HAUTE",
        }
        with patch("accounts.item_assist.decrire_depuis_texte", return_value=faux) as ia:
            resp = self._post({"source": "nom", "nom": "Chaise en bois"})

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(
            resp.json()["description"], "Chaise robuste en bois massif."
        )
        # La consigne envoyee au modele doit bien contenir le nom saisi.
        consigne = ia.call_args.args[0]
        self.assertIn("Chaise en bois", consigne)

    def test_amelioration_transmet_la_description_actuelle(self):
        from unittest.mock import patch

        faux = {"nom": "", "description": "Reformule.", "unite": "",
                "categorie": "", "etat": "INCONNU", "caracteristiques": {},
                "confiance": "MOYENNE"}
        with patch("accounts.item_assist.decrire_depuis_texte", return_value=faux) as ia:
            resp = self._post({
                "source": "amelioration",
                "description_actuelle": "Chaise en bois pour salle de conference",
            })

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        consigne = ia.call_args.args[0]
        self.assertIn("salle de conference", consigne)

    def test_une_demande_vide_est_refusee_sans_appeler_l_ia(self):
        from unittest.mock import patch

        # Faire deviner le modele a partir de rien coute un appel pour un
        # resultat inutilisable.
        with patch("accounts.item_assist.decrire_depuis_texte") as ia:
            resp = self._post({"source": "nom", "nom": "   "})

        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        ia.assert_not_called()

    def test_source_inconnue_refusee(self):
        resp = self._post({"source": "telepathie"})
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_la_generation_ne_propose_jamais_de_reference(self):
        from unittest.mock import patch

        faux = {"nom": "Table", "description": "Une table.", "unite": "",
                "categorie": "", "etat": "INCONNU", "caracteristiques": {},
                "confiance": "HAUTE"}
        with patch("accounts.item_assist.decrire_depuis_texte", return_value=faux):
            resp = self._post({"source": "nom", "nom": "Table"})

        # La reference a sa propre route, gratuite : la melanger ici
        # obligerait a payer un appel IA pour l'obtenir.
        self.assertEqual(resp.json()["reference"], "")
