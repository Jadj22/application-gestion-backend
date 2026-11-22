from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


class Argon2SecurityTests(APITestCase):
    """Vérification du hasher Argon2 et de la rétrocompatibilité des mots de passe."""

    def test_argon2_hashing_and_verification(self):
        password = "TestSecurePassword123!"
        hashed = make_password(password)

        self.assertTrue(hashed.startswith("argon2$"))
        self.assertTrue(check_password(password, hashed))
        self.assertFalse(check_password("WrongPassword123!", hashed))

    def test_legacy_pbkdf2_password_compatibility(self):
        password = "LegacyPassword123!"
        pbkdf2_hash = make_password(password, hasher="pbkdf2_sha256")
        self.assertTrue(pbkdf2_hash.startswith("pbkdf2_sha256$"))

        # Vérification directe du hasher
        self.assertTrue(check_password(password, pbkdf2_hash))

        # Connexion d'un utilisateur existant avec un ancien mot de passe PBKDF2
        legacy_user = User.objects.create(
            email="legacy@example.com",
            username="legacy@example.com",
            password=pbkdf2_hash,
            statut=User.Statut.ACTIF,
        )
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "legacy@example.com", "password": password},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("access", resp.data)


class UserManagerTests(APITestCase):
    """Vérification des méthodes du UserManager et de l'unicité de username."""

    def test_create_user_sets_username_to_email(self):
        user1 = User.objects.create_user("user1@example.com", "password123")
        user2 = User.objects.create_user("user2@example.com", "password123")

        self.assertEqual(user1.username, "user1@example.com")
        self.assertEqual(user2.username, "user2@example.com")
        self.assertFalse(user1.is_staff)
        self.assertFalse(user1.is_superuser)
        self.assertTrue(user1.password.startswith("argon2$"))

    def test_create_superuser(self):
        admin = User.objects.create_superuser("admin@example.com", "adminpass123")
        self.assertEqual(admin.username, "admin@example.com")
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)


class RegistrationEndpointTests(APITestCase):
    """Tests détaillés de l'inscription."""

    def test_register_valid_user(self):
        data = {
            "email": "newuser@example.com",
            "password": "ValidPassword123!",
            "first_name": "Jean",
            "last_name": "Valjean",
        }
        resp = self.client.post("/api/auth/register/", data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("access", resp.data)
        self.assertIn("refresh", resp.data)
        self.assertEqual(resp.data["user"]["email"], "newuser@example.com")

        user = User.objects.get(email="newuser@example.com")
        self.assertTrue(user.password.startswith("argon2$"))
        self.assertEqual(user.username, "newuser@example.com")

    def test_register_duplicate_email_fails(self):
        User.objects.create_user("existing@example.com", "password123")
        data = {
            "email": "existing@example.com",
            "password": "ValidPassword123!",
        }
        resp = self.client.post("/api/auth/register/", data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_invalid_email_fails(self):
        data = {
            "email": "not-an-email",
            "password": "ValidPassword123!",
        }
        resp = self.client.post("/api/auth/register/", data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_missing_password_fails(self):
        data = {"email": "nopass@example.com"}
        resp = self.client.post("/api/auth/register/", data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_short_password_fails(self):
        data = {
            "email": "short@example.com",
            "password": "short",
        }
        resp = self.client.post("/api/auth/register/", data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class LoginEndpointTests(APITestCase):
    """Tests détaillés de la connexion."""

    def setUp(self):
        self.user = User.objects.create_user("active@example.com", "CorrectPassword123!")

    def test_login_success(self):
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "active@example.com", "password": "CorrectPassword123!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("access", resp.data)
        self.assertIn("refresh", resp.data)
        self.assertIn("user", resp.data)
        self.assertEqual(resp.data["user"]["email"], "active@example.com")

    def test_login_case_insensitive_email(self):
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "ACTIVE@EXAMPLE.COM", "password": "CorrectPassword123!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_login_wrong_password_returns_401(self):
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "active@example.com", "password": "WrongPassword!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("detail", resp.data)

    def test_login_nonexistent_user_returns_401(self):
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "nonexistent@example.com", "password": "AnyPassword123!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_inactive_status_returns_401(self):
        self.user.statut = User.Statut.INACTIF
        self.user.save()
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "active@example.com", "password": "CorrectPassword123!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_inactive_user_flag_returns_401(self):
        self.user.is_active = False
        self.user.save()
        resp = self.client.post(
            "/api/auth/login/",
            {"email": "active@example.com", "password": "CorrectPassword123!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)


class GoogleAuthEndpointTests(APITestCase):
    """Tests de l'authentification Google."""

    def test_google_auth_dummy_token_returns_401(self):
        resp = self.client.post(
            "/api/auth/google/",
            {"id_token": "string"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch("accounts.views._verify_google_id_token")
    def test_google_auth_valid_token_creates_user(self, mock_verify):
        mock_verify.return_value = {
            "sub": "google-sub-12345",
            "email": "googler@example.com",
            "given_name": "Google",
            "family_name": "User",
        }
        resp = self.client.post(
            "/api/auth/google/",
            {"id_token": "valid_mocked_token"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("access", resp.data)
        user = User.objects.get(email="googler@example.com")
        self.assertEqual(user.google_sub, "google-sub-12345")
        self.assertFalse(user.has_usable_password())

    @patch("accounts.views._verify_google_id_token")
    def test_google_auth_expired_or_invalid_audience(self, mock_verify):
        mock_verify.side_effect = ValueError("Token Google expiré ou audience invalide")
        resp = self.client.post(
            "/api/auth/google/",
            {"id_token": "expired_token"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)


class RoutesConsistencyTests(APITestCase):
    """Vérification de la cohérence des routes sans préfixe (/auth/) et avec préfixe (/api/auth/)."""

    def setUp(self):
        User.objects.create_user("route_test@example.com", "PasswordRoute123!")

    def test_login_routes_both_work(self):
        # Route sans préfixe
        resp1 = self.client.post(
            "/auth/login/",
            {"email": "route_test@example.com", "password": "PasswordRoute123!"},
            format="json",
        )
        self.assertEqual(resp1.status_code, status.HTTP_200_OK)

        # Route avec préfixe
        resp2 = self.client.post(
            "/api/auth/login/",
            {"email": "route_test@example.com", "password": "PasswordRoute123!"},
            format="json",
        )
        self.assertEqual(resp2.status_code, status.HTTP_200_OK)

    def test_register_routes_both_work(self):
        resp1 = self.client.post(
            "/auth/register/",
            {"email": "route1@example.com", "password": "PasswordRoute123!"},
            format="json",
        )
        self.assertEqual(resp1.status_code, status.HTTP_201_CREATED)

        resp2 = self.client.post(
            "/api/auth/register/",
            {"email": "route2@example.com", "password": "PasswordRoute123!"},
            format="json",
        )
        self.assertEqual(resp2.status_code, status.HTTP_201_CREATED)
