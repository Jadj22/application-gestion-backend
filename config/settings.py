"""
Configuration Django du projet backend_management.
Sprint 1 : Auth JWT + multi-tenant + RBAC.
"""

import os
from datetime import timedelta
from pathlib import Path
import dj_database_url

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Cloudinary - stockage des fichiers médias
CLOUDINARY_URL = os.getenv("CLOUDINARY_URL")

if not CLOUDINARY_URL:
    raise RuntimeError("CLOUDINARY_URL must be set")

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("DJANGO_SECRET_KEY must be set")

DEBUG = os.getenv("DJANGO_DEBUG", "True") == "True"

# Environnement : "development" par défaut, "production" pour les déploiements.
DJANGO_ENV = os.getenv("DJANGO_ENV", "production" if not DEBUG else "development")
IS_PROD = DJANGO_ENV == "production"


ALLOWED_HOSTS = [
    h.strip()
    for h in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if h.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "drf_spectacular",
    "accounts",
    "cloudinary",
    "cloudinary_storage",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.gzip.GZipMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Offline-First : rejoue la reponse d'une mutation deja traitee quand le
    # client reessaie apres une reponse perdue. Place apres l'authentification,
    # la cle d'idempotence etant cloisonnee par utilisateur.
    "accounts.idempotency.IdempotencyMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# Redis (optionnel) : cache public catalog + stock. REDIS_URL=redis://... sur Render
REDIS_URL = os.getenv("REDIS_URL", "")

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache" if REDIS_URL else "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": REDIS_URL or "unique-snowflake",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient" if REDIS_URL else "",
            "IGNORE_EXCEPTIONS": True,  # degrade gracieusement si Redis down
        },
        "KEY_PREFIX": "dodome",
        "TIMEOUT": 120,
    }
} if REDIS_URL else {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-snowflake",
    }
}

DATABASES = {
    "default": dj_database_url.config(
        default=os.getenv("DATABASE_URL"),
        # Pooling: Render PgBouncer recommandé (DATABASE_URL pooled). Avec pgbouncer, CONN_MAX_AGE=0
        # Sans pgbouncer, 60s réutilise la connexion par worker.
        conn_max_age=int(os.getenv("DB_CONN_MAX_AGE", "0" if "pooler" in os.getenv("DATABASE_URL", "") else "60")),
        conn_health_checks=True,
    )
}
# Pool local si pas de pgbouncer externe (ex: pgbouncer sidecar)
if not REDIS_URL and "pooler" not in os.getenv("DATABASE_URL", ""):
    DATABASES["default"]["CONN_MAX_AGE"] = int(os.getenv("DB_CONN_MAX_AGE", "60"))

AUTH_USER_MODEL = "accounts.User"

# Hachage des mots de passe : Argon2id en tête (~60 ms) plutôt que PBKDF2 à
# 1,5 M d'itérations (~2 s mesurées au banc de charge). Les hachages PBKDF2
# existants restent vérifiables et sont réécrits en Argon2 à la connexion
# suivante de chaque utilisateur : aucune réinitialisation nécessaire.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "fr-fr"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

STATIC_URL = "static/"

STATIC_ROOT = BASE_DIR / "staticfiles"

# Limites de taille de requête (S9) : payloads JSON raisonnables, photos
# d'article jusqu'à 5 Mo (le plafond multipart = max des deux + marge).
DATA_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 6 * 1024 * 1024

# Fichiers uploadés (photos d'articles, S 2-03)
# MEDIA_URL = "/media/"
# MEDIA_ROOT = BASE_DIR / "media"



STORAGES = {
    "default": {
        "BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "accounts.pagination.StandardPagination",
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.AnonRateThrottle",
        "accounts.throttling.ScopesRateThrottle",
    ),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

# Throttling (S9) : taux stricts en production, généreux hors production.
# Scopes utilisés : "auth" (login/register/refresh), "write" (mutations),
# "ai" (analyse d'image Gemini, coûteuse : bridée même en dev).
if IS_PROD:
    THROTTLE_RATES = {"anon": "30/min", "auth": "10/min", "write": "60/min", "ai": "10/min"}
else:
    THROTTLE_RATES = {"anon": "3000/min", "auth": "3000/min", "write": "3000/min", "ai": "30/min"}

REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = THROTTLE_RATES

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=int(os.getenv("REFRESH_TOKEN_DAYS", "7"))),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
}

# Le header X-Business-ID est envoyé par le client (RM-01)
BUSINESS_HEADER = "X-Business-ID"

# Clients OAuth 2.0 Google autorisés (aud de l'ID token envoyé par l'app).
# L'ID Android est celui du google-services.json ; on peut en ajouter
# d'autres (web, iOS...) séparés par des virgules.
GOOGLE_CLIENT_IDS = [
    c.strip()
    for c in os.getenv(
        "GOOGLE_CLIENT_IDS",
        "976579848816-0snvj73v3bhvh28prtmaqhn8rqlfleik.apps.googleusercontent.com,"
        "976579848816-gfq0r9uecquhjbictks7m6cffgqtm1gs.apps.googleusercontent.com,"
        "976579848816-e598kpiel6eict62066bdi7jut75nbmb.apps.googleusercontent.com,"
        "786231345880-61viiam43rsiqmb5o4rjeut03jcn6e1t.apps.googleusercontent.com",
    ).split(",")
    if c.strip()
]

CORS_ALLOW_ALL_ORIGINS = os.getenv("CORS_ALLOW_ALL", "False") == "True"

CORS_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]


CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]

CORS_ALLOW_HEADERS = [
    "accept",
    "authorization",
    "content-type",
    "x-business-id",
    # Offline-First : cle de rejeu des mutations (voir accounts.idempotency).
    "idempotency-key",
    "x-visitor-id",
]

# Emails (invitations des membres, Sprint 10) : SMTP via variables d'env.
EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend"
)
EMAIL_HOST = os.getenv("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "False") == "True"
DEFAULT_FROM_EMAIL = os.getenv(
    "DEFAULT_FROM_EMAIL", "DODOME <no-reply@dodome.app>"
)

# Invitations : base URL du lien (remplacée par le deep link Android),
# durée de validité du token signé et du code, sel du hash du code.
INVITATION_BASE_URL = os.getenv(
    "INVITATION_BASE_URL", "https://app.dodome.app/invitation"
)
INVITATION_TOKEN_MAX_AGE = int(os.getenv("INVITATION_TOKEN_DAYS", "7")) * 86400
INVITATION_CODE_DAYS = int(os.getenv("INVITATION_CODE_DAYS", "7"))
INVITATION_CODE_SALT = (
    os.getenv("INVITATION_CODE_SALT", "") or SECRET_KEY
)

# App Links Android (assetlinks.json, vérification de domaine) : renseigner
# l'ID de package et l'empreinte SHA-256 du certificat de signature.
ANDROID_PACKAGE_NAME = os.getenv("ANDROID_PACKAGE_NAME", "")
ANDROID_SHA256_CERT = os.getenv("ANDROID_SHA256_CERT", "")

# Gemini API (description automatique des photos d'articles, Sprint 10).
# La clé reste côté serveur : l'app passe par POST /api/ai/image-description/.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
# Modèle vision. gemini-2.0-flash a été retiré par Google (l'API répond
# « no longer available ») : on cible une version datée plutôt que l'alias
# gemini-flash-latest, souvent surchargé → 503 « high demand ».
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

# Sécurité transport (S9) : renforcée uniquement en production.
if IS_PROD:
    SECURE_SSL_REDIRECT = os.getenv("DJANGO_SECURE_SSL_REDIRECT", "True") == "True"
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

SPECTACULAR_SETTINGS = {
    "TITLE": "API Gestion d'équipement multi-tenant",
    "DESCRIPTION": (
        "Backend Django multi-tenant : auth JWT, catalogue, stock & traçabilité, "
        "entretien, fiabilité, alertes métier, activités, notifications et "
        "réservations. Toutes les listes GET renvoient l'enveloppe paginée "
        "{count, next, previous, results}."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
}