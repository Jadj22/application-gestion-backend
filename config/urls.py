from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path
from django.views.decorators.http import require_GET
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


@require_GET
def assetlinks(request):
    """/.well-known/assetlinks.json : vérification du domaine pour les App
    Links Android (lien d'invitation). Vide tant que l'ID de package et
    l'empreinte SHA-256 du certificat ne sont pas renseignés dans le .env.
    """
    package = settings.ANDROID_PACKAGE_NAME
    sha256 = settings.ANDROID_SHA256_CERT
    if not (package and sha256):
        return JsonResponse([], safe=False)
    return JsonResponse(
        [
            {
                "relation": ["delegate_permission/common.handle_all_urls"],
                "target": {
                    "namespace": "android_app",
                    "package_name": package,
                    "sha256_cert_fingerprints": [sha256],
                },
            }
        ],
        safe=False,
    )


urlpatterns = [
    path(".well-known/assetlinks.json", assetlinks),
    path("admin/", admin.site.urls),
    path("api/", include("accounts.urls")),
    path(
        "api/schema/",
        SpectacularAPIView.as_view(),
        name="schema",
    ),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="docs",
    ),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)