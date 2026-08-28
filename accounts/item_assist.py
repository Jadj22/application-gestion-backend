"""Aides à la saisie d'un article : référence et génération IA depuis un texte.

Deux besoins distincts, volontairement séparés en deux routes :

* **Proposer une référence** — pur calcul déterministe, aucune IA, aucun coût.
  Le confondre avec l'analyse de photo obligeait l'utilisateur à passer par
  l'IA (et à en payer le coût) pour la seule chose qui n'en a jamais eu besoin.

* **Générer une description** — appel Gemini, mais à partir de ce que
  l'utilisateur a choisi de fournir : le nom déjà saisi, des mots-clés, les
  champs du formulaire, une consigne libre, ou la description actuelle à
  reformuler. La photo n'est plus la seule porte d'entrée.

Dans les deux cas, le serveur *propose* ; c'est l'application qui décide de ce
qu'elle applique, et l'utilisateur qui valide.
"""

from django.conf import settings
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .ai import GeminiError, decrire_depuis_texte, suggerer_reference
from .permissions import HasBusinessPermission, get_membership
from .rbac import Perm


class NextReferenceSerializer(serializers.Serializer):
    """Entrée de la proposition de référence."""

    nom = serializers.CharField(required=False, allow_blank=True, max_length=200)


class ItemReferenceView(APIView):
    """`GET /businesses/<id>/items/next-reference/?nom=...`

    Renvoie une référence libre dans le catalogue du business, dérivée du nom.

    Volontairement **sans IA** : c'est une normalisation de chaîne suivie d'un
    compteur. La router par Gemini coûterait un appel payant, exigerait une
    photo, et échouerait hors ligne — pour un résultat identique.

    L'unicité est vérifiée ici, sur le catalogue réel : c'est le seul endroit
    qui connaît toutes les références déjà prises, y compris celles créées par
    les autres membres de l'équipe.
    """

    permission_classes = [HasBusinessPermission.require(Perm.CATALOG_VIEW)]
    serializer_class = NextReferenceSerializer

    def get(self, request, business_id):
        serializer = NextReferenceSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        nom = serializer.validated_data.get("nom", "")

        business = request.business
        prises = business.items.exclude(reference__isnull=True).values_list(
            "reference", flat=True
        )
        reference = suggerer_reference(nom, prises)
        return Response(
            {
                "reference": reference,
                # L'application peut ainsi expliquer pourquoi le champ reste
                # vide au lieu d'afficher un échec silencieux.
                "detail": ""
                if reference
                else "Saisissez d'abord un nom pour proposer une référence.",
            }
        )


class ItemDescriptionSerializer(serializers.Serializer):
    """Entrée de la génération de description.

    `source` dit d'où viennent les informations. Le champ existe pour que le
    serveur construise une consigne adaptée — et pour que l'intention de
    l'utilisateur reste explicite jusqu'au bout de la chaîne.
    """

    SOURCES = ("nom", "mots_cles", "champs", "amelioration", "libre")

    source = serializers.ChoiceField(choices=SOURCES)
    nom = serializers.CharField(required=False, allow_blank=True, max_length=200)
    mots_cles = serializers.CharField(
        required=False, allow_blank=True, max_length=500
    )
    description_actuelle = serializers.CharField(
        required=False, allow_blank=True, max_length=2000
    )
    consigne = serializers.CharField(
        required=False, allow_blank=True, max_length=1000
    )
    categorie = serializers.CharField(
        required=False, allow_blank=True, max_length=150
    )
    marque = serializers.CharField(required=False, allow_blank=True, max_length=150)
    reference = serializers.CharField(
        required=False, allow_blank=True, max_length=100
    )
    unite = serializers.CharField(required=False, allow_blank=True, max_length=30)
    prix = serializers.CharField(required=False, allow_blank=True, max_length=50)
    caracteristiques = serializers.DictField(
        child=serializers.CharField(allow_blank=True, max_length=200),
        required=False,
    )

    def validate(self, attrs):
        """Refuse une demande vide plutôt que de faire deviner le modèle."""
        source = attrs["source"]
        exigences = {
            "nom": ("nom", "Renseignez le nom de l'article."),
            "mots_cles": ("mots_cles", "Saisissez au moins un mot-clé."),
            "amelioration": (
                "description_actuelle",
                "Écrivez d'abord une description à améliorer.",
            ),
            "libre": ("consigne", "Décrivez ce que vous attendez."),
        }
        if source in exigences:
            champ, message = exigences[source]
            if not (attrs.get(champ) or "").strip():
                raise serializers.ValidationError({champ: message})
        elif source == "champs" and not any(
            (attrs.get(c) or "").strip()
            for c in ("nom", "categorie", "marque", "reference", "unite", "prix")
        ):
            raise serializers.ValidationError(
                {"detail": "Renseignez au moins un champ du formulaire."}
            )
        return attrs


class ItemDescriptionView(APIView):
    """`POST /ai/item-description/` — génère une fiche article sans photo.

    Pendant textuel de l'analyse d'image : même forme de réponse, donc
    l'application traite les propositions de la même façon quelle que soit la
    source choisie par l'utilisateur.
    """

    serializer_class = ItemDescriptionSerializer
    # Memes garde-fous que l'analyse d'image : la generation est payante.
    throttle_scopes = ("write", "ai")

    def post(self, request):
        if not settings.GEMINI_API_KEY:
            return Response(
                {"detail": "La génération IA n'est pas configurée."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        serializer = ItemDescriptionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        membership = get_membership(request)
        business = membership.business if membership else None
        categories = (
            list(business.categories.values_list("nom", flat=True))
            if business
            else []
        )

        try:
            result = decrire_depuis_texte(
                _consigne(data), categories=categories
            )
        except GeminiError as exc:
            if exc.retryable:
                detail = (
                    "La génération IA est temporairement indisponible "
                    "(forte demande). Réessayez dans quelques instants."
                )
                code = status.HTTP_503_SERVICE_UNAVAILABLE
            else:
                detail = str(exc)
                code = status.HTTP_502_BAD_GATEWAY
            return Response({"detail": detail}, status=code)

        # Contrairement à l'analyse d'image, on ne propose pas de référence
        # ici : elle a sa propre route, sans coût ni réseau IA.
        result = dict(result)
        result["reference"] = ""
        result["category_id"] = _categorie_existante(result, business)
        return Response(result)


def _categorie_existante(result, business):
    """Identifiant de la catégorie proposée si elle existe déjà, sinon None."""
    if business is None:
        return None
    libelle = (result.get("categorie") or "").strip().casefold()
    if not libelle:
        return None
    for categorie in business.categories.all():
        if categorie.nom.strip().casefold() == libelle:
            return str(categorie.id)
    return None


def _consigne(data):
    """Traduit le choix de l'utilisateur en consigne pour le modèle."""
    source = data["source"]
    lignes = []

    def ajouter(libelle, cle):
        valeur = (data.get(cle) or "").strip()
        if valeur:
            lignes.append(f"{libelle} : {valeur}")

    if source == "nom":
        ajouter("Nom de l'article", "nom")
        lignes.append(
            "Rédige une description de catalogue pour cet article."
        )
    elif source == "mots_cles":
        ajouter("Mots-clés", "mots_cles")
        ajouter("Nom de l'article", "nom")
        lignes.append(
            "Rédige un nom court et une description à partir de ces mots-clés."
        )
    elif source == "amelioration":
        ajouter("Description actuelle", "description_actuelle")
        ajouter("Nom de l'article", "nom")
        lignes.append(
            "Reformule cette description pour la rendre plus claire et "
            "professionnelle, sans ajouter d'information nouvelle."
        )
    elif source == "libre":
        ajouter("Demande de l'utilisateur", "consigne")
        ajouter("Nom de l'article", "nom")
        ajouter("Description actuelle", "description_actuelle")
    else:  # champs
        for libelle, cle in (
            ("Nom", "nom"),
            ("Catégorie", "categorie"),
            ("Marque", "marque"),
            ("Référence", "reference"),
            ("Unité", "unite"),
            ("Prix", "prix"),
        ):
            ajouter(libelle, cle)
        caracteristiques = data.get("caracteristiques") or {}
        for libelle, valeur in list(caracteristiques.items())[:10]:
            if str(valeur).strip():
                lignes.append(f"{libelle} : {valeur}")
        lignes.append(
            "Rédige une description de catalogue à partir de ces informations."
        )

    return "\n".join(lignes)
