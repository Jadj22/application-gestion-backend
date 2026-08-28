"""Analyse d'image via l'API Gemini (Sprint 10, enrichi Sprint 12).

POST /api/ai/image-description/ reçoit la photo d'un article ; le backend
appelle Gemini avec l'image embarquée en base64 (inline_data) et renvoie une
fiche article pré-remplie : nom, description, catégorie, unité, état apparent
et caractéristiques. La clé API reste côté serveur (settings.GEMINI_API_KEY).

La réponse de Gemini est contrainte par un schéma JSON (`responseSchema`) :
plus de parsing de texte libre, donc plus de champ perdu quand le modèle
reformule sa sortie. Un repli sur l'ancien format « NOM: / DESCRIPTION: »
reste en place si le modèle renvoie malgré tout du texte brut.
"""

import base64
import json
import logging
import time
import urllib.error
import urllib.request

from django.conf import settings

logger = logging.getLogger(__name__)

# Codes HTTP Gemini temporaires : retry avec backoff avant d'échouer.
_RETRYABLE_HTTP_CODES = frozenset({429, 503})
_RETRY_DELAYS_SECONDS = (1.0, 2.0, 4.0)

# États apparents proposés à l'utilisateur (rangés dans `characteristics` :
# le champ `statut` de l'article, lui, ne vaut que ACTIF/INACTIF).
ETATS = ("NEUF", "BON", "USE", "ENDOMMAGE", "INCONNU")

CONFIANCES = ("HAUTE", "MOYENNE", "FAIBLE")

# Nombre maximum de caractéristiques retenues (garde-fou : le modèle peut
# être bavard, le formulaire mobile ne doit pas déborder).
MAX_CARACTERISTIQUES = 8

PROMPT = (
    "Tu es un assistant de gestion d'équipement. À partir de la photo, "
    "remplis la fiche d'un article de catalogue (matériel, décoration, "
    "mobilier, outils, vaisselle...).\n"
    "Règles :\n"
    "- Réponds en français.\n"
    "- `nom` : 2 à 5 mots, sans marque inventée.\n"
    "- `description` : 1 à 3 phrases — nature, usage, matériaux, couleurs, "
    "état apparent, texte lisible sur une étiquette.\n"
    "- `unite` : l'unité de comptage la plus naturelle (pièce, lot, paire, "
    "mètre, kg...).\n"
    "- `etat` : l'état visible sur la photo, parmi NEUF, BON, USE, "
    "ENDOMMAGE, INCONNU.\n"
    "- `caracteristiques` : au plus 6 couples libellé/valeur factuels et "
    "visibles (matière, couleur, dimensions, capacité...). N'invente rien.\n"
    "- `confiance` : HAUTE si l'article est net et identifiable, MOYENNE si "
    "tu hésites, FAIBLE si la photo est floue ou ambiguë.\n"
    "- Si aucun objet n'est identifiable : `nom` vide, `confiance` FAIBLE.\n"
)

_PROMPT_CATEGORIES = (
    "\n- `categorie` : choisis EXACTEMENT l'un des libellés suivants s'il "
    "convient, sinon propose un libellé court de ton choix : {libelles}.\n"
)

_PROMPT_SANS_CATEGORIE = (
    "\n- `categorie` : propose un libellé de catégorie court (1 à 3 mots).\n"
)

_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "nom": {"type": "STRING"},
        "description": {"type": "STRING"},
        "categorie": {"type": "STRING"},
        "unite": {"type": "STRING"},
        "etat": {"type": "STRING", "enum": list(ETATS)},
        "caracteristiques": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "libelle": {"type": "STRING"},
                    "valeur": {"type": "STRING"},
                },
                "required": ["libelle", "valeur"],
            },
        },
        "confiance": {"type": "STRING", "enum": list(CONFIANCES)},
    },
    "required": ["nom", "description", "confiance"],
}


class GeminiError(Exception):
    """Échec de l'appel à l'API Gemini (réseau, quota, réponse vide...)."""

    def __init__(self, message, *, http_code=None, retryable=False):
        super().__init__(message)
        self.http_code = http_code
        self.retryable = retryable


def _gemini_endpoint():
    model = settings.GEMINI_MODEL
    return (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent"
    )


def _parse_gemini_http_error(exc):
    """Extrait le message JSON de Gemini ou renvoie un libellé générique."""
    try:
        payload = json.loads(exc.read().decode("utf-8"))
        error = payload.get("error") or {}
        message = error.get("message")
        if message:
            return message
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        pass
    return f"Gemini a répondu {exc.code}."


def _build_prompt(categories):
    """Prompt complet, enrichi des catégories existantes du business."""
    if categories:
        libelles = ", ".join(f'"{c}"' for c in categories)
        return PROMPT + _PROMPT_CATEGORIES.format(libelles=libelles)
    return PROMPT + _PROMPT_SANS_CATEGORIE


def _call_gemini(image_bytes, mime_type, categories):
    """Un seul appel HTTP à l'API Gemini, à partir d'une photo (sans retry)."""
    return _post_gemini(
        [
            {"text": _build_prompt(categories)},
            {
                "inline_data": {
                    "mime_type": mime_type,
                    "data": base64.b64encode(image_bytes).decode("ascii"),
                }
            },
        ]
    )


def _call_gemini_texte(prompt):
    """Un seul appel HTTP à l'API Gemini, à partir d'un texte seul.

    Même schéma de réponse que l'analyse d'image : l'application reçoit une
    fiche article de la même forme, quelle que soit la source utilisée.
    """
    return _post_gemini([{"text": prompt}])


def _post_gemini(parts):
    """Envoie `parts` à Gemini et renvoie la fiche article analysée."""
    body = {
        "contents": [{"parts": parts}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 800,
            "responseMimeType": "application/json",
            "responseSchema": _RESPONSE_SCHEMA,
        },
    }
    request = urllib.request.Request(
        _gemini_endpoint(),
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-goog-api-key": settings.GEMINI_API_KEY,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = _parse_gemini_http_error(exc)
        logger.warning("Gemini HTTP %s : %s", exc.code, message[:300])
        retryable = exc.code in _RETRYABLE_HTTP_CODES
        raise GeminiError(message, http_code=exc.code, retryable=retryable) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise GeminiError("Impossible de joindre l'API Gemini.") from exc

    try:
        text = payload["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        logger.warning("Réponse Gemini inattendue : %s", payload)
        raise GeminiError("Réponse Gemini vide ou inattendue.") from exc
    return _parse(text)


def describe_image(image_bytes, mime_type="image/jpeg", categories=None):
    """Analyse la photo et retourne une fiche article pré-remplie.

    `categories` : libellés des catégories déjà créées par le business, pour
    que le modèle classe l'article dans l'une d'elles plutôt que d'en
    inventer une nouvelle à chaque photo.
    """
    last_error = None
    attempts = len(_RETRY_DELAYS_SECONDS) + 1
    for attempt in range(attempts):
        try:
            return _call_gemini(image_bytes, mime_type, categories or ())
        except GeminiError as exc:
            last_error = exc
            if exc.retryable and attempt < attempts - 1:
                delay = _RETRY_DELAYS_SECONDS[attempt]
                logger.info(
                    "Gemini %s, nouvel essai dans %.0fs (%d/%d)",
                    exc.http_code,
                    delay,
                    attempt + 2,
                    attempts,
                )
                time.sleep(delay)
                continue
            raise
    raise last_error  # pragma: no cover


PROMPT_TEXTE = (
    "Tu es un assistant de gestion d'équipement. À partir des informations "
    "fournies par l'utilisateur, remplis la fiche d'un article de catalogue.\n"
    "Règles :\n"
    "- Réponds en français.\n"
    "- N'invente aucune information factuelle (marque, dimensions, matière) "
    "qui ne soit pas déduite de ce que l'utilisateur a fourni.\n"
    "- `description` : 1 à 3 phrases, claires et professionnelles.\n"
    "- `unite` : l'unité de comptage la plus naturelle (pièce, lot, kg...).\n"
    "- `caracteristiques` : au plus 6 couples libellé/valeur, uniquement "
    "s'ils découlent des informations fournies.\n"
    "- `confiance` : FAIBLE si les informations sont trop maigres.\n"
)


def decrire_depuis_texte(consigne, *, categories=None):
    """Génère une fiche article à partir d'un texte, sans photo.

    C'est ce qui permet à l'IA d'être utilisable sans appareil photo : depuis
    le nom déjà saisi, des mots-clés, les champs du formulaire, une demande
    libre, ou pour reformuler une description existante.

    `consigne` est construite par la vue à partir du choix de l'utilisateur ;
    ce module ne décide pas de la source, il exécute.
    """
    prompt = PROMPT_TEXTE
    if categories:
        libelles = ", ".join(f'"{c}"' for c in categories)
        prompt += _PROMPT_CATEGORIES.format(libelles=libelles)
    else:
        prompt += _PROMPT_SANS_CATEGORIE
    prompt += "\n\nInformations fournies par l'utilisateur :\n" + consigne

    return _avec_retry(lambda: _call_gemini_texte(prompt))


def _avec_retry(appel):
    """Rejoue `appel` sur les erreurs Gemini temporaires (quota, 5xx)."""
    last_error = None
    attempts = len(_RETRY_DELAYS_SECONDS) + 1
    for attempt in range(attempts):
        try:
            return appel()
        except GeminiError as exc:
            last_error = exc
            if exc.retryable and attempt < attempts - 1:
                time.sleep(_RETRY_DELAYS_SECONDS[attempt])
                continue
            raise
    raise last_error  # pragma: no cover


def _texte(valeur, *, maxlen):
    """Normalise une valeur du modèle en chaîne bornée."""
    if not isinstance(valeur, str):
        return ""
    return valeur.strip()[:maxlen]


def _parse_caracteristiques(brut):
    """Convertit la liste [{libelle, valeur}] du modèle en dictionnaire."""
    if not isinstance(brut, list):
        return {}
    caracteristiques = {}
    for entree in brut:
        if not isinstance(entree, dict):
            continue
        libelle = _texte(entree.get("libelle"), maxlen=40)
        valeur = _texte(entree.get("valeur"), maxlen=120)
        if libelle and valeur and libelle not in caracteristiques:
            caracteristiques[libelle] = valeur
        if len(caracteristiques) >= MAX_CARACTERISTIQUES:
            break
    return caracteristiques


def _parse(text):
    """Lit la réponse JSON contrainte de Gemini (repli : ancien format texte)."""
    try:
        brut = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return _parse_texte_libre(text)
    if not isinstance(brut, dict):
        return _parse_texte_libre(text)

    etat = _texte(brut.get("etat"), maxlen=20).upper()
    confiance = _texte(brut.get("confiance"), maxlen=10).upper()
    nom = _texte(brut.get("nom"), maxlen=200)
    description = _texte(brut.get("description"), maxlen=2000)
    if not description and nom:
        description = nom
    return {
        "nom": nom,
        "description": description,
        "categorie": _texte(brut.get("categorie"), maxlen=100),
        "unite": _texte(brut.get("unite"), maxlen=30),
        "etat": etat if etat in ETATS else "INCONNU",
        "caracteristiques": _parse_caracteristiques(brut.get("caracteristiques")),
        "confiance": confiance if confiance in CONFIANCES else "MOYENNE",
    }


def _parse_texte_libre(text):
    """Repli sur l'ancien format « NOM: / DESCRIPTION: » (Sprint 10)."""
    nom = ""
    description = ""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("NOM:"):
            nom = stripped[4:].strip()
        elif stripped.upper().startswith("DESCRIPTION:"):
            description = stripped[12:].strip()
    if not description and nom:
        description = nom
    return {
        "nom": nom[:200],
        "description": description[:2000],
        "categorie": "",
        "unite": "",
        "etat": "INCONNU",
        "caracteristiques": {},
        "confiance": "FAIBLE",
    }


# --- Suggestion de référence (SKU) -----------------------------------------

# Mots ignorés pour construire le préfixe : ils n'apportent rien à un SKU.
_MOTS_VIDES = frozenset(
    {
        "de", "du", "des", "le", "la", "les", "un", "une", "en", "a", "à",
        "et", "avec", "sans", "pour", "sur", "sous", "dans", "au", "aux",
        "ou", "d", "l",
    }
)


def _normaliser(mot):
    """Retire les accents et ne garde que les lettres et chiffres."""
    import unicodedata

    sans_accent = unicodedata.normalize("NFKD", mot)
    sans_accent = "".join(c for c in sans_accent if not unicodedata.combining(c))
    return "".join(c for c in sans_accent if c.isalnum()).upper()


def suggerer_reference(nom, references_existantes):
    """Propose une référence unique dérivée du nom de l'article.

    « Chaise pliante en bois » → CHA-PLI-BOI-001. Le compteur final est
    incrémenté tant que la référence est déjà prise dans le business, ce qui
    évite un 400 sur la contrainte d'unicité au moment de la création.
    """
    mots = [
        _normaliser(mot)
        for mot in (nom or "").split()
        if _normaliser(mot) and mot.lower() not in _MOTS_VIDES
    ]
    if not mots:
        return ""
    prefixe = "-".join(mot[:3] for mot in mots[:3])
    prises = {r.upper() for r in references_existantes if r}
    for compteur in range(1, 1000):
        reference = f"{prefixe}-{compteur:03d}"
        if reference not in prises:
            return reference
    return ""
