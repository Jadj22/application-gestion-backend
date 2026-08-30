"""Module de normalisation de texte pour DODOME Smart Search.

Responsabilités :
- Nettoyage et suppression des accents / signes diacritiques.
- Tokenisation et suppression des mots vides (stopwords) non significatifs.
- Résolution des synonymes et variantes linguistiques (FR/EN).
"""

from typing import List, Set
import re
import unicodedata

# Mots vides courants en français pour la recherche
STOPWORDS: Set[str] = {
    "le", "la", "les", "un", "une", "des", "du", "de", "d", "l",
    "et", "ou", "en", "pour", "avec", "sans", "sur", "dans", "par",
    "mon", "ma", "mes", "ton", "ta", "tes", "son", "sa", "ses", "notre", "nos", "votre", "vos", "leur", "leurs",
    "je", "tu", "il", "elle", "nous", "vous", "ils", "elles", "on",
    "veux", "voudrais", "cherche", "souhaite", "besoin", "aimerais",
}

# Dictionnaire de synonymes vers termes canoniques
SYNONYMS_MAP = {
    # Événements
    "anniv": "anniversaire",
    "bday": "anniversaire",
    "birthday": "anniversaire",
    "mariage": "mariage",
    "wedding": "mariage",
    "noce": "mariage",
    "bapteme": "bapteme",
    "baptism": "bapteme",
    "fete": "fete",
    "party": "fete",
    "soiree": "fete",
    "reunion": "reunion",
    "meeting": "reunion",
    "conference": "conference",
    "seminaire": "conference",
    "ceremonie": "ceremonie",
    "gala": "ceremonie",

    # Personnes / Cibles
    "maman": "mere",
    "mere": "mere",
    "mother": "mere",
    "mom": "mere",
    "papa": "pere",
    "pere": "pere",
    "father": "pere",
    "dad": "pere",
    "fille": "fille",
    "daughter": "fille",
    "fils": "fils",
    "son": "fils",
    "enfant": "enfant",
    "enfants": "enfant",
    "kids": "enfant",
    "children": "enfant",
    "bebe": "bebe",
    "baby": "bebe",
    "femme": "femme",
    "epouse": "femme",
    "wife": "femme",
    "mari": "mari",
    "epoux": "mari",
    "husband": "mari",
    "ami": "ami",
    "amie": "ami",
    "amis": "ami",
    "copain": "ami",
    "copine": "ami",
    "friend": "ami",

    # Équipements / Décoration
    "chapiteau": "tente",
    "barnum": "tente",
    "tent": "tente",
    "tente": "tente",
    "sieges": "chaise",
    "siege": "chaise",
    "fauteuil": "chaise",
    "chair": "chaise",
    "chairs": "chaise",
    "table": "table",
    "tables": "table",
    "sono": "sonorisation",
    "son": "sonorisation",
    "sound": "sonorisation",
    "enceinte": "sonorisation",
    "micro": "sonorisation",
    "lumiere": "eclairage",
    "lumieres": "eclairage",
    "light": "eclairage",
    "lighting": "eclairage",
    "deco": "decoration",
    "decor": "decoration",
}


class QueryNormalizer:
    """Service de normalisation textuelle."""

    @staticmethod
    def strip_accents(text: str) -> str:
        """Supprime les accents d'une chaîne de caractères."""
        if not text:
            return ""
        normalized = unicodedata.normalize("NFD", text)
        return "".join(c for c in normalized if unicodedata.category(c) != "Mn")

    @classmethod
    def clean_text(cls, text: str) -> str:
        """Nettoie et normalise une chaîne (minuscules, sans accents, sans ponctuation excessive)."""
        if not text:
            return ""
        accent_free = cls.strip_accents(text.lower().strip())
        cleaned = re.sub(r"[^\w\s-]", " ", accent_free)
        return re.sub(r"\s+", " ", cleaned).strip()

    @classmethod
    def tokenize(cls, text: str, remove_stopwords: bool = True) -> List[str]:
        """Découpe un texte en liste de tokens normalisés."""
        cleaned = cls.clean_text(text)
        if not cleaned:
            return []
        tokens = cleaned.split()
        if not remove_stopwords:
            return tokens
        return [t for t in tokens if t not in STOPWORDS and len(t) > 1]

    @classmethod
    def resolve_synonym(cls, token: str) -> str:
        """Retourne le terme canonique correspondant à un token ou le token lui-même."""
        return SYNONYMS_MAP.get(token, token)

    @classmethod
    def get_canonical_tokens(cls, text: str) -> List[str]:
        """Retourne les tokens canoniques d'un texte."""
        tokens = cls.tokenize(text, remove_stopwords=True)
        return [cls.resolve_synonym(t) for t in tokens]
