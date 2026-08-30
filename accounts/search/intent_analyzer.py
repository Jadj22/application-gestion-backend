"""Service d'analyse d'intention pour DODOME Smart Search.

Responsabilités :
- Analyser la requête utilisateur pour extraire l'intention principale.
- Extraire le type d'événement, la cible / personne concernée, le nombre de participants et la localisation.
- Fournir une structure normalisée pour le moteur de recherche et ranking.
"""

from typing import Any, Dict, Optional
import re

from .normalizer import QueryNormalizer

# Mappage des verbes / intentions vers identifiant canonique
INTENT_MAP = {
    "organiser": "event_organization",
    "preparer": "event_organization",
    "planifier": "event_organization",
    "louer": "rental",
    "location": "rental",
    "reserve": "rental",
    "reserver": "rental",
    "chercher": "search",
    "trouver": "search",
    "decorer": "decoration",
    "decoration": "decoration",
    "equiper": "equipment_search",
    "materiel": "equipment_search",
    "besoin": "need",
}

# Mappage des types d'événements
EVENT_MAP = {
    "anniversaire": "birthday",
    "mariage": "wedding",
    "bapteme": "baptism",
    "reunion": "meeting",
    "conference": "conference",
    "seminaire": "conference",
    "ceremonie": "ceremony",
    "fete": "party",
    "soiree": "party",
    "gala": "ceremony",
    "evenement": "event",
    "reception": "party",
    "cocktail": "party",
}

# Mappage des cibles / personnes
TARGET_MAP = {
    "mere": {"relationship": "mother", "gender": "female", "audience": "adult"},
    "pere": {"relationship": "father", "gender": "male", "audience": "adult"},
    "fille": {"relationship": "daughter", "gender": "female", "audience": "children"},
    "fils": {"relationship": "son", "gender": "male", "audience": "children"},
    "enfant": {"relationship": "child", "gender": "unknown", "audience": "children"},
    "bebe": {"relationship": "baby", "gender": "unknown", "audience": "baby"},
    "femme": {"relationship": "wife", "gender": "female", "audience": "adult"},
    "mari": {"relationship": "husband", "gender": "male", "audience": "adult"},
    "ami": {"relationship": "friend", "gender": "unknown", "audience": "adult"},
    "collegue": {"relationship": "colleague", "gender": "unknown", "audience": "adult"},
    "client": {"relationship": "client", "gender": "unknown", "audience": "adult"},
}


class SearchIntentAnalyzer:
    """Analyseur d'intention et d'extraction de contexte pour les requêtes utilisateur."""

    @classmethod
    def analyze(cls, query: str) -> Dict[str, Any]:
        """Analyse une requête utilisateur et retourne une structure normalisée."""
        if not query or not query.strip():
            return cls._empty_result()

        raw_query = query.strip()
        normalized_clean = QueryNormalizer.clean_text(raw_query)
        canonical_tokens = QueryNormalizer.get_canonical_tokens(raw_query)

        intent = cls._detect_intent(canonical_tokens, normalized_clean)
        event = cls._detect_event(canonical_tokens)
        target = cls._detect_target(canonical_tokens, normalized_clean)
        attendees = cls._detect_attendees(normalized_clean)
        location = cls._detect_location(raw_query)

        return {
            "intent": intent,
            "event": event,
            "target": target,
            "attendees": attendees,
            "location": location,
            "canonical_tokens": canonical_tokens,
            "raw_query": raw_query,
        }

    @classmethod
    def _detect_intent(cls, tokens: list[str], text: str) -> str:
        """Détecte l'intention principale de la requête."""
        for token in tokens:
            if token in INTENT_MAP:
                return INTENT_MAP[token]

        # Vérification par préfixe / substring sur le texte nettoyé
        for key, value in INTENT_MAP.items():
            if re.search(r"\b" + re.escape(key), text):
                return value

        return "search"

    @classmethod
    def _detect_event(cls, tokens: list[str]) -> Optional[str]:
        """Détecte le type d'événement mentionné."""
        for token in tokens:
            if token in EVENT_MAP:
                return EVENT_MAP[token]
        return None

    @classmethod
    def _detect_target(cls, tokens: list[str], text: str) -> Optional[Dict[str, Any]]:
        """Détecte le contexte cible (personne, lien de parenté, âge)."""
        target_info = None

        for token in tokens:
            if token in TARGET_MAP:
                target_info = dict(TARGET_MAP[token])
                break

        # Extraction d'âge (ex: "fils de 10 ans", "fille de 5 ans")
        age_match = re.search(r"\b(\d{1,2})\s*ans?\b", text)
        if age_match:
            age = int(age_match.group(1))
            if target_info is None:
                target_info = {"relationship": "unknown", "gender": "unknown", "audience": "children" if age < 18 else "adult"}
            target_info["age"] = age
            if age < 18:
                target_info["audience"] = "children"

        return target_info

    @classmethod
    def _detect_attendees(cls, text: str) -> Optional[int]:
        """Extrait le nombre estimé de participants / invités."""
        match = re.search(r"\b(\d{1,5})\s*(personnes|pers|invites|convives|places|chaises|gens)\b", text)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None

    @classmethod
    def _detect_location(cls, query: str) -> Optional[str]:
        """Détecte une mention de ville ou lieu précédée d'une préposition."""
        match = re.search(r"\b(?:à|a|sur|dans)\s+([A-ZÀ-ÖØ-öø-ÿ][a-zà-öø-ÿA-Z0-9\s'-]+)$", query.strip())
        if match:
            loc = match.group(1).strip()
            if len(loc) >= 2 and loc.lower() not in {"louer", "decorer", "organiser"}:
                return loc
        return None

    @classmethod
    def _empty_result(cls) -> Dict[str, Any]:
        """Retourne un résultat vide par défaut."""
        return {
            "intent": "search",
            "event": None,
            "target": None,
            "attendees": None,
            "location": None,
            "canonical_tokens": [],
            "raw_query": "",
        }