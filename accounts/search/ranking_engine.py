"""Moteur de classement (Ranking Engine) pour DODOME Smart Search.

Responsabilités :
- Calculer le score de pertinence composite de chaque article.
- Associer des pondérations configurables (texte, événement, catégorie, disponibilité, récence).
- Générer des explications humaines (match_reasons) pour chaque résultat.
"""

from typing import Any, Dict, List, Optional
from .normalizer import QueryNormalizer

# Profils d'équipements et catégories associés par type d'événement
EVENT_EQUIPMENT_PROFILES: Dict[str, Dict[str, Any]] = {
    "wedding": {
        "keywords": ["tente", "chaise", "table", "decoration", "nappe", "eclairage", "sonorisation", "arche", "buffet", "tapis", "fleur", "mariage"],
        "reason": "Indispensable pour un mariage",
    },
    "birthday": {
        "keywords": ["decoration", "chaise", "table", "sonorisation", "eclairage", "gateau", "ballon", "anniversaire", "fete", "tente", "buffet"],
        "reason": "Idéal pour un anniversaire",
    },
    "baptism": {
        "keywords": ["tente", "chaise", "table", "decoration", "nappe", "arche", "ceremonie", "bapteme"],
        "reason": "Recommandé pour un baptême",
    },
    "conference": {
        "keywords": ["chaise", "table", "micro", "sonorisation", "videoprojecteur", "ecran", "pupitre", "conference", "reunion", "badge"],
        "reason": "Équipement pour conférence et réunion",
    },
    "meeting": {
        "keywords": ["chaise", "table", "ecran", "micro", "tableau", "sonorisation", "reunion"],
        "reason": "Adapté pour une réunion professionnelle",
    },
    "ceremony": {
        "keywords": ["tente", "chaise", "table", "decoration", "pupitre", "tapis", "arche", "sonorisation", "ceremonie"],
        "reason": "Parfait pour une cérémonie",
    },
    "party": {
        "keywords": ["sonorisation", "eclairage", "table", "chaise", "bar", "glaciere", "lumieres", "fete", "ambiance"],
        "reason": "Idéal pour une fête ou soirée",
    },
}

# Pondérations par défaut du moteur de ranking
DEFAULT_WEIGHTS = {
    "text": 0.30,
    "event_context": 0.35,
    "category": 0.15,
    "availability": 0.15,
    "recency": 0.05,
}


class RankingEngine:
    """Moteur de scoring et de classement des articles du catalogue."""

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or DEFAULT_WEIGHTS

    def rank_items(
        self,
        items: List[Any],
        intent_data: Dict[str, Any],
        availability_map: Optional[Dict[str, bool]] = None,
    ) -> List[Dict[str, Any]]:
        """Calcule le score de chaque article et retourne la liste ordonnée."""
        if not items:
            return []

        scored_results: List[Dict[str, Any]] = []
        for item in items:
            score, reasons = self._calculate_item_score(item, intent_data, availability_map)
            scored_results.append({
                "item": item,
                "score": round(score, 3),
                "match_reasons": reasons,
            })

        # Tri décroissant par score
        return sorted(scored_results, key=lambda x: x["score"], reverse=True)

    def _calculate_item_score(
        self,
        item: Any,
        intent_data: Dict[str, Any],
        availability_map: Optional[Dict[str, bool]],
    ) -> tuple[float, List[str]]:
        """Calcule les composantes de score et rassemble les raisons de pertinence."""
        reasons: List[str] = []

        # 1. Score textuel direct
        text_score, text_reasons = self._evaluate_text_match(item, intent_data)
        reasons.extend(text_reasons)

        # 2. Score de contexte événementiel
        event_score, event_reason = self._evaluate_event_context(item, intent_data.get("event"))
        if event_reason:
            reasons.append(event_reason)

        # 3. Score de catégorie
        category_score = self._evaluate_category_match(item, intent_data)

        # 4. Score de disponibilité
        is_available = True
        if availability_map is not None:
            item_id_str = str(getattr(item, "id", item.get("id") if isinstance(item, dict) else ""))
            is_available = availability_map.get(item_id_str, False)
            if is_available:
                reasons.append("Disponible sur vos dates")

        avail_score = 1.0 if is_available else 0.0

        # Calcul pondéré final
        total_score = (
            text_score * self.weights.get("text", 0.30)
            + event_score * self.weights.get("event_context", 0.35)
            + category_score * self.weights.get("category", 0.15)
            + avail_score * self.weights.get("availability", 0.15)
        )

        # Si aucune raison explicite n'a été trouvée mais que l'article a un score, ajouter un label par défaut
        if not reasons:
            reasons.append("Article du catalogue")

        return min(max(total_score, 0.0), 1.0), reasons

    @staticmethod
    def _evaluate_text_match(item: Any, intent_data: Dict[str, Any]) -> tuple[float, List[str]]:
        """Évalue la correspondance textuelle avec le nom, description et caractéristiques."""
        reasons: List[str] = []
        raw_query = intent_data.get("raw_query", "").strip()
        tokens = intent_data.get("canonical_tokens", [])

        if not raw_query and not tokens:
            return 0.5, reasons

        item_nom = getattr(item, "nom", "")
        item_desc = getattr(item, "public_description", "") or getattr(item, "description", "")
        item_nom_norm = QueryNormalizer.clean_text(item_nom)
        item_desc_norm = QueryNormalizer.clean_text(item_desc)

        query_norm = QueryNormalizer.clean_text(raw_query)

        # Match exact ou début de nom
        if query_norm and query_norm in item_nom_norm:
            reasons.append("Correspondance exacte dans le nom")
            return 1.0, reasons

        # Token overlap
        item_tokens = set(QueryNormalizer.tokenize(f"{item_nom} {item_desc}"))
        matching_tokens = set(tokens).intersection(item_tokens)

        if not tokens:
            return 0.3, reasons

        ratio = len(matching_tokens) / max(len(tokens), 1)

        # Boost si le nom contient directement l'un des tokens principaux
        nom_tokens = set(QueryNormalizer.tokenize(item_nom))
        nom_matches = set(tokens).intersection(nom_tokens)
        if nom_matches:
            reasons.append(f"Correspond au terme '{next(iter(nom_matches))}'")
            return min(0.7 + ratio * 0.3, 1.0), reasons

        if matching_tokens:
            reasons.append("Mentionné dans la description")
            return 0.4 + ratio * 0.3, reasons

        return 0.1, reasons

    @staticmethod
    def _evaluate_event_context(item: Any, event_type: Optional[str]) -> tuple[float, Optional[str]]:
        """Évalue la pertinence de l'article pour un type d'événement donné."""
        if not event_type or event_type not in EVENT_EQUIPMENT_PROFILES:
            return 0.3, None

        profile = EVENT_EQUIPMENT_PROFILES[event_type]
        keywords = set(profile["keywords"])

        item_nom = getattr(item, "nom", "")
        item_cat = getattr(getattr(item, "category", None), "nom", "") or getattr(item, "category_nom", "")
        item_desc = getattr(item, "public_description", "") or getattr(item, "description", "")

        combined_text = f"{item_nom} {item_cat} {item_desc}"
        item_tokens = set(QueryNormalizer.get_canonical_tokens(combined_text))

        matching_keywords = keywords.intersection(item_tokens)
        if matching_keywords:
            return 1.0, profile["reason"]

        return 0.2, None

    @staticmethod
    def _evaluate_category_match(item: Any, intent_data: Dict[str, Any]) -> float:
        """Évalue si la catégorie correspond aux termes de la requête."""
        item_cat = getattr(getattr(item, "category", None), "nom", "") or getattr(item, "category_nom", "")
        if not item_cat:
            return 0.3

        cat_tokens = set(QueryNormalizer.get_canonical_tokens(item_cat))
        query_tokens = set(intent_data.get("canonical_tokens", []))

        if cat_tokens.intersection(query_tokens):
            return 1.0

        return 0.3
