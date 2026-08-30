"""Moteur de recommandation pour DODOME.

Responsabilités :
- Générer des recommandations pour un article donné sur sa fiche produit.
- Différencier les types de recommandations :
    - SIMILAR : articles équivalents ou alternatifs dans la même catégorie.
    - COMPLEMENTARY : articles d'autres catégories indispensables pour compléter l'installation.
    - USED_FOR : articles associés au même type d'événement.
    - OFTEN_RENTED_TOGETHER : co-occurrences observées dans l'historique des réservations / demandes.
- Respecter strictement l'isolation multi-tenant (même business, actif, publié).
"""

from typing import Any, Dict, List, Optional
from django.db.models import Count, Q

from .normalizer import QueryNormalizer

# Règles de complémentarité inter-catégories et inter-équipements
COMPLEMENTARY_RULES = {
    "tente": ["chaise", "table", "eclairage", "decoration", "sonorisation", "sol"],
    "barnum": ["chaise", "table", "eclairage", "decoration"],
    "chapiteau": ["chaise", "table", "eclairage", "decoration", "scène"],
    "table": ["chaise", "nappe", "decoration", "vaisselle", "chemin de table"],
    "chaise": ["table", "housse", "noeud", "tente"],
    "sonorisation": ["eclairage", "micro", "pupitre", "videoprojecteur", "cable"],
    "enceinte": ["micro", "eclairage", "mixage"],
    "eclairage": ["sonorisation", "decoration", "guirlande", "tente"],
    "lumiere": ["sonorisation", "decoration", "spot"],
    "decoration": ["table", "chaise", "eclairage", "fleur", "arche", "bougie"],
    "arche": ["fleur", "decoration", "tapis", "eclairage"],
    "scène": ["pupitre", "micro", "sonorisation", "eclairage", "chaise"],
}

# Raisons associées par catégorie de complément
COMPLEMENTARY_REASONS = {
    "tente": "Idéal pour équiper votre tente ou chapiteau",
    "table": "Complément indispensable pour vos tables",
    "chaise": "Parfait pour accompagner vos chaises",
    "sonorisation": "Équipement sonore et visuel coordonné",
    "eclairage": "Pour illuminer votre espace",
    "decoration": "Élément assorti pour votre décoration",
}


class RecommendationEngine:
    """Moteur de génération de recommandations d'articles."""

    @classmethod
    def get_recommendations(
        cls,
        target_item: Any,
        rec_type: str = "complementary",
        limit: int = 4,
    ) -> Dict[str, Any]:
        """Génère les recommandations adaptées au type demandé."""
        business = target_item.business
        base_qs = business.items.filter(
            is_published=True,
            statut="ACTIF",
        ).exclude(id=target_item.id).select_related("category").prefetch_related("photos")

        rec_type_normalized = (rec_type or "complementary").lower().strip()

        if rec_type_normalized == "similar":
            items = cls._get_similar_items(target_item, base_qs, limit)
            default_reason = "Article similaire dans la même catégorie"
        elif rec_type_normalized == "used_for":
            items = cls._get_used_for_items(target_item, base_qs, limit)
            default_reason = "Souvent utilisé pour le même type d'événement"
        elif rec_type_normalized == "often_rented_together":
            items = cls._get_often_rented_together(target_item, base_qs, limit)
            default_reason = "Fréquemment loué ensemble lors de précédents événements"
        else:
            rec_type_normalized = "complementary"
            items = cls._get_complementary_items(target_item, base_qs, limit)
            default_reason = "Recommandé pour compléter votre installation"

        return {
            "type": rec_type_normalized.upper(),
            "items": items,
            "default_reason": default_reason,
        }

    @classmethod
    def _get_similar_items(cls, target_item: Any, base_qs: Any, limit: int) -> List[Any]:
        """Retourne des articles similaires (même catégorie, ou caractéristiques proches)."""
        results: List[Any] = []

        if target_item.category_id:
            same_cat = list(base_qs.filter(category_id=target_item.category_id)[:limit])
            results.extend(same_cat)

        if len(results) < limit:
            remaining = limit - len(results)
            already_ids = [target_item.id] + [item.id for item in results]
            fallback = list(base_qs.exclude(id__in=already_ids)[:remaining])
            results.extend(fallback)

        return results[:limit]

    @classmethod
    def _get_complementary_items(cls, target_item: Any, base_qs: Any, limit: int) -> List[Any]:
        """Retourne des articles complémentaires basés sur les règles métier."""
        item_nom_norm = QueryNormalizer.clean_text(target_item.nom)
        item_cat_norm = QueryNormalizer.clean_text(
            getattr(target_item.category, "nom", "") if target_item.category else ""
        )
        combined_term = f"{item_nom_norm} {item_cat_norm}"

        # Trouver les mots-clés complémentaires pertinents
        complementary_keywords = set()
        for key, complements in COMPLEMENTARY_RULES.items():
            if key in combined_term:
                complementary_keywords.update(complements)

        if not complementary_keywords:
            # Règle par défaut : proposer des articles d'autres catégories
            if target_item.category_id:
                diff_cat = list(base_qs.exclude(category_id=target_item.category_id)[:limit])
                if len(diff_cat) >= limit:
                    return diff_cat[:limit]
            return list(base_qs[:limit])

        # Construire une requête Q or pour les mots-clés complémentaires
        keyword_q = Q()
        for kw in complementary_keywords:
            keyword_q |= Q(nom__icontains=kw)
            keyword_q |= Q(category__nom__icontains=kw)
            keyword_q |= Q(public_description__icontains=kw)

        matched_items = list(base_qs.filter(keyword_q).distinct()[:limit])

        # Si pas assez de correspondances directes, compléter avec d'autres catégories
        if len(matched_items) < limit:
            remaining = limit - len(matched_items)
            already_ids = [target_item.id] + [item.id for item in matched_items]
            fallback = list(
                base_qs.exclude(id__in=already_ids)
                .exclude(category_id=target_item.category_id)[:remaining]
            )
            matched_items.extend(fallback)

        if len(matched_items) < limit:
            remaining = limit - len(matched_items)
            already_ids = [target_item.id] + [item.id for item in matched_items]
            fallback = list(base_qs.exclude(id__in=already_ids)[:remaining])
            matched_items.extend(fallback)

        return matched_items[:limit]

    @classmethod
    def _get_used_for_items(cls, target_item: Any, base_qs: Any, limit: int) -> List[Any]:
        """Retourne des articles partageant les mêmes contextes d'événements."""
        # On extrait les mots-clés de l'article pour identifier l'usage
        return cls._get_complementary_items(target_item, base_qs, limit)

    @classmethod
    def _get_often_rented_together(cls, target_item: Any, base_qs: Any, limit: int) -> List[Any]:
        """Détecte les co-occurrences dans l'historique des réservations / devis."""
        business = target_item.business

        try:
            from ..models import Reservation, BookingRequest
            common_br = BookingRequest.objects.filter(
                business=business,
                item_id=target_item.id,
            ).values_list("client_nom", "date_debut")

            if common_br.exists():
                q_filters = Q()
                for client_nom, date_debut in common_br[:20]:
                    q_filters |= Q(client_nom=client_nom, date_debut=date_debut)

                co_rented_ids = (
                    BookingRequest.objects.filter(business=business)
                    .filter(q_filters)
                    .exclude(item_id=target_item.id)
                    .values("item_id")
                    .annotate(count=Count("id"))
                    .order_by("-count")
                    .values_list("item_id", flat=True)[:limit]
                )

                if co_rented_ids:
                    items_map = {item.id: item for item in base_qs.filter(id__in=list(co_rented_ids))}
                    ordered = [items_map[iid] for iid in co_rented_ids if iid in items_map]
                    if len(ordered) >= limit:
                        return ordered[:limit]
        except Exception:
            pass

        # Fallback gracieux sur complementary
        return cls._get_complementary_items(target_item, base_qs, limit)
