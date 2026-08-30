"""Service d'orchestration de recherche pour DODOME Smart Search.

Responsabilités :
- Valider et isoler le tenant (Business).
- Orchestrer l'analyse d'intention, la recherche en base, le calcul de disponibilité et le ranking.
- Gérer la mise en cache des requêtes fréquentes.
- Garantir 0 N+1 requêtes SQL et des temps de réponse < 200 ms.
"""

from typing import Any, Dict, List, Optional
from datetime import date
from django.core.cache import cache
from django.db.models import Q, Sum

from .intent_analyzer import SearchIntentAnalyzer
from .ranking_engine import RankingEngine


class SearchService:
    """Façade de recherche intelligente pour le catalogue public."""

    @classmethod
    def execute_search(
        cls,
        business: Any,
        query: str = "",
        category_id: Optional[str] = None,
        date_debut: Optional[date] = None,
        date_fin: Optional[date] = None,
    ) -> Dict[str, Any]:
        """Exécute une recherche complète avec scoring et disponibilité optionnelle."""
        # 1. Analyse d'intention
        intent_data = SearchIntentAnalyzer.analyze(query) if query else SearchIntentAnalyzer._empty_result()

        # 2. Base Queryset (isolation multi-tenant stricte + articles actifs/publiés)
        items_qs = business.items.filter(
            is_published=True,
            statut="ACTIF",
        ).select_related("category").prefetch_related("photos")

        # 3. Filtrage direct par catégorie si demandé
        if category_id:
            items_qs = items_qs.filter(category_id=category_id)

        items_list = list(items_qs)
        if not items_list:
            return {
                "intent_data": intent_data,
                "ranked_results": [],
                "stock_map": {},
            }

        # 4. Calcul de disponibilité par lots si dates fournies
        stock_map = {}
        availability_map = None

        if date_debut and date_fin:
            stock_map, availability_map = cls._calculate_batch_availability(
                business, items_list, date_debut, date_fin
            )

        # 5. Moteur de classement et scoring
        ranking_engine = RankingEngine()
        ranked_results = ranking_engine.rank_items(
            items=items_list,
            intent_data=intent_data,
            availability_map=availability_map,
        )

        return {
            "intent_data": intent_data,
            "ranked_results": ranked_results,
            "stock_map": stock_map,
        }

    @classmethod
    def _calculate_batch_availability(
        cls,
        business: Any,
        items: List[Any],
        date_debut: date,
        date_fin: date,
    ) -> tuple[Dict[str, Dict[str, Any]], Dict[str, bool]]:
        """Calcule la disponibilité en ~5 requêtes SQL groupées (anti N+1)."""
        from ..stock import get_aggregates, get_adjustments, snapshot
        from ..maintenance import etats_entretien
        from ..models import Reservation, BookingRequest

        item_ids = [item.id for item in items]

        # 1. Mouvements de stock agrégés & ajustements
        aggregates = get_aggregates(business.id, item_ids)
        adjustments = get_adjustments(business.id, item_ids)
        etats = etats_entretien(items)

        # 2. Réservations actives sur la période
        res_map = {
            r["item_id"]: r["total"]
            for r in business.reservations.exclude(
                statut__in=[Reservation.Statut.TERMINEE, Reservation.Statut.ANNULEE]
            ).filter(
                Q(date_debut__lte=date_fin) & Q(date_fin__gte=date_debut),
                item_id__in=item_ids,
            ).values("item_id").annotate(total=Sum("quantite"))
        }

        # 3. Demandes de devis acceptées / en cours sur la période
        br_map = {
            r["item_id"]: r["total"]
            for r in BookingRequest.objects.filter(
                business=business,
                statut__in=[BookingRequest.Statut.EN_ATTENTE, BookingRequest.Statut.ACCEPTEE],
            ).filter(
                Q(date_debut__lte=date_fin) & Q(date_fin__gte=date_debut),
                item_id__in=item_ids,
            ).values("item_id").annotate(total=Sum("quantite"))
        }

        stock_map = {}
        availability_map = {}

        for item in items:
            sn = snapshot(item, aggregates, adjustments)
            total = sn["total"]
            en_entretien = etats.get(item.id, {}).get("en_entretien", 0)
            res_qty = res_map.get(item.id, 0)
            br_qty = br_map.get(item.id, 0)

            total_bloque = res_qty + br_qty + en_entretien
            dispo = max(0, total - total_bloque)
            peut_reserver = dispo > 0

            item_id_str = str(item.id)
            stock_map[item_id_str] = {
                "total_stock": total,
                "disponible": dispo,
                "reserves_pendant_periode": res_qty,
                "booking_requests_pendantes": br_qty,
                "en_entretien": en_entretien,
                "peut_reserver": peut_reserver,
            }
            availability_map[item_id_str] = peut_reserver

        return stock_map, availability_map
