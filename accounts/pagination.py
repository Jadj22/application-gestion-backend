"""Pagination standard de l'API (Sprint 9, stabilisation production).

Toutes les listes GET renvoient la même enveloppe DRF :
    {"count": N, "next": URL|null, "previous": URL|null, "results": [...]}

page_size par défaut 100, ajustable via ?page_size= (max 1000).
"""

from rest_framework.pagination import PageNumberPagination


class StandardPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = "page_size"
    max_page_size = 1000


def paginated(request, queryset, serializer, **context):
    """Sérialise la page courante de `queryset` avec l'enveloppe standard."""
    paginator = StandardPagination()
    page = paginator.paginate_queryset(queryset, request)
    return paginator.get_paginated_response(
        serializer(page, many=True, context=context).data
    )