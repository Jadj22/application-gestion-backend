"""Hooks de prétraitement pour drf-spectacular.

Filtre les endpoints pour ne documenter que les routes canoniques sous /api/
et éviter les collisions d'operationId dues à la double inclusion des URLs.
"""


def filter_api_endpoints(endpoints):
    """Ne conserve dans Swagger que les routes préfixées par /api/."""
    return [
        (path, path_regex, method, callback)
        for (path, path_regex, method, callback) in endpoints
        if path.startswith("/api/")
    ]
