"""Throttling multi-scopes (S9).

DRF ne lit qu'un seul scope par vue (`throttle_scope`), alors que plusieurs
vues du projet en déclarent deux : `("auth", "write")` pour les mutations
d'authentification, `("write", "ai")` pour l'analyse d'image. `ScopesRateThrottle`
lit l'attribut `throttle_scopes` et refuse la requête dès qu'un seul des scopes
déclarés est dépassé.
"""

from rest_framework.throttling import SimpleRateThrottle


class ScopesRateThrottle(SimpleRateThrottle):
    """Applique tous les scopes déclarés par la vue via `throttle_scopes`."""

    scope_attr = "throttle_scopes"

    def __init__(self):
        # Le scope n'est connu qu'au moment de la requête : contrairement à
        # SimpleRateThrottle, on ne peut pas résoudre le taux à la construction.
        self.wait_for = None

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}

    def allow_request(self, request, view):
        scopes = getattr(view, self.scope_attr, None) or ()
        now = self.timer()
        # Les compteurs ne sont incrémentés que si *tous* les scopes passent :
        # une requête refusée ne doit pas consommer le quota des autres scopes.
        a_enregistrer = []

        for scope in scopes:
            self.scope = scope
            rate = self.get_rate()
            if rate is None:
                continue
            num_requests, duration = self.parse_rate(rate)
            key = self.get_cache_key(request, view)
            if key is None:
                continue
            history = self.cache.get(key, [])
            while history and history[-1] <= now - duration:
                history.pop()
            if len(history) >= num_requests:
                self.wait_for = duration - (now - history[-1])
                return False
            a_enregistrer.append((key, history, duration))

        for key, history, duration in a_enregistrer:
            history.insert(0, now)
            self.cache.set(key, history, duration)
        return True

    def wait(self):
        """Secondes à attendre avant la prochaine tentative (header Retry-After)."""
        return self.wait_for
