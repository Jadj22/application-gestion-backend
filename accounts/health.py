"""Sonde de disponibilité de l'API (Offline-First).

Le client mobile ne peut pas se fier à l'état de son interface réseau : un
téléphone associé à un Wi-Fi peut être derrière un portail captif, un VPN
coupé, un DNS cassé, ou face à un serveur simplement éteint. Dans tous ces cas
le système annonce « connecté » alors qu'aucune requête n'aboutira.

C'est donc une **réponse réelle de cette route** qui fait passer l'application
en mode ONLINE, et rien d'autre.

La route est volontairement :

* publique — la sonde tourne aussi quand la session a expiré ;
* minimale — appelée régulièrement par chaque appareil, elle ne doit rien
  coûter, en particulier aucune requête en base ;
* non limitée en débit — la brider reviendrait à faire croire à des coupures.
"""

from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET


@never_cache
@require_GET
def health(request):
    """Renvoie 200 dès que l'application Django répond.

    L'horodatage permet au client de mesurer la dérive d'horloge, utile pour
    arbitrer les conflits « dernière écriture gagne » quand l'appareil a une
    heure fausse.
    """
    return JsonResponse(
        {
            "status": "ok",
            "server_time": timezone.now().isoformat(),
        }
    )
