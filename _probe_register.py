import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.test import override_settings
from rest_framework.test import APIClient

c = APIClient()
with override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"]):
    r = c.post(
        "/auth/register/",
        {
            "email": "adjankeshadowj@gmail.com",
            "first_name": "ADJANKE",
            "last_name": "Joel",
            "telephone": "+22870203054",
            "statut": "ACTIF",
        },
        format="json",
    )
    print("NO_PW", r.status_code, getattr(r, "data", None))

    r = c.post(
        "/auth/register/",
        {
            "email": "adjankeshadowj+oklocal@gmail.com",
            "password": "TestPass123!",
            "first_name": "ADJANKE",
            "last_name": "Joel",
            "telephone": "+22870203054",
            "statut": "ACTIF",
        },
        format="json",
    )
    data = getattr(r, "data", None)
    if isinstance(data, dict) and r.status_code < 400:
        safe = {
            k: (str(v)[:24] + "..." if k in ("access", "refresh") else v)
            for k, v in data.items()
        }
        print("WITH_PW", r.status_code, safe)
    else:
        print("WITH_PW", r.status_code, data)
