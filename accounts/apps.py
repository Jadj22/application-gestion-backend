from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = 'accounts'

    def ready(self):
        # Importer les signaux pour les enregistrer
        import accounts.signals  # noqa: F401
