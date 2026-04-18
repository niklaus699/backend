from django.apps import AppConfig


class VulnerabilitiesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.vulnerabilities'
    def ready(self):
        import apps.vulnerabilities.signals  # noqa — registers signal handlers