import uuid
from django.db import models
from apps.tenants.models import Organization


class Asset(models.Model):
    class AssetType(models.TextChoices):
        SERVER = 'server', 'Server'
        CONTAINER = 'container', 'Container'
        DATABASE = 'database', 'Database'
        ENDPOINT = 'endpoint', 'Endpoint'

    class Environment(models.TextChoices):
        PRODUCTION = 'production', 'Production'
        STAGING = 'staging', 'Staging'
        DEVELOPMENT = 'development', 'Development'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='assets'
    )
    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices)
    hostname = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    environment = models.CharField(
        max_length=20,
        choices=Environment.choices,
        default=Environment.PRODUCTION
    )
    # Denormalized for fast dashboard queries — recomputed by Celery
    risk_score = models.IntegerField(default=0)
    last_scanned = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'assets_asset'
        # Partial index: only index production assets for risk queries
        indexes = [
            models.Index(
                fields=['organization', 'risk_score'],
                name='idx_asset_org_risk'
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.organization.slug})"


class Package(models.Model):
    """
    A software package installed on an asset.
    ecosystem follows OSV convention: 'PyPI', 'npm', 'Go', 'Maven', etc.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='packages')
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100)
    ecosystem = models.CharField(max_length=50)
    # Raw JSON from the scanner — preserve it, you'll need it later
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = 'assets_package'
        # Idempotency constraint: one version of a package per asset
        unique_together = [('asset', 'name', 'version', 'ecosystem')]
        indexes = [
            models.Index(fields=['name', 'ecosystem'], name='idx_package_name_eco'),
        ]