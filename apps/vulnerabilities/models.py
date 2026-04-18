import uuid
from django.db import models
from apps.assets.models import Asset, Package


class Vulnerability(models.Model):
    """
    Global truth. NOT scoped to an organization.
    id is the external identifier — e.g. 'CVE-2024-1234' or 'GHSA-xxxx-xxxx-xxxx'.
    We use it as the PK directly to make idempotent upserts trivial.
    """
    class Severity(models.TextChoices):
        CRITICAL = 'critical', 'Critical'
        HIGH = 'high', 'High'
        MEDIUM = 'medium', 'Medium'
        LOW = 'low', 'Low'
        NONE = 'none', 'None'

    class Source(models.TextChoices):
        OSV = 'osv', 'OSV'
        NVD = 'nvd', 'NVD'
        GITHUB = 'github', 'GitHub Advisory'

    # Natural key from the feed — 'CVE-2024-1234', 'GHSA-...', 'PYSEC-...'
    id = models.CharField(max_length=100, primary_key=True)
    source = models.CharField(max_length=20, choices=Source.choices)
    summary = models.TextField(blank=True)
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices,
        default=Severity.NONE
    )
    cvss_score = models.FloatField(null=True, blank=True)
    # OSV 'affected' array — store raw, query with Python
    # In a v2 you'd normalise this into a separate table for SQL range queries
    affected_ranges = models.JSONField(default=list)
    references = models.JSONField(default=list)
    published_at = models.DateTimeField(null=True, blank=True)
    # Track when WE ingested it — useful for "new since last week" queries
    ingested_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'vulnerabilities_vulnerability'
        indexes = [
            models.Index(fields=['severity', 'published_at']),
        ]


class Finding(models.Model):
    """
    An organization's specific exposure to a vulnerability.
    This is the core business object — everything in the dashboard
    is ultimately a view over this table.
    """
    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        IN_PROGRESS = 'in_progress', 'In Progress'
        RESOLVED = 'resolved', 'Resolved'
        ACCEPTED = 'accepted', 'Accepted Risk'
        FALSE_POSITIVE = 'false_positive', 'False Positive'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='findings')
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name='findings'
    )
    package = models.ForeignKey(
        Package,
        on_delete=models.SET_NULL,
        null=True,
        related_name='findings'
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.OPEN
    )
    # Risk score at the finding level — accounts for asset criticality
    # risk_score = vuln.cvss_score * asset_criticality_multiplier
    risk_score = models.IntegerField(default=0)
    first_seen = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'vulnerabilities_finding'
        # Critical: prevents duplicate findings on re-ingestion
        unique_together = [('asset', 'vulnerability', 'package')]
        indexes = [
            models.Index(fields=['asset', 'status', 'risk_score']),
        ]


class RiskSnapshot(models.Model):
    """
    Time-series risk history per asset.
    Populated by a periodic Celery Beat task, not on every Finding change.
    Used for the trend chart — never query Finding directly for historical data.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='snapshots')
    risk_score = models.IntegerField()
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vulnerabilities_risksnapshot'
        indexes = [
            models.Index(fields=['asset', 'recorded_at']),
        ]