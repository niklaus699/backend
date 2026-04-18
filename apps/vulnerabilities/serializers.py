from rest_framework import serializers
from apps.vulnerabilities.models import Vulnerability, Finding, RiskSnapshot


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'source', 'summary', 'severity', 'cvss_score',
            'references', 'published_at', 'ingested_at',
        ]
        read_only_fields = fields


class FindingDetailSerializer(serializers.ModelSerializer):
    vulnerability = VulnerabilitySerializer(read_only=True)
    asset_name = serializers.CharField(source='asset.name', read_only=True)
    asset_environment = serializers.CharField(source='asset.environment', read_only=True)
    package_name = serializers.CharField(source='package.name', default=None)
    package_version = serializers.CharField(source='package.version', default=None)

    class Meta:
        model = Finding
        fields = [
            'id', 'vulnerability', 'asset_name', 'asset_environment',
            'package_name', 'package_version',
            'status', 'risk_score', 'first_seen', 'resolved_at',
        ]
        read_only_fields = [
            'id', 'vulnerability', 'asset_name', 'asset_environment',
            'package_name', 'package_version', 'risk_score',
            'first_seen', 'resolved_at',
        ]


class FindingStatusUpdateSerializer(serializers.ModelSerializer):
    """
    Minimal serializer for PATCH /findings/{id}/status/.
    Analysts can update status — the only field clients are allowed to mutate.
    resolved_at is auto-set by the model, not accepted from client.
    """
    class Meta:
        model = Finding
        fields = ['status']

    def validate_status(self, value):
        # Cannot re-open a false-positive without admin permission
        # (enforced at view layer with permission class)
        return value

    def update(self, instance, validated_data):
        from django.utils import timezone
        new_status = validated_data.get('status', instance.status)

        if new_status == Finding.Status.RESOLVED and instance.status != Finding.Status.RESOLVED:
            validated_data['resolved_at'] = timezone.now()
        elif new_status != Finding.Status.RESOLVED:
            validated_data['resolved_at'] = None

        return super().update(instance, validated_data)


class RiskSnapshotSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskSnapshot
        fields = ['risk_score', 'critical_count', 'high_count', 'medium_count', 'recorded_at']
        read_only_fields = fields


class DashboardStatsSerializer(serializers.Serializer):
    """
    Aggregated stats for the dashboard overview cards.
    Not a ModelSerializer — assembled from multiple QuerySets in the view.
    """
    total_assets = serializers.IntegerField()
    total_open_findings = serializers.IntegerField()
    critical_findings = serializers.IntegerField()
    high_findings = serializers.IntegerField()
    avg_risk_score = serializers.FloatField()
    most_critical_asset = serializers.DictField(allow_null=True)