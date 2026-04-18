from rest_framework import serializers
from apps.assets.models import Asset, Package
from apps.vulnerabilities.models import Finding


class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Package
        fields = ['id', 'name', 'version', 'ecosystem']
        read_only_fields = fields


class FindingSummarySerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for the asset detail view.
    Full finding detail has its own endpoint.
    """
    vulnerability_id = serializers.CharField(source='vulnerability.id')
    vulnerability_summary = serializers.CharField(source='vulnerability.summary')
    severity = serializers.CharField(source='vulnerability.severity')
    cvss_score = serializers.FloatField(source='vulnerability.cvss_score')
    package_name = serializers.CharField(source='package.name', default=None)
    package_version = serializers.CharField(source='package.version', default=None)

    class Meta:
        model = Finding
        fields = [
            'id', 'vulnerability_id', 'vulnerability_summary',
            'severity', 'cvss_score', 'package_name', 'package_version',
            'status', 'risk_score', 'first_seen',
        ]
        read_only_fields = ['id', 'first_seen', 'risk_score']


class AssetListSerializer(serializers.ModelSerializer):
    """
    Used for the asset list endpoint — omits findings for performance.
    Includes counts only so the dashboard table can render without N+1.
    """
    open_findings_count = serializers.IntegerField(read_only=True)
    critical_count = serializers.IntegerField(read_only=True)
    high_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Asset
        fields = [
            'id', 'name', 'asset_type', 'hostname', 'ip_address',
            'environment', 'risk_score', 'last_scanned',
            'open_findings_count', 'critical_count', 'high_count',
        ]
        read_only_fields = fields


class AssetDetailSerializer(serializers.ModelSerializer):
    """Full asset detail including paginated findings."""
    packages = PackageSerializer(many=True, read_only=True)
    findings = FindingSummarySerializer(many=True, read_only=True, source='open_findings')

    class Meta:
        model = Asset
        fields = [
            'id', 'name', 'asset_type', 'hostname', 'ip_address',
            'environment', 'risk_score', 'last_scanned',
            'packages', 'findings',
        ]
        read_only_fields = fields


class AssetWriteSerializer(serializers.ModelSerializer):
    """
    Separate write serializer — never expose organization on writes.
    The organization is always injected from the JWT, never from request data.
    This is a security invariant: clients cannot claim a different org.
    """
    class Meta:
        model = Asset
        fields = ['name', 'asset_type', 'hostname', 'ip_address', 'environment']

    def create(self, validated_data):
        # Organization is injected from context, not from client data
        org_id = self.context['request'].auth['organization_id']
        from apps.tenants.models import Organization
        validated_data['organization_id'] = org_id
        return super().create(validated_data)