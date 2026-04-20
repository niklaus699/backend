from rest_framework import serializers


SUPPORTED_ECOSYSTEMS = ['PyPI', 'npm', 'Go', 'Maven', 'RubyGems']


class PackageItemSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    version = serializers.CharField(max_length=100)
    ecosystem = serializers.ChoiceField(choices=SUPPORTED_ECOSYSTEMS, default='PyPI')


class AssetIngestionSerializer(serializers.Serializer):
    """
    Accepts package data from any source:
      - manifest upload  → file field populated, packages empty
      - agent/CI push    → packages populated, file empty
    """
    asset_name = serializers.CharField(max_length=255)
    hostname   = serializers.CharField(max_length=255, required=False, default='')
    environment = serializers.ChoiceField(
        choices=['production', 'staging', 'development'],
        default='production'
    )
    asset_type = serializers.ChoiceField(
        choices=['server', 'container', 'database', 'endpoint'],
        default='server'
    )
    # For agent/CI push — direct package list
    packages = PackageItemSerializer(many=True, required=False, default=list)
    # For manifest upload — file
    manifest = serializers.FileField(required=False)

    def validate(self, attrs):
        packages = attrs.get('packages', [])
        manifest = attrs.get('manifest')

        if not packages and not manifest:
            raise serializers.ValidationError(
                'Provide either a dependency manifest file or a non-empty packages list.'
            )

        if packages and manifest:
            raise serializers.ValidationError(
                'Provide packages or a manifest file, but not both in the same request.'
            )

        return attrs
