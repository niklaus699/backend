import logging
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from apps.tenants.permissions import IsAnalystOrAbove
from apps.assets.models import Asset, Package
from apps.tenants.models import Organization
from apps.ingestion.serializers import AssetIngestionSerializer
from apps.ingestion.parsers import parse_manifest

logger = logging.getLogger(__name__)
MAX_MANIFEST_SIZE = 5 * 1024 * 1024  # 5 MB limit for manifest files

def _build_success_message(pinned_count, unpinned_count, new_count, updated_count):
    parts = [f"Found {pinned_count} pinned packages."]
    if unpinned_count > 0:
        parts.append(f"{unpinned_count} packages skipped (no pinned version).")
    if new_count > 0:
        parts.append(f"{new_count} new packages added.")
    if updated_count > 0:
        parts.append(f"{updated_count} packages updated.")
    if unpinned_count > 0:
        parts.append("Use 'pip freeze' or a lock file to pin all versions for accurate scanning.")
    return " ".join(parts)

class AssetIngestionView(APIView):
    """
    POST /api/ingestion/sync/

    Unified ingestion endpoint. Accepts multipart (manifest upload)
    or JSON (agent/CI push). Creates the asset if it doesn't exist,
    syncs its package list, then triggers correlation.

    Auth: Bearer JWT (same as all other endpoints)
    Extra header for CI/agent: X-Asset-Token (API key scoped to one asset)
    """
    # Support both file upload and JSON body
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    permission_classes = [IsAuthenticated, IsAnalystOrAbove]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'ingestion'

    def post(self, request):
        serializer = AssetIngestionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        org_id = request.auth.get('organization_id')
        try:
            org = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            return Response({'detail': 'Organization not found.'}, status=404)

        # Resolve packages — from file or from direct list
        packages_data = []
        manifest_file = request.FILES.get('manifest')

        if manifest_file:
            if manifest_file.size > MAX_MANIFEST_SIZE:
                return Response(
                    {'detail': f'Manifest file exceeds maximum size of {MAX_MANIFEST_SIZE // (1024*1024)} MB.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                content = manifest_file.read().decode('utf-8', errors='replace')
                packages_data, unpinned_packages = parse_manifest(manifest_file.name, content)
            except ValueError as e:
                return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            except Exception:
                logger.exception("Manifest parse error for %s", manifest_file.name)
                return Response(
                    {'detail': 'Could not parse manifest file.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        else:
            packages_data = data.get('packages', [])
            unpinned_packages = []  # agent/CI pushes should always be pinned

        if not packages_data:
            return Response(
                {'detail': 'No packages found. Check your manifest file has pinned versions (e.g. requests==2.31.0).'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create or update the asset
        with transaction.atomic():
            asset, asset_created = Asset.objects.get_or_create(
                organization=org,
                name=data['asset_name'],
                defaults=dict(
                    hostname=data.get('hostname', ''),
                    environment=data['environment'],
                    asset_type=data['asset_type'],
                    last_scanned=timezone.now(),
                )
            )
            if not asset_created:
                # Update last_scanned on re-sync
                Asset.objects.filter(id=asset.id).update(last_scanned=timezone.now())

            # Sync packages — upsert, never blindly delete
            # Mark existing packages then reconcile
            incoming = {
                (p['name'].lower(), p.get('ecosystem', 'PyPI')): p['version']
                for p in packages_data
            }

            existing_pkgs = {
                (p.name.lower(), p.ecosystem): p
                for p in Package.objects.filter(asset=asset)
            }

            created_count = 0
            updated_count = 0

            for (name, ecosystem), version in incoming.items():
                if (name, ecosystem) in existing_pkgs:
                    pkg = existing_pkgs[(name, ecosystem)]
                    if pkg.version != version:
                        Package.objects.filter(id=pkg.id).update(version=version)
                        updated_count += 1
                else:
                    Package.objects.create(
                        asset=asset,
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                    )
                    created_count += 1

        logger.info(
            f"Ingestion complete: asset={asset.name}, "
            f"packages_total={len(incoming)}, created={created_count}, updated={updated_count}"
        )

        # Trigger correlation outside the transaction
        from apps.ingestion.tasks import correlate_new_packages_for_asset
        correlate_new_packages_for_asset.apply_async(
            kwargs={
                'asset_id': str(asset.id),
                'organization_id': str(org.id),
            },
            queue='correlation',
        )

        return Response({
            'asset_id':       str(asset.id),
            'asset_name':     asset.name,
            'asset_created':  asset_created,
            'packages_found': len(incoming),
            'packages_new':   created_count,
            'packages_updated': updated_count,
            'unpinned_count': len(unpinned_packages),
            'status': 'scan_queued',
            'message': _build_success_message(len(incoming), len(unpinned_packages), created_count, updated_count),
        }, status=status.HTTP_202_ACCEPTED)
    
