from django.shortcuts import render

# Create your views here.
from django.db.models import Count, Q, Prefetch
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from apps.tenants.permissions import IsAdminOrAbove, IsAnalystOrAbove
from apps.assets.models import Asset, Package
from apps.assets.serializers import (
    AssetListSerializer,
    AssetDetailSerializer,
    AssetWriteSerializer,
)
from apps.vulnerabilities.models import Finding, RiskSnapshot
from apps.vulnerabilities.serializers import RiskSnapshotSerializer


class AssetViewSet(viewsets.ModelViewSet):
    """
    /api/assets/           GET (list), POST (create)
    /api/assets/{id}/      GET (detail), PATCH (update), DELETE
    /api/assets/{id}/risk-history/   GET — time-series for trend chart
    /api/assets/{id}/scan/           POST — trigger re-scan
    """
    permission_classes = [IsAuthenticated, IsAnalystOrAbove]

    def get_permissions(self):
        if self.action in ('create', 'update', 'partial_update', 'destroy', 'trigger_scan'):
            return [IsAuthenticated(), IsAdminOrAbove()]
        return super().get_permissions()

    def get_serializer_class(self):
        if self.action == 'list':
            return AssetListSerializer
        if self.action in ('create', 'update', 'partial_update'):
            return AssetWriteSerializer
        return AssetDetailSerializer

    def get_queryset(self):
        """
        RLS handles tenant isolation — we don't filter by org here.
        But we DO annotate with aggregated finding counts so the list
        view doesn't trigger N+1 queries.

        This single query replaces what would otherwise be:
          for asset in assets:
              count = Finding.objects.filter(asset=asset).count()  # N queries
        """
        qs = Asset.objects.annotate(
            open_findings_count=Count(
                'findings',
                filter=Q(findings__status=Finding.Status.OPEN)
            ),
            critical_count=Count(
                'findings',
                filter=Q(
                    findings__status=Finding.Status.OPEN,
                    findings__risk_score__gte=90
                )
            ),
            high_count=Count(
                'findings',
                filter=Q(
                    findings__status=Finding.Status.OPEN,
                    findings__risk_score__gte=70,
                    findings__risk_score__lt=90,
                )
            ),
        ).order_by('-risk_score')

        # Optional filters from query params
        environment = self.request.query_params.get('environment')
        if environment:
            qs = qs.filter(environment=environment)

        asset_type = self.request.query_params.get('type')
        if asset_type:
            qs = qs.filter(asset_type=asset_type)

        return qs

    def get_object(self):
        """
        For detail views, prefetch open findings and packages
        to avoid N+1 on the serializer.
        """
        obj = Asset.objects.prefetch_related(
            Prefetch(
                'findings',
                queryset=Finding.objects.filter(
                    status=Finding.Status.OPEN
                ).select_related(
                    'vulnerability', 'package'
                ).order_by('-risk_score'),
                to_attr='open_findings',
            ),
            'packages',
        ).get(pk=self.kwargs['pk'])

        self.check_object_permissions(self.request, obj)
        return obj

    @action(detail=True, methods=['get'], url_path='risk-history')
    def risk_history(self, request, pk=None):
        """
        Returns the time-series risk snapshots for the trend chart.
        Accepts ?days=30 (default) to control lookback window.
        """
        asset = self.get_object()
        days = min(int(request.query_params.get('days', 30)), 90)

        from django.utils import timezone
        from datetime import timedelta

        since = timezone.now() - timedelta(days=days)
        snapshots = (
            RiskSnapshot.objects
            .filter(asset=asset, recorded_at__gte=since)
            .order_by('recorded_at')
        )

        serializer = RiskSnapshotSerializer(snapshots, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='scan',
            permission_classes=[IsAuthenticated, IsAdminOrAbove])
    def trigger_scan(self, request, pk=None):
        """
        Triggers a re-correlation pass for this asset against all known vulns.
        In a real product this would also trigger an agent scan — for now
        it runs the correlation task, which is demonstrably useful.
        """
        asset = self.get_object()

        from apps.ingestion.tasks import correlate_new_packages_for_asset
        correlate_new_packages_for_asset.apply_async(
            kwargs={'asset_id': str(asset.id)},
            queue='correlation',
        )

        return Response(
            {'detail': f'Scan queued for {asset.name}'},
            status=status.HTTP_202_ACCEPTED
        )