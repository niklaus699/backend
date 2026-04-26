from django.db.models import Count, Avg, Q
from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
from rest_framework.pagination import CursorPagination, PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.tenants.permissions import IsAnalystOrAbove, IsAdminOrAbove
from apps.vulnerabilities.models import Finding, Vulnerability
from apps.vulnerabilities.serializers import (
    FindingDetailSerializer,
    FindingStatusUpdateSerializer,
    VulnerabilitySerializer,
    DashboardStatsSerializer,
)


class FindingPagination(CursorPagination):
    ordering = '-risk_score'


class FindingViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    """
    Findings are never created or deleted via API — only the correlation
    engine creates them, and only status changes are allowed from clients.

    /api/findings/              GET list (filterable)
    /api/findings/{id}/         GET detail
    /api/findings/{id}/status/  PATCH — update status only
    """
    permission_classes = [IsAuthenticated, IsAnalystOrAbove]
    serializer_class = FindingDetailSerializer
    pagination_class = PageNumberPagination
    ordering_fields = ['risk_score', 'first_seen', 'status']
    ordering = ['-risk_score', '-first_seen']

    def get_queryset(self):
        """
        Highly filterable — the frontend uses these params for the
        findings table with column filters.
        """
        org_id = self.request.auth['organization_id']
        qs = (
            Finding.objects
            .filter(asset__organization_id=org_id)
            .select_related('vulnerability', 'asset', 'package')
            .order_by('-risk_score', '-first_seen')
        )

        params = self.request.query_params

        if status_filter := params.get('status'):
            qs = qs.filter(status=status_filter)

        if severity := params.get('severity'):
            qs = qs.filter(vulnerability__severity=severity)

        if environment := params.get('environment'):
            qs = qs.filter(asset__environment=environment)

        if asset_id := params.get('asset_id'):
            qs = qs.filter(asset_id=asset_id)

        if min_score := params.get('min_risk_score'):
            qs = qs.filter(risk_score__gte=int(min_score))

        return qs

    @action(
        detail=True,
        methods=['patch'],
        url_path='status',
        serializer_class=FindingStatusUpdateSerializer,
    )
    def update_status(self, request, pk=None):
        finding = self.get_object()
        serializer = FindingStatusUpdateSerializer(
            finding, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # If resolved/accepted, trigger an asset rescore so the
        # dashboard updates in real time via WebSocket
        if finding.status in (Finding.Status.RESOLVED, Finding.Status.ACCEPTED):
            from apps.ingestion.tasks import rescore_and_broadcast_asset
            rescore_and_broadcast_asset.apply_async(
                kwargs={
                    'asset_id': str(finding.asset_id),
                    'organization_id': str(request.auth['organization_id']),
                },
                countdown=1,
            )

        return Response(FindingDetailSerializer(finding).data)


class DiscoveryScanView(APIView):
    """
    POST /api/discovery/scan/

    Triggers a global vulnerability ingestion scan across all ecosystems.
    """
    permission_classes = [IsAuthenticated, IsAdminOrAbove]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'discovery'

    def post(self, request):
        from apps.ingestion.tasks import trigger_all_ecosystems
        trigger_all_ecosystems.apply_async(queue='ingestion')
        return Response({'detail': 'Discovery scan queued'}, status=status.HTTP_202_ACCEPTED)


class DashboardStatsView(APIView):
    """
    GET /api/dashboard/stats/

    Single endpoint that powers the four summary cards at the top
    of the dashboard. One request, one DB round-trip via a single
    annotated queryset — not four separate API calls.
    """
    permission_classes = [IsAuthenticated, IsAnalystOrAbove]

    def get(self, request):
        from apps.assets.models import Asset
        org_id = request.auth['organization_id']

        # All stats in two queries — one for asset-level data,
        # one for finding-level data
        asset_stats = Asset.objects.filter(organization_id=org_id).aggregate(
            total_assets=Count('id'),
            avg_risk_score=Avg('risk_score'),
        )

        finding_stats = Finding.objects.filter(
            asset__organization_id=org_id,
            status=Finding.Status.OPEN,
        ).aggregate(
            total_open=Count('id'),
            critical=Count('id', filter=Q(risk_score__gte=90)),
            high=Count('id', filter=Q(risk_score__gte=70, risk_score__lt=90)),
        )

        # The single most critical asset — for the "top threat" card
        most_critical = (
            Asset.objects
            .filter(organization_id=org_id)
            .filter(risk_score__gt=0)
            .order_by('-risk_score')
            .values('id', 'name', 'risk_score', 'environment')
            .first()
        )

        if most_critical:
            most_critical['id'] = str(most_critical['id'])

        data = {
            'total_assets': asset_stats['total_assets'] or 0,
            'total_open_findings': finding_stats['total_open'] or 0,
            'critical_findings': finding_stats['critical'] or 0,
            'high_findings': finding_stats['high'] or 0,
            'avg_risk_score': round(asset_stats['avg_risk_score'] or 0, 1),
            'most_critical_asset': most_critical,
        }

        serializer = DashboardStatsSerializer(data)
        return Response(serializer.data)


class VulnerabilityPagination(CursorPagination):
    ordering = '-published_at'
    page_size = 50


class VulnerabilityViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    """
    Global vulnerability catalog — not tenant-scoped.
    RLS does not apply here because Vulnerability has no org FK.
    Used for the "CVE lookup" feature and finding detail pages.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = VulnerabilitySerializer
    pagination_class = VulnerabilityPagination
    ordering_fields = ['published_at', 'severity', 'id']
    ordering = ['-published_at']

    def get_queryset(self):
        qs = Vulnerability.objects.all()

        if severity := self.request.query_params.get('severity'):
            qs = qs.filter(severity=severity)

        if search := self.request.query_params.get('q'):
            qs = qs.filter(
                Q(id__icontains=search) | Q(summary__icontains=search)
            )

        return qs
