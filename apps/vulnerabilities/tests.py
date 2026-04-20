from unittest.mock import patch

import pytest
from django.urls import reverse
from rest_framework import status

from apps.tenants.context import tenant_context
from apps.vulnerabilities.models import Finding


@pytest.mark.django_db
class TestVulnerabilityViews:
    def test_dashboard_stats_are_tenant_scoped(
        self,
        authenticated_client,
        tenant_a,
        tenant_b,
        tenant_a_asset,
        tenant_a_finding,
        tenant_b_asset,
        sample_vulnerability,
    ):
        with tenant_context(tenant_b.id):
            Finding.objects.create(
                asset=tenant_b_asset,
                vulnerability=sample_vulnerability,
                package=None,
                status=Finding.Status.OPEN,
                risk_score=99,
            )

        response = authenticated_client.get(reverse('dashboard_stats'))

        assert response.status_code == status.HTTP_200_OK
        assert response.data['total_assets'] == 1
        assert response.data['total_open_findings'] == 1
        assert response.data['critical_findings'] == 0
        assert response.data['high_findings'] == 1
        assert response.data['most_critical_asset']['id'] == str(tenant_a_asset.id)

    def test_findings_list_is_tenant_scoped(
        self,
        authenticated_client,
        tenant_b,
        tenant_b_asset,
        sample_vulnerability,
        tenant_a_finding,
    ):
        with tenant_context(tenant_b.id):
            Finding.objects.create(
                asset=tenant_b_asset,
                vulnerability=sample_vulnerability,
                package=None,
                status=Finding.Status.OPEN,
                risk_score=92,
            )

        response = authenticated_client.get(reverse('finding-list'))

        assert response.status_code == status.HTTP_200_OK
        returned_ids = {item['id'] for item in response.data['results']}
        assert str(tenant_a_finding.id) in returned_ids
        assert len(returned_ids) == 1

    def test_update_status_enqueues_rescore_with_org_context(
        self,
        authenticated_client,
        tenant_a_finding,
    ):
        with patch('apps.ingestion.tasks.rescore_and_broadcast_asset.apply_async') as mocked_apply_async:
            response = authenticated_client.patch(
                reverse('finding-update-status', kwargs={'pk': tenant_a_finding.id}),
                {'status': Finding.Status.RESOLVED},
                format='json',
            )

        assert response.status_code == status.HTTP_200_OK
        kwargs = mocked_apply_async.call_args.kwargs['kwargs']
        assert kwargs['asset_id'] == str(tenant_a_finding.asset_id)
        assert kwargs['organization_id'] == str(tenant_a_finding.asset.organization_id)
