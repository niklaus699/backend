from unittest.mock import patch

import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestAssetViewSet:
    def test_list_assets_returns_only_current_tenant_assets(
        self,
        authenticated_client,
        tenant_a_asset,
        tenant_b_asset,
    ):
        response = authenticated_client.get(reverse('asset-list'))

        assert response.status_code == status.HTTP_200_OK
        asset_ids = {item['id'] for item in response.data['results']}
        assert str(tenant_a_asset.id) in asset_ids
        assert str(tenant_b_asset.id) not in asset_ids

    def test_cannot_access_other_org_asset_detail(
        self,
        authenticated_client,
        tenant_b_asset,
    ):
        response = authenticated_client.get(
            reverse('asset-detail', kwargs={'pk': tenant_b_asset.id})
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_trigger_scan_passes_organization_context(
        self,
        authenticated_client,
        tenant_a_asset,
    ):
        with patch('apps.ingestion.tasks.correlate_new_packages_for_asset.apply_async') as mocked_apply_async:
            response = authenticated_client.post(
                reverse('asset-trigger-scan', kwargs={'pk': tenant_a_asset.id})
            )

        assert response.status_code == status.HTTP_202_ACCEPTED
        mocked_apply_async.assert_called_once()
        kwargs = mocked_apply_async.call_args.kwargs['kwargs']
        assert kwargs['asset_id'] == str(tenant_a_asset.id)
        assert kwargs['organization_id'] == str(tenant_a_asset.organization_id)
