import pytest
from django.test import override_settings
from django.urls import reverse
from django.db import connection
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from apps.tenants.serializers import SentinelTokenObtainSerializer

@pytest.mark.django_db
class TestTenantIsolation:
    """
    Tests for ensuring multi-tenancy isolation at both the Application (API) 
    and Database (RLS) levels.
    """

    def test_tenant_a_cannot_access_tenant_b_asset(self, api_client, tenant_a_user, tenant_b_asset):
        """
        GIVEN: User is authenticated as Tenant A.
        WHEN: They attempt to access an Asset ID belonging to Tenant B.
        THEN: The system returns 403 or 404, preventing cross-tenant data leakage.
        """
        api_client.force_authenticate(user=tenant_a_user)
        
        url = reverse('asset-detail', kwargs={'pk': tenant_b_asset.pk})
        response = api_client.get(url)
        
        # Accept 403 (Forbidden) or 404 (Not Found) as valid security responses
        assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

    def test_database_level_rls_integrity(self):
        """
        GIVEN: The PostgreSQL database schema.
        WHEN: Checking the system policies.
        THEN: The Row Level Security policy must exist on the assets_asset table.
        """
        with connection.cursor() as cursor:
            # Verify the policy exists and uses our specific tenant setting
            cursor.execute("""
                SELECT count(*) 
                FROM pg_policies 
                WHERE tablename = 'assets_asset' 
                AND cmd = 'ALL' 
                AND qual LIKE '%app.current_tenant_id%';
            """)
            policy_count = cursor.fetchone()[0]
            assert policy_count > 0, "CRITICAL: RLS Policy is missing from assets_asset table!"


@pytest.mark.django_db
def test_jwt_payload_contains_tenant_id(tenant_a_user):
    """
    Ensures that the JWT token contains the organization_id, which is 
    required by the middleware to set the Postgres session variable.
    """
    refresh = RefreshToken.for_user(tenant_a_user)
    SentinelTokenObtainSerializer._inject_claims(refresh, tenant_a_user)
    access_token = refresh.access_token
    
    assert 'organization_id' in access_token
    assert str(access_token['organization_id']) == str(tenant_a_user.organization.id)


@pytest.mark.django_db
@override_settings(
    SECURE_HSTS_SECONDS=31536000,
    SECURE_HSTS_INCLUDE_SUBDOMAINS=True,
    SECURE_HSTS_PRELOAD=True,
)
def test_security_headers_active(api_client):
    """
    Ensures standard security headers are present to protect against 
    clickjacking, MIME-sniffing, and MITM attacks.
    """
    # Use secure=True to simulate HTTPS for HSTS testing
    response = api_client.get('/api/v1/health/', secure=True)
    
    assert response.status_code == 200
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'Strict-Transport-Security' in response.headers