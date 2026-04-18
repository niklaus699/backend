import pytest
from django.contrib.auth.hashers import make_password
from django.db import connection
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

# Adjust these imports based on your actual model locations
from apps.tenants.models import Organization, User
from apps.assets.models import Asset
from apps.vulnerabilities.version_matching import AffectedRange, RangeType, VersionEvent

# --- General Fixtures ---

@pytest.fixture
def api_client():
    """A basic DRF test client."""
    return APIClient()

# --- Tenant & User Fixtures ---

@pytest.fixture
def tenant_a(db):
    return Organization.objects.create(name="Cyberdyne Systems", slug="cyberdyne")

@pytest.fixture
def tenant_b(db):
    return Organization.objects.create(name="Stark Industries", slug="stark")

@pytest.fixture
def tenant_a_user(tenant_a):
    with connection.cursor() as cursor:
        cursor.execute(f"SET sentinel.current_tenant_id = '{tenant_a.id}';")
        user = User.objects.create(
            email="niklaus@sentinel.com",
            organization=tenant_a,
            password_hash=make_password("securepassword123"),
            role="admin")
        cursor.execute("RESET ALL;")
        return user

@pytest.fixture
def tenant_a_context(tenant_a):
    """Provides just the tenant object for raw SQL session tests."""
    return tenant_a

# --- Asset Fixtures ---

@pytest.fixture
def tenant_a_asset(tenant_a):
    # IMPORTANT: We must bypass RLS to create the test data
    with connection.cursor() as cursor:
        cursor.execute(f"SET sentinel.current_tenant_id = '{tenant_a.id}';")
        asset = Asset.objects.create(
            name="Production Web Server", 
            organization=tenant_a, # Use 'organization', not 'tenant'
            ip_address="192.168.1.10"
        )
        cursor.execute("RESET ALL;")
        return asset

@pytest.fixture
def tenant_b_asset(tenant_b):
    from django.db import connection
    with connection.cursor() as cursor:
        # Manually set the session variable so the INSERT is allowed
        cursor.execute(f"SET LOCAL sentinel.current_tenant_id = '{tenant_b.id}';")
        asset = Asset.objects.create(
            name="Stark Secret Database",
            organization=tenant_b,
            ip_address="10.0.0.5"
        )
        # Reset it after
        cursor.execute("RESET ALL;")
        return asset

# --- Vulnerability / OSV Fixtures ---

@pytest.fixture
def sample_osv_range():
    """A standard vulnerability range for version matching tests."""
    return [
        AffectedRange(
            range_type=RangeType.ECOSYSTEM, 
            events=[
                VersionEvent(introduced="0"),
                VersionEvent(fixed="2.32.0")
            ]
        )
    ]

# --- Helper Logic ---

@pytest.fixture
def authenticated_client(api_client, tenant_a_user):
    """An API client that is already logged in as Tenant A."""
    # Ensure organization is loaded for the serializer claims
    from apps.tenants.serializers import SentinelTokenObtainSerializer

    refresh = RefreshToken.for_user(tenant_a_user)
    # Inject the specific claims your middleware needs
    SentinelTokenObtainSerializer._inject_claims(refresh, tenant_a_user)

    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client