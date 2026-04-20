import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.tenants.context import tenant_context
from apps.tenants.models import Organization, User
from apps.assets.models import Asset, Package
from apps.vulnerabilities.models import Vulnerability, Finding
from apps.vulnerabilities.version_matching import AffectedRange, RangeType, VersionEvent


@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def tenant_a(db):
    return Organization.objects.create(name="Cyberdyne Systems", slug="cyberdyne")

@pytest.fixture
def tenant_b(db):
    return Organization.objects.create(name="Stark Industries", slug="stark")

@pytest.fixture
def tenant_a_user(tenant_a):
    return User.objects.create_user(
        email="niklaus@sentinel.com",
        organization=tenant_a,
        password="securepassword123",
        role=User.Role.ADMIN,
    )


@pytest.fixture
def tenant_b_user(tenant_b):
    return User.objects.create_user(
        email="pepper@stark.com",
        organization=tenant_b,
        password="securepassword123",
        role=User.Role.ADMIN,
    )

@pytest.fixture
def tenant_a_context(tenant_a):
    return tenant_a

@pytest.fixture
def tenant_a_asset(tenant_a):
    with tenant_context(tenant_a.id):
        return Asset.objects.create(
            name="Production Web Server",
            organization=tenant_a,
            asset_type=Asset.AssetType.SERVER,
            environment=Asset.Environment.PRODUCTION,
            hostname="web-01.cyberdyne.local",
            ip_address="192.168.1.10",
        )

@pytest.fixture
def tenant_b_asset(tenant_b):
    with tenant_context(tenant_b.id):
        return Asset.objects.create(
            name="Stark Secret Database",
            organization=tenant_b,
            asset_type=Asset.AssetType.DATABASE,
            environment=Asset.Environment.PRODUCTION,
            hostname="db-01.stark.local",
            ip_address="10.0.0.5",
        )

@pytest.fixture
def tenant_a_package(tenant_a, tenant_a_asset):
    with tenant_context(tenant_a.id):
        return Package.objects.create(
            asset=tenant_a_asset,
            name="django",
            version="6.0.4",
            ecosystem="PyPI",
        )


@pytest.fixture
def sample_vulnerability():
    return Vulnerability.objects.create(
        id="CVE-2099-0001",
        source=Vulnerability.Source.OSV,
        summary="Test vulnerability",
        severity=Vulnerability.Severity.HIGH,
        cvss_score=8.8,
        affected_ranges=[],
        references=["https://example.com/advisory"],
    )


@pytest.fixture
def tenant_a_finding(tenant_a, tenant_a_asset, tenant_a_package, sample_vulnerability):
    with tenant_context(tenant_a.id):
        return Finding.objects.create(
            asset=tenant_a_asset,
            vulnerability=sample_vulnerability,
            package=tenant_a_package,
            status=Finding.Status.OPEN,
            risk_score=88,
        )

@pytest.fixture
def sample_osv_range():
    return [
        AffectedRange(
            range_type=RangeType.ECOSYSTEM, 
            events=[
                VersionEvent(introduced="0"),
                VersionEvent(fixed="2.32.0")
            ]
        )
    ]

@pytest.fixture
def authenticated_client(api_client, tenant_a_user):
    from apps.tenants.serializers import SentinelTokenObtainSerializer

    refresh = RefreshToken.for_user(tenant_a_user)
    SentinelTokenObtainSerializer._inject_claims(refresh, tenant_a_user)

    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    return api_client
