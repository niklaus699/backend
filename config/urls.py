"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from apps.ingestion.views import AssetIngestionView
from apps.tenants.views import LoginView, health_check, RegisterView
from apps.assets.views import AssetViewSet
from apps.vulnerabilities.views import (
    FindingViewSet,
    VulnerabilityViewSet,
    DashboardStatsView,
    DiscoveryScanView,
)

try:
    from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
except ImportError:
    SpectacularAPIView = None
    SpectacularSwaggerView = None

router = DefaultRouter()
router.register('assets', AssetViewSet, basename='asset')
router.register('findings', FindingViewSet, basename='finding')
router.register('vulnerabilities', VulnerabilityViewSet, basename='vulnerability')


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/login/', LoginView.as_view(), name='login'),
    path('api/auth/register/', RegisterView.as_view(), name='register'),
    path('api/auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/dashboard/stats/', DashboardStatsView.as_view(), name='dashboard_stats'),
    path('api/discovery/scan/', DiscoveryScanView.as_view(), name='discovery_scan'),
    path('api/', include(router.urls)),
    path('api/v1/health/', health_check, name='health_check'),
    path('api/ingestion/sync/',  AssetIngestionView.as_view(), name='ingestion-sync'),
]

if SpectacularAPIView and SpectacularSwaggerView:
    urlpatterns += [
        path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
        path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='api-docs'),
    ]
