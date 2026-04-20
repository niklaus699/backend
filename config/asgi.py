"""
ASGI config for config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/asgi/
"""
import os
import django

# Set settings before importing anything else
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.production')
django.setup()

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import OriginValidator  # Changed this
from django.urls import re_path
from apps.vulnerabilities.consumers import DashboardConsumer

# Initialize Django ASGI application early to ensure the AppRegistry is populated
django_asgi_app = get_asgi_application()

websocket_urlpatterns = [
    re_path(r'ws/dashboard/$', DashboardConsumer.as_asgi()),
]

# Get the frontend origin from environment or list it explicitly
# Using a list to include both Vercel and potential local development
trusted_origins = [
    "https://package-sentinel-theta.vercel.app",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
]

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": OriginValidator(
        URLRouter(websocket_urlpatterns),
        trusted_origins
    ),
})