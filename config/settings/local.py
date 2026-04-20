from .base import *
from datetime import timedelta

DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

SIMPLE_JWT = {
    **SIMPLE_JWT,
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1), # Long life for dev
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'SIGNING_KEY': SECRET_KEY,
}

# Merge REST_FRAMEWORK settings for development
REST_FRAMEWORK = {
    **REST_FRAMEWORK,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '1000/hour',      # More lenient for development
        'user': '10000/hour',     # More lenient for development
        'login': '100/hour',      # More lenient for development
        'discovery': '1000/hour', # More lenient for development
        'ingestion': '10000/hour',# More lenient for development
    },
}

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
