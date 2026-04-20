import os
from datetime import timedelta

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

from .base import *
from .utils import env_bool, env_int, env_list, env_required

DEBUG = False
# Uses the real key if present, falls back to the build-dummy only during Docker build
SECRET_KEY = os.getenv('SECRET_KEY') or os.getenv('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise ImproperlyConfigured('SECRET_KEY environment variable is required')


ALLOWED_HOSTS = env_list('ALLOWED_HOSTS')

if not ALLOWED_HOSTS and SECRET_KEY != 'build-dummy':
    raise ImproperlyConfigured('ALLOWED_HOSTS must be configured for production')
elif not ALLOWED_HOSTS:
    # Fallback for collectstatic during docker build
    ALLOWED_HOSTS = ['localhost', '127.0.0.1']

CORS_ALLOWED_ORIGINS = env_list('CORS_ALLOWED_ORIGINS')
CSRF_TRUSTED_ORIGINS = env_list('CSRF_TRUSTED_ORIGINS')


db_url = os.getenv('DATABASE_URL')
if not db_url and SECRET_KEY == 'build-dummy':
    # Dummy URL for collectstatic phase
    db_url = 'postgres://user:pass@localhost:5432/db'
elif not db_url:
    raise ImproperlyConfigured('DATABASE_URL environment variable is required')

db_config = dj_database_url.config(
    default=db_url,
    conn_max_age=env_int('CONN_MAX_AGE', 600),
    engine='django.db.backends.postgresql',
)
db_config.setdefault('OPTIONS', {})
db_config['OPTIONS']['sslmode'] = os.getenv('DB_SSLMODE', 'require')
DATABASES = {'default': db_config}


INSTALLED_APPS += [
    'whitenoise.runserver_nostatic', # Optional, for whitenoise
]

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.getenv('CACHE_URL', os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/1')),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')],
        },
    },
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.getenv('EMAIL_HOST', '')
EMAIL_PORT = env_int('EMAIL_PORT', 587)
EMAIL_USE_TLS = env_bool('EMAIL_USE_TLS', True)
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'noreply@sentinel.local')

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = env_bool('USE_X_FORWARDED_HOST', True)
SECURE_SSL_REDIRECT = env_bool('SECURE_SSL_REDIRECT', True)
SECURE_HSTS_SECONDS = env_int('SECURE_HSTS_SECONDS', 31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', True)
SECURE_HSTS_PRELOAD = env_bool('SECURE_HSTS_PRELOAD', True)
SECURE_REFERRER_POLICY = 'same-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

CONTENT_SECURITY_POLICY = {
    "default-src": ("'self'",),
    "img-src": ("'self'", "data:", "https:"),
    "style-src": ("'self'", "'unsafe-inline'"),
    "script-src": ("'self'",),
    "connect-src": ("'self'", "https:", "wss:"),
    "frame-ancestors": ("'none'",),
}

SIMPLE_JWT = {
    **SIMPLE_JWT,
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}

REST_FRAMEWORK = {
    **REST_FRAMEWORK,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': os.getenv('THROTTLE_ANON_RATE', '100/hour'),
        'user': os.getenv('THROTTLE_USER_RATE', '1000/hour'),
        'login': os.getenv('THROTTLE_LOGIN_RATE', '5/minute'),
        'discovery': os.getenv('THROTTLE_DISCOVERY_RATE', '10/hour'),
        'ingestion': os.getenv('THROTTLE_INGESTION_RATE', '60/hour'),
    },
}

CELERY_RESULT_EXPIRES = env_int('CELERY_RESULT_EXPIRES', 3600)
CELERY_TASK_TRACK_STARTED = True

LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', '')
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'level': LOG_LEVEL,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': LOG_LEVEL,
    },
}

if LOG_FILE:
    LOGGING['handlers']['file'] = {
        'level': LOG_LEVEL,
        'class': 'logging.handlers.RotatingFileHandler',
        'filename': LOG_FILE,
        'maxBytes': 1024 * 1024 * 10,
        'backupCount': 10,
        'formatter': 'verbose',
    }
    LOGGING['root']['handlers'].append('file')

SENTRY_DSN = os.getenv('SENTRY_DSN')
if SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.django import DjangoIntegration
    except ImportError:
        sentry_sdk = None
    else:
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            integrations=[DjangoIntegration()],
            traces_sample_rate=float(os.getenv('SENTRY_TRACES_SAMPLE_RATE', '0.1')),
            environment=os.getenv('ENVIRONMENT', 'production'),
        )
