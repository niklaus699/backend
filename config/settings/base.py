import importlib.util
import os
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv

from .utils import env_bool, env_int

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY", "local-development-only-secret-key")
DEBUG = env_bool("DEBUG", False)
ALLOWED_HOSTS: list[str] = []
CSRF_TRUSTED_ORIGINS: list[str] = []
CORS_ALLOWED_ORIGINS: list[str] = []
CORS_ALLOW_CREDENTIALS = True
AUTH_USER_MODEL = 'tenants.User'

HAS_SPECTACULAR = importlib.util.find_spec("drf_spectacular") is not None

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third Party
    'channels',
    'rest_framework',
    'corsheaders',
    'django_celery_beat',
    'rest_framework_simplejwt',
    # Internal Apps
    'apps.tenants',
    'apps.assets',
    'apps.vulnerabilities',
    'apps.ingestion',
]

if HAS_SPECTACULAR:
    INSTALLED_APPS.append('drf_spectacular')

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'apps.tenants.security.ContentSecurityPolicyMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'apps.tenants.middleware.TenantMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'
WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = 'static/'
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}


DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv('DATABASE_URL', 'postgresql://localhost:5432/sentinel'),
        conn_max_age=env_int('CONN_MAX_AGE', 600),
        engine='django.db.backends.postgresql',
    )
}


CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'sentinel-local',
    }
}


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.CursorPagination',
    'PAGE_SIZE': 50,
    'EXCEPTION_HANDLER': 'apps.tenants.exceptions.sentinel_exception_handler',
}


if HAS_SPECTACULAR:
    REST_FRAMEWORK['DEFAULT_SCHEMA_CLASS'] = 'drf_spectacular.openapi.AutoSchema'

SIMPLE_JWT = {
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Sentinel API',
    'DESCRIPTION': 'Sentinel backend API schema',
    'VERSION': '1.0.0',
} if HAS_SPECTACULAR else {}

EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

REDIS_URL = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', REDIS_URL)
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', REDIS_URL)
# CELERY_TASK_ROUTES = {
#     'apps.ingestion.tasks.ingest_osv_ecosystem': {'queue': 'ingestion'},
#     'apps.ingestion.tasks.trigger_all_ecosystems': {'queue': 'ingestion'},
#     'apps.ingestion.tasks.correlate_vulnerability': {'queue': 'correlation'},
#     'apps.ingestion.tasks.rescore_and_broadcast_asset': {'queue': 'correlation'},
#     'apps.vulnerabilities.tasks.snapshot_risk_scores': {'queue': 'correlation'},
# }
CELERY_TASK_ALWAYS_EAGER = env_bool('CELERY_TASK_ALWAYS_EAGER', False)

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [REDIS_URL],
        },
    },
}

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
CONTENT_SECURITY_POLICY: dict[str, tuple[str, ...]] = {}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
