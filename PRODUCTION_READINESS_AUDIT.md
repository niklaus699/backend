# Production Readiness Assessment
**Sentinel Backend** | Django 6.0.4 + DRF 3.17.1  
**Assessment Date:** April 20, 2026  
**Status:** ⚠️ NOT PRODUCTION READY – Critical issues require resolution

---

## Executive Summary

The Sentinel backend demonstrates **solid architectural foundations** with multi-tenancy, async processing, WebSocket support, and comprehensive vulnerability correlation. However, **critical security and configuration gaps** prevent production deployment:

- **Production settings are incomplete** (empty production.py, insecure defaults)
- **Multi-tenancy data isolation has a bug** (DashboardStatsView returns global stats)
- **Settings module defaults to local** across entry points (ASGI, Celery, manage.py)
- **Test coverage is minimal** (empty test files, ~5% coverage estimate)
- **Security headers and HTTPS hardening not configured**

**Estimated effort to production-ready:** 3-5 days for an experienced Django developer.

---

## 1. ARCHITECTURE & CODE QUALITY

### ✅ Strengths

- **Well-structured multi-tenancy architecture** using organization-based scoping and PostgreSQL RLS
- **Async first** with Celery for correlation and ingestion, WebSocket for real-time updates
- **Clean separation of concerns**: models, views, serializers, tasks follow Django conventions
- **Thoughtful API design**: RESTful endpoints, cursor pagination, filtered querysets
- **Good naming conventions and module organization**: apps logically separated (tenants, assets, vulnerabilities, ingestion)
- **ORM optimization**: Prefetch relations, select_related, aggregations to avoid N+1 queries

### ⚠️ Issues

| Issue | Severity | Details |
|-------|----------|---------|
| User model doesn't inherit AbstractBaseUser | HIGH | Custom User model has `password_hash` field but uses Django's make_password/check_password. Should inherit from `AbstractBaseUser` or `AbstractUser` for consistency and future compatibility. See comment: "In production you'd inherit AbstractBaseUser" |
| No input validation in parsers | MEDIUM | Manifest parsers use regex without comprehensive validation; XML parser catches ParseError but doesn't validate schema |
| Limited error context in tasks | MEDIUM | OSV ingestion and correlation tasks catch generic `Exception` – logs are minimal for debugging |
| Magic numbers in scoring | LOW | Risk score multipliers hardcoded in scoring.py – should be configurable |

### 🔍 Code Quality Assessment

- **Code style**: Consistent, readable, PEP 8 compliant
- **Documentation**: Docstrings present for key functions; good inline comments explaining RLS and multi-tenancy
- **Circular import risk**: Minimal (uses `from ... import ...` inside functions where needed)
- **Duplication**: Low – good reuse of serializers and utility functions

---

## 2. SECURITY

### 🚨 CRITICAL ISSUES

#### 2.1 Empty Production Settings
**File:** [config/settings/production.py](config/settings/production.py)  
**Status:** CRITICAL  
**Impact:** All production deployments will use local development settings

```python
# Current state:
# SECURE_HSTS_SECONDS = 31536000
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_SSL_REDIRECT = False
```

**Required additions:**
```python
# config/settings/production.py
from .base import *

DEBUG = False
ALLOWED_HOSTS = ['api.sentinel.example.com', 'www.sentinel.example.com']
SECRET_KEY = os.getenv('SECRET_KEY')  # Must be set; no fallback

# Security headers
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_SECURITY_POLICY = {
    "default-src": ("'self'",),
    "script-src": ("'self'", "'unsafe-inline'"),
    "style-src": ("'self'", "'unsafe-inline'"),
}

# Database with SSL
DATABASES = {
    'default': {
        **dj_database_url.config(
            default=os.getenv('DATABASE_URL'),
            conn_max_age=600,
            engine='django.db.backends.postgresql',
        ),
        'OPTIONS': {
            'sslmode': 'require',
        }
    }
}

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')

# Cache with Redis
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/1'),
    }
}

# Session security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

# CSRF
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_TRUSTED_ORIGINS = os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',')

# JWT settings
SIMPLE_JWT = {
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}

# Logging for production
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
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/sentinel/django.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        }
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
}
```

#### 2.2 Settings Module Defaults to Local Environment
**Files:** 
- [config/wsgi.py](config/wsgi.py) line 13: `'config.settings.production'` ✓
- [config/asgi.py](config/asgi.py) line 14: `'config.settings.local'` ❌
- [config/celery.py](config/celery.py) line 5: `'config.settings.local'` ❌  
- [manage.py](manage.py) line 14: `'config.settings.local'` ❌

**Status:** HIGH  
**Impact:** ASGI (WebSocket), Celery workers, and CLI all use development settings in production

**Fix:**
```python
# config/asgi.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.production')

# config/celery.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.production')

# manage.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.production')
```

**For development, override locally:**
```bash
export DJANGO_SETTINGS_MODULE=config.settings.local
./manage.py runserver

# Or use a dev management command wrapper
```

#### 2.3 ALLOWED_HOSTS Is Empty
**File:** [config/settings/base.py](config/settings/base.py) line 23  
**Status:** CRITICAL  
**Current:** `ALLOWED_HOSTS = []`  
**Impact:** In production with DEBUG=False, all requests will return 400 Bad Request

**Fix:** Move to production.py and populate from environment:
```python
# config/settings/production.py
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'api.sentinel.example.com').split(',')
```

#### 2.4 SECRET_KEY Has Insecure Fallback
**File:** [config/settings/base.py](config/settings/base.py) line 19  
**Current:** `SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-fallback-key-change-this")`

**Status:** CRITICAL  
**Impact:** Any deployment without SECRET_KEY env var uses the hardcoded insecure key

**Fix:**
```python
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ImproperlyConfigured(
        'SECRET_KEY environment variable is not set. '
        'Generate with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
    )
```

#### 2.5 TenantMiddleware Has Race Condition
**File:** [apps/tenants/middleware.py](apps/tenants/middleware.py)  
**Status:** HIGH  
**Issue:** The middleware tries to extract `organization_id` from `request.auth` before authentication runs

```python
def _extract_tenant_id(self, request) -> str | None:
    # request.auth is populated by REST Framework's authentication,
    # which usually runs during the view.
    # To access it in middleware, ensure you're using JWTAuthentication correctly.
    if hasattr(request, 'auth') and request.auth is not None:
        return request.auth.get('organization_id')
    return None
```

**Problem:** REST Framework's authentication phase runs in the view layer (after middleware). This middleware will never find `request.auth` populated.

**Root Cause:** The JWT token needs to be extracted and validated in the middleware itself.

**Fix:**
```python
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed

class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/api/auth/'):
            return self.get_response(request)

        tenant_id = self._extract_tenant_id_from_jwt(request)

        if tenant_id:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('app.current_tenant_id', %s, true)",
                    [str(tenant_id)]
                )

        return self.get_response(request)

    def _extract_tenant_id_from_jwt(self, request) -> str | None:
        """Extract and validate JWT token directly from Authorization header."""
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return None
        
        token_str = auth_header[7:]  # Remove 'Bearer ' prefix
        try:
            token = AccessToken(token_str)
            return token.get('organization_id')
        except (InvalidToken, AuthenticationFailed, Exception):
            return None  # Invalid token; will be rejected by view authentication
```

#### 2.6 RLS Policies Don't Fail Safely If Tenant ID Missing
**File:** [apps/tenants/migrations/0002_enable_rls.py](apps/tenants/migrations/0002_enable_rls.py)  
**Status:** HIGH  
**Issue:** RLS policies check if a row's organization matches the Postgres session variable, but if `app.current_tenant_id` is not set (NULL), the policies may not work as intended.

```sql
CREATE POLICY tenant_isolation ON assets_asset
USING (
    organization_id = current_setting('app.current_tenant_id', true)::uuid
);
```

**Risk:** If middleware fails to set the session variable or a Celery task doesn't set it, the policy comparison becomes `org_id = NULL`, which is always FALSE (good) or could silently return no rows, making it hard to debug.

**Recommendation:** Make the session variable mandatory:
```python
# In middleware and before Celery tasks:
with connection.cursor() as cursor:
    cursor.execute(
        "SELECT set_config('app.current_tenant_id', %s, false)",  # false = session-level, not transaction
        [str(tenant_id)]
    )
    # Verify it was set:
    cursor.execute("SELECT current_setting('app.current_tenant_id')")
    current = cursor.fetchone()[0]
    if not current:
        raise RuntimeError("Failed to set tenant context")
```

**Also add a database-level check:**
```python
# In a post_migrate signal or separate migration:
cursor.execute("""
    CREATE OR REPLACE FUNCTION check_tenant_isolation()
    RETURNS TRIGGER AS $$
    BEGIN
        IF current_setting('app.current_tenant_id', true) IS NULL THEN
            RAISE EXCEPTION 'Tenant context not set. Set app.current_tenant_id before querying.';
        END IF;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    
    CREATE TRIGGER enforce_tenant_on_insert BEFORE INSERT ON assets_asset
    FOR EACH ROW EXECUTE FUNCTION check_tenant_isolation();
""")
```

#### 2.7 CORS Not Fully Configured for Production
**File:** [config/settings/local.py](config/settings/local.py)  
**Current:**
```python
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
```

**Status:** MEDIUM  
**Missing in base.py/production.py:**
```python
# config/settings/production.py
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', '').split(',')
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_CREDENTIALS_ORIGINS = CORS_ALLOWED_ORIGINS
CORS_MAX_AGE = 3600
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
```

#### 2.8 API Rate Limiting Not Configured
**Status:** MEDIUM  
**Issue:** No rate limiting on authentication endpoints or other expensive operations (discovery scan, ingestion).

**Recommendation:** Add throttling to DRF:
```python
# config/settings/production.py
REST_FRAMEWORK = {
    # ... existing config ...
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'login': '5/minute',  # Custom scope for login endpoint
    }
}
```

And apply to views:
```python
from rest_framework.throttling import ScopedRateThrottle

class LoginView(APIView):
    throttle_scope = 'login'
    # ...
```

#### 2.9 WebSocket Consumer Not Over HTTPS
**File:** [apps/vulnerabilities/consumers.py](apps/vulnerabilities/consumers.py)  
**Status:** MEDIUM  
**Issue:** JWT token passed as query string in WebSocket URL (`?token=eyJ...`).

**Risk:** 
- Query strings are logged in server logs
- May be cached in browser history
- Not encrypted in HTTP

**Better approach:** Use sub-protocol authentication or secure cookies (if same-origin).

**Note:** The `AllowedHostsOriginValidator` in [config/asgi.py](config/asgi.py) is good, but configure properly for HTTPS:
```python
# config/settings/production.py
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
```

---

### ✅ Security Strengths

| Area | Status | Details |
|------|--------|---------|
| **Authentication** | ✅ Good | JWT with SimplJWT, custom claims for org_id and role |
| **Password Hashing** | ✅ Good | Uses Django's make_password (PBKDF2), not plain text |
| **Authorization** | ✅ Good | Role-based permissions (viewer, analyst, admin, owner) |
| **Multi-tenancy** | ✅ Strong | PostgreSQL RLS + application-level filtering |
| **CSRF Protection** | ✅ Enabled | CsrfViewMiddleware in MIDDLEWARE stack |
| **Input Validation** | ✅ Good | Serializers validate all inputs; FileField size limit (5MB) |
| **SQL Injection** | ✅ Protected | ORM used throughout; parameterized queries; no raw SQL except RLS setup |
| **Data Isolation** | ✅ Excellent | Sentinel exception handler masks 403 as 404 (info leakage prevention) |
| **WebSocket Auth** | ⚠️ Partial | JWT validation in consumer; but no re-auth on connection drop |

---

## 3. TESTING

### ⚠️ CRITICAL: Minimal Test Coverage

**Current state:**

```
apps/assets/tests.py                    ← EMPTY
apps/vulnerabilities/tests.py           ← EMPTY  
apps/tenants/tests.py                   ← EMPTY
✓ apps/tenants/tests/test_security.py   ← Good (50 lines, multi-tenancy + RLS checks)
✓ apps/vulnerabilities/tests/test_version_matching.py  ← Excellent (150 lines, real CVE examples)
✓ apps/ingestion/tests/test_routing.py  ← Minimal (5 lines, just Celery routing)
```

**Estimated Coverage:** ~5-10%  
**Status:** NOT PRODUCTION READY

### Missing Test Categories

| Category | Tests Needed | Priority |
|----------|-------------|----------|
| **API endpoints** | List, detail, create, update, delete for each resource | CRITICAL |
| **Multi-tenancy isolation** | Cross-tenant access attempts | CRITICAL |
| **Authentication** | Login, refresh, register, invalid tokens | CRITICAL |
| **Permissions** | Role-based access (viewer can't create, analyst can't delete, etc.) | CRITICAL |
| **Error handling** | 400/401/403/404/500 responses | CRITICAL |
| **Celery tasks** | Ingestion, correlation, scoring, broadcasting | HIGH |
| **Integration** | End-to-end asset ingestion → finding discovery → WebSocket broadcast | HIGH |
| **Edge cases** | Empty querysets, malformed manifests, duplicate packages | HIGH |
| **Performance** | Query counts (N+1 detection), pagination | MEDIUM |
| **Concurrency** | Race conditions in asset updates, duplicate findings | MEDIUM |

### Recommended Test Structure

```python
# apps/assets/tests.py
import pytest
from rest_framework import status
from rest_framework.test import APIClient
from apps.tenants.models import Organization, User
from apps.assets.models import Asset

@pytest.mark.django_db
class TestAssetViewSet:
    """Test asset CRUD, filtering, pagination."""
    
    def test_list_assets_paginated(self, authenticated_client, tenant_a_asset):
        """Users see only their own assets."""
        response = authenticated_client.get('/api/assets/')
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1
        
    def test_cannot_access_other_org_asset(self, api_client, tenant_a_user, tenant_b_asset):
        """Cross-tenant access is blocked."""
        token = get_token_for_user(tenant_a_user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = api_client.get(f'/api/assets/{tenant_b_asset.id}/')
        assert response.status_code == status.HTTP_404_NOT_FOUND

# Run: pytest --cov=apps --cov-report=html
```

### Test Configuration

**Current [pytest.ini](pytest.ini):**
```ini
[pytest]
DJANGO_SETTINGS_MODULE = config.settings.local
python_files = tests.py test_*.py *_tests.py
addopts = --reuse-db
```

**Recommended additions:**
```ini
[pytest]
DJANGO_SETTINGS_MODULE = config.settings.local
python_files = tests.py test_*.py *_tests.py
addopts = 
    --reuse-db
    --cov=apps
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=80
    -v
testpaths = apps
```

---

## 4. CONFIGURATION MANAGEMENT

### ⚠️ Issues

#### 4.1 Empty requirements/production.txt and requirements/local.txt
**Files:** 
- [requirements/base.txt](requirements/base.txt) ✓ populated
- [requirements/production.txt](requirements/production.txt) ❌ empty
- [requirements/local.txt](requirements/local.txt) ❌ empty

**Status:** LOW (not breaking, but inconsistent)  
**Recommendation:**
```
# requirements/production.txt
-r base.txt
gunicorn==21.2.0
psycopg[binary]==3.3.3

# requirements/local.txt
-r base.txt
django-debug-toolbar==4.3.0
pytest==7.4.3
pytest-django==4.12.0
pytest-cov==7.1.0
```

#### 4.2 No .env.example File
**Status:** MEDIUM  
**Impact:** New developers don't know which environment variables to set

**Create [.env.example](.env.example):**
```bash
# Django
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,api.sentinel.example.com
DJANGO_SETTINGS_MODULE=config.settings.production

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sentinel

# Redis/Celery
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0

# Security (Production)
SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=31536000
CSRF_TRUSTED_ORIGINS=https://sentinel.example.com

# CORS
CORS_ALLOWED_ORIGINS=https://frontend.sentinel.example.com

# Email
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=SG.xxxx

# Logging
LOG_LEVEL=INFO
```

#### 4.3 No Environment Variable Validation
**Status:** MEDIUM  
**Issue:** Missing variables silently use defaults or fail at runtime

**Recommendation:** Add validation on startup:
```python
# config/settings/production.py
def _validate_env_vars():
    """Verify all required variables are set."""
    required = [
        'SECRET_KEY',
        'DATABASE_URL',
        'ALLOWED_HOSTS',
    ]
    for var in required:
        if not os.getenv(var):
            raise ImproperlyConfigured(f'{var} is not set')

if not DEBUG:
    _validate_env_vars()
```

---

## 5. DATABASE

### ✅ Strengths

| Aspect | Status | Details |
|--------|--------|---------|
| **Migrations** | ✅ Excellent | RLS properly enabled with `FORCE ROW LEVEL SECURITY` |
| **Schema design** | ✅ Good | UUIDs for all PK, ForeignKey constraints, appropriate indexes |
| **Multi-tenancy** | ✅ Strong | Organization scoping at app layer + RLS at DB layer |
| **Indexes** | ✅ Good | Partial index on `assets_asset` for risk queries, composite indexes |

### ⚠️ Issues

#### 5.1 No Database Connection Pooling in Production
**Current:** `conn_max_age=600` (10 minutes) – relies on Django's default pooling

**Status:** MEDIUM  
**Recommendation:** Use pgBouncer or django-db-conn-pool:
```python
# config/settings/production.py
DATABASES = {
    'default': {
        **dj_database_url.config(
            default=os.getenv('DATABASE_URL'),
            engine='django.db.backends.postgresql',
        ),
        'CONN_MAX_AGE': 0,  # Disable Django's pooling
        'OPTIONS': {
            'sslmode': 'require',
            'pool': {
                'min_size': 10,
                'max_size': 20,
                'timeout': 30,
            }
        }
    }
}
```

Or deploy pgBouncer as a separate service (recommended for high concurrency).

#### 5.2 RLS Policy on Package/Finding Uses Subquery
**File:** [apps/tenants/migrations/0002_enable_rls.py](apps/tenants/migrations/0002_enable_rls.py)

```sql
CREATE POLICY tenant_isolation ON assets_package
USING (
    asset_id IN (
        SELECT id FROM assets_asset
        WHERE organization_id = current_setting('app.current_tenant_id', true)::uuid
    )
);
```

**Status:** LOW  
**Impact:** Subquery on every filtered query; may cause performance issues at scale

**Better approach for production:**
```sql
-- Add a denormalized org_id to Package for direct RLS check
ALTER TABLE assets_package ADD COLUMN organization_id UUID;
-- Backfill: UPDATE assets_package p SET organization_id = a.organization_id
--           FROM assets_asset a WHERE a.id = p.asset_id;

CREATE POLICY tenant_isolation ON assets_package
USING (
    organization_id = current_setting('app.current_tenant_id', true)::uuid
);
```

#### 5.3 No Automated Backups Configuration
**Status:** MEDIUM  
**Recommendation:** Document backup strategy:
```bash
# Backup script
pg_dump postgresql://user@host/sentinel > backups/sentinel_$(date +%Y%m%d_%H%M%S).sql
```

---

## 6. ERROR HANDLING

### ✅ Strengths

| Aspect | Status | Details |
|--------|--------|---------|
| **Exception handler** | ✅ Good | [apps/tenants/exceptions.py](apps/tenants/exceptions.py) masks 403 as 404 to prevent info leakage |
| **HTTP status codes** | ✅ Good | Appropriate use of 400/401/403/404/422 |
| **Transaction rollback** | ✅ Good | `@transaction.atomic` on critical operations |

### ⚠️ Issues

#### 6.1 Ingestion Tasks Lack Error Context
**File:** [apps/ingestion/tasks.py](apps/ingestion/tasks.py)

```python
except Exception as e:
    logger.error(f"Failed to query OSV for {ecosystem}/{name}: {e}")
```

**Status:** MEDIUM  
**Issue:** Generic exception handling; stack traces not logged

**Fix:**
```python
except Exception as e:
    logger.exception(f"Failed to query OSV for {ecosystem}/{name}")  # Logs stack trace
    # Optionally send to error tracking (Sentry, Rollbar):
    import sentry_sdk
    sentry_sdk.capture_exception(e)
```

#### 6.2 No Global Exception Handler for Unexpected Errors
**Status:** MEDIUM  
**Recommendation:** Add Sentry or similar error tracking:
```python
# config/settings/production.py
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

sentry_sdk.init(
    dsn=os.getenv('SENTRY_DSN'),
    integrations=[DjangoIntegration()],
    traces_sample_rate=0.1,
    environment=os.getenv('ENVIRONMENT', 'production'),
)
```

---

## 7. ASYNC / CELERY

### ✅ Strengths

| Aspect | Status | Details |
|--------|--------|---------|
| **Task routing** | ✅ Good | Separate queues for `ingestion` and `correlation` |
| **Celery Beat** | ✅ Configured | Uses DatabaseScheduler for persistence |
| **Task signatures** | ✅ Good | Named tasks with explicit routing |
| **Retries** | ✅ Configured | `max_retries=3`, `autoretry_for` on ingest task |

### ⚠️ Issues

#### 7.1 Celery Configuration in config/celery.py Hardcodes Queue Names
**File:** [config/celery.py](config/celery.py)

```python
app.conf.beat_schedule = {
    'ingest-all-ecosystems-every-6h': {
        'task': 'apps.ingestion.tasks.trigger_all_ecosystems',
        'schedule': crontab(minute=0, hour='*/6'),
    },
}
```

**Status:** MEDIUM  
**Issue:** Hardcoded 6-hour schedule; should be configurable

**Fix:**
```python
# config/celery.py
app.conf.beat_schedule = {
    'ingest-all-ecosystems': {
        'task': 'apps.ingestion.tasks.trigger_all_ecosystems',
        'schedule': crontab(
            minute=0,
            hour=os.getenv('INGEST_SCHEDULE_HOUR', '*/6'),  # Configurable
        ),
    },
}
```

#### 7.2 No Celery Result Backend Retention Policy
**Status:** LOW  
**Issue:** Redis results accumulate indefinitely

**Recommendation:**
```python
# config/settings/production.py
CELERY_RESULT_EXPIRES = 3600  # Expire results after 1 hour
CELERY_TASK_TRACK_STARTED = True
```

#### 7.3 Missing Health Check for Celery/Redis
**Status:** MEDIUM  
**Issue:** No monitoring of Celery worker/Redis status

**Recommendation:** Add a health check endpoint:
```python
# apps/tenants/views.py
@api_view(['GET'])
def health_check(request):
    """Check Django, DB, and Celery health."""
    try:
        # DB check
        from django.db import connection
        connection.ensure_connection()
        
        # Celery check
        from apps.ingestion.tasks import ingest_osv_ecosystem
        from celery.result import AsyncResult
        result = ingest_osv_ecosystem.apply_async(
            kwargs={'ecosystem': 'PyPI'},
            countdown=999,  # Never actually runs
            expires=5,
        )
        result.revoke()  # Cancel it
        
        return Response({
            'status': 'healthy',
            'checks': {
                'database': 'ok',
                'celery': 'ok',
                'redis': 'ok',
            }
        })
    except Exception as e:
        return Response(
            {'status': 'unhealthy', 'error': str(e)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )
```

---

## 8. WEBSOCKET / REAL-TIME

### ✅ Strengths

| Aspect | Status | Details |
|--------|--------|---------|
| **Architecture** | ✅ Good | Channels with Redis channel layer |
| **Auth** | ✅ Good | JWT validation in consumer |
| **Isolation** | ✅ Good | Organization-scoped channel groups |
| **Broadcast** | ✅ Good | Celery task broadcasts to WebSocket consumers |

### ⚠️ Issues

#### 8.1 WebSocket Auth Not Secure Over HTTP
**File:** [apps/vulnerabilities/consumers.py](apps/vulnerabilities/consumers.py)

```python
def _get_token_from_scope(self) -> str | None:
    """Parse JWT from WebSocket query string: ?token=eyJ..."""
```

**Status:** MEDIUM  
**Risk:** Query strings logged in server/proxy logs

**Better approach:**
```python
# Use sub-protocol or post-authentication
# Or: tunnel WebSocket over HTTPS with secure cookies
```

#### 8.2 No Heartbeat / Connection Keepalive
**Status:** LOW  
**Issue:** Long-idle WebSocket connections may be closed by proxies

**Fix:**
```python
# Consumer
async def connect(self):
    # ... existing code ...
    # Schedule periodic heartbeat
    await self._send_heartbeat()

async def _send_heartbeat(self):
    """Send ping every 30 seconds to keep connection alive."""
    while self.connected:
        await self.send(text_data=json.dumps({"type": "ping"}))
        await asyncio.sleep(30)
```

---

## 9. DEPENDENCIES & REQUIREMENTS

### ✅ Strengths

- **Comprehensive stack:** Django 6.0.4, DRF 3.17.1, Channels 4.3.2, Celery 5.6.3
- **Security libraries:** `cryptography` (46.0.7), `PyJWT` (2.12.1)
- **Testing:** pytest, pytest-django, pytest-cov
- **Async support:** httpx, Twisted, channels_redis

### ⚠️ Issues

#### 9.1 No requirements/production.txt or requirements/local.txt
**Status:** LOW  
**See:** Configuration Management, Section 4.1

#### 9.2 Missing Production Dependencies
**Recommendations:**

```
# requirements/production.txt
-r base.txt
gunicorn==21.2.0                  # WSGI server (if not using Daphne)
whitenoise==6.6.0                 # Static file serving
django-redis==5.4.0               # Caching backend
sentry-sdk==1.38.0                # Error tracking
python-decouple==3.8              # Env var parsing
```

#### 9.3 No Security Audit of Dependencies
**Status:** MEDIUM  
**Recommendation:** Regular scans for vulnerabilities:
```bash
pip install pip-audit
pip-audit
```

---

## 10. DOCUMENTATION

### ⚠️ Issues

#### 10.1 Minimal README
**Status:** MEDIUM  
**Missing sections:**
- Architecture overview
- Installation instructions
- Configuration guide
- Deployment instructions
- Troubleshooting

#### 10.2 No API Documentation
**Status:** MEDIUM  
**Recommendation:** Add API docs with drf-spectacular:
```bash
pip install drf-spectacular
```

```python
# config/settings/base.py
INSTALLED_APPS += ['drf_spectacular']

# config/urls.py
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns += [
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema')),
]
```

#### 10.3 Missing Deployment Guide
**Status:** HIGH  
**Should include:**
- Docker Compose setup for local dev
- Production deployment (AWS/GCP/Heroku)
- Environment variable reference
- Database setup and migrations
- Celery worker configuration
- WebSocket proxy setup (nginx)

---

## 11. DEPLOYMENT & OPERATIONS

### Architecture
```
Internet
    ↓
[Nginx/Reverse Proxy]
    ↓
[Daphne Worker(s)] ← ASGI (HTTP + WebSocket)
[Gunicorn Worker(s)] ← WSGI (if dual-stack)
[Celery Ingestion Worker(s)]
[Celery Correlation Worker(s)]
[Celery Beat] ← Scheduler
    ↓
[PostgreSQL] ← RLS-enabled
[Redis] ← Message broker + caching
```

### ✅ Strengths
- **Async-first:** Daphne handles both HTTP and WebSocket
- **Scalable task processing:** Separate queues for different workloads
- **Stateless:** Suitable for container orchestration (Kubernetes)

### ⚠️ Issues

#### 11.1 No Docker / Docker Compose Configuration
**Status:** HIGH  
**Recommendation:** Create Docker setup for reproducible deployments

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
RUN apt-get update && apt-get install -y postgresql-client && rm -rf /var/lib/apt/lists/*
COPY requirements/base.txt .
RUN pip install --no-cache-dir -r base.txt
COPY . .

CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "config.asgi:application"]
```

```yaml
# docker-compose.yml
version: '3.9'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: sentinel
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: changeme
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://sentinel:changeme@postgres:5432/sentinel
      REDIS_URL: redis://redis:6379/0
      SECRET_KEY: dev-key-change-in-prod
    depends_on:
      - postgres
      - redis

  worker_ingestion:
    build: .
    command: celery -A config worker --queues=ingestion -l info
    environment:
      DATABASE_URL: postgresql://sentinel:changeme@postgres:5432/sentinel
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis

  beat:
    build: .
    command: celery -A config beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
    environment:
      DATABASE_URL: postgresql://sentinel:changeme@postgres:5432/sentinel
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis

volumes:
  postgres_data:
```

#### 11.2 No Monitoring / Observability
**Status:** MEDIUM  
**Recommendation:** Add monitoring
```bash
pip install django-health-check prometheus-client
```

#### 11.3 No Load Balancing / Auto-scaling Configuration
**Status:** MEDIUM  
**Recommendation:** Document scaling strategies for Kubernetes/ECS

---

## PRODUCTION READINESS CHECKLIST

### 🚨 CRITICAL (Must fix before deploy)
- [ ] Populate `config/settings/production.py` with all security settings
- [ ] Change ASGI/Celery/manage.py to default to production settings
- [ ] Set `ALLOWED_HOSTS` from environment variable
- [ ] Remove `SECRET_KEY` fallback; make it required
- [ ] Fix TenantMiddleware to extract JWT before view layer
- [ ] Add tests for multi-tenancy isolation (DashboardStatsView bug)
- [ ] Add comprehensive test suite (target 80%+ coverage)
- [ ] Create `.env.example` with all required variables
- [ ] Document environment variable validation

### ⚠️ HIGH (Should fix before production)
- [ ] Add database connection pooling (pgBouncer or django-db-conn-pool)
- [ ] Add rate limiting to sensitive endpoints (login, discovery scan)
- [ ] Set up error tracking (Sentry)
- [ ] Add logging configuration for production
- [ ] Create Docker/Docker Compose for reproducible deployment
- [ ] Document deployment procedure (AWS/GCP/Heroku)
- [ ] Set up monitoring (Prometheus, New Relic, or equivalent)
- [ ] Add API documentation (drf-spectacular)

### 🔷 MEDIUM (Recommended for production)
- [ ] Add requirements/production.txt and requirements/local.txt
- [ ] Implement database backups strategy
- [ ] Add WebSocket keepalive heartbeat
- [ ] Make Celery schedule configurable
- [ ] Add health check endpoint for monitoring
- [ ] Denormalize organization_id on Package table for RLS performance
- [ ] Add HTTPS/SSL redirect in production.py
- [ ] Configure CSP headers
- [ ] Document RLS policies and failsafes

### 🟦 LOW (Nice to have)
- [ ] Improve CVSS score extraction from OSV
- [ ] Make risk scoring configurable
- [ ] Add audit logging for admin actions
- [ ] Implement feature flags for A/B testing
- [ ] Add performance profiling/APM

---

## SUMMARY TABLE

| Category | Status | Notes |
|----------|--------|-------|
| **Architecture** | ⭐⭐⭐⭐ | Solid multi-tenancy, async-first design |
| **Security** | ⭐⭐⭐ | Good auth/authorization, but critical settings gaps |
| **Testing** | ⭐⭐ | Minimal coverage; needs comprehensive test suite |
| **Configuration** | ⭐⭐ | Production settings incomplete; needs env validation |
| **Database** | ⭐⭐⭐⭐ | Excellent RLS implementation; good schema |
| **Error Handling** | ⭐⭐⭐ | Good exception handling; missing observability |
| **Async/Celery** | ⭐⭐⭐⭐ | Well-structured task routing |
| **WebSocket/Real-time** | ⭐⭐⭐ | Good architecture; auth needs improvement |
| **Dependencies** | ⭐⭐⭐⭐ | Comprehensive and modern |
| **Documentation** | ⭐⭐ | Minimal; needs deployment guide |
| **Deployment** | ⭐⭐ | No Docker; no monitoring/observability |
| **Overall** | ⭐⭐⭐ | **NOT PRODUCTION READY** |

---

## ESTIMATED EFFORT TO PRODUCTION READY

| Task | Hours | Priority |
|------|-------|----------|
| Fix production.py + env config | 4 | CRITICAL |
| Add comprehensive tests (80% coverage) | 16 | CRITICAL |
| Fix multi-tenancy bugs | 4 | CRITICAL |
| Add Docker/Docker Compose | 6 | HIGH |
| Add monitoring/logging | 6 | HIGH |
| Database pooling + optimization | 4 | HIGH |
| Deployment documentation | 8 | HIGH |
| Rate limiting + security hardening | 4 | MEDIUM |
| **TOTAL** | **52 hours** | ~6-7 days (experienced Django dev) |

---

## NEXT STEPS

1. **Immediate (Before any production deployment):**
   - Create production.py configuration file
   - Fix settings defaults in ASGI/Celery/manage.py
   - Add test suite for multi-tenancy
   - Add environment validation

2. **Short-term (Before first production release):**
   - Add comprehensive test coverage (80%+)
   - Implement Docker and deployment automation
   - Set up monitoring and error tracking
   - Create deployment documentation

3. **Ongoing:**
   - Regular security audits (dependencies, code)
   - Performance testing under load
   - Incident response procedures
   - Disaster recovery drills

---

## CONTACT & QUESTIONS

For production deployment support or clarifications on any findings, refer to Django deployment checklist: https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/
