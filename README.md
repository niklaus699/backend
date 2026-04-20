# Sentinel Backend

Sentinel is a Django + DRF backend for multi-tenant asset inventory, vulnerability correlation, and real-time risk updates over WebSockets.

## Stack

- Django 6 / DRF
- PostgreSQL with row-level security
- Celery + Redis
- Channels + Daphne

## Local setup

1. Create a `.env` from [.env.example](/home/niklaus/projects/sentinel/backend/.env.example).
2. Install dependencies with `pip install -r requirements/local.txt`.
3. Start PostgreSQL and Redis.
4. Run migrations with `DJANGO_SETTINGS_MODULE=config.settings.local ./.venv/bin/python manage.py migrate`.
5. Start the app with `DJANGO_SETTINGS_MODULE=config.settings.local ./.venv/bin/python manage.py runserver`.

## Services

- Web/API: `daphne config.asgi:application -p 8000`
- Celery ingestion worker: `celery -A config worker --queues=ingestion -l info`
- Celery correlation worker: `celery -A config worker --queues=correlation -l info`
- Celery beat: `celery -A config beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler`

## Operational notes

- Production defaults now live in `config.settings.production`.
- Tenant context is established from JWTs before request handling and is also set explicitly inside Celery tasks that touch tenant-scoped tables.
- API schema/docs are exposed at `/api/schema/` and `/api/docs/` when `drf-spectacular` is installed.
- Health checks are available at `/api/v1/health/`.
