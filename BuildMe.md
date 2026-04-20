# Check if it's running
sudo systemctl status postgresql

# If it's "inactive" or "failed", start it
sudo systemctl start postgresql

# (Optional) Enable it so it starts automatically on boot
sudo systemctl enable postgresql


# Terminal 1 — Django dev server (HTTP + WebSocket via Daphne)
source .venv/bin/activate
cd backend
python manage.py migrate
python manage.py runserver  # or: daphne config.asgi:application -p 8000

# Terminal 2 — Celery worker: ingestion queue
source .venv/bin/activate
celery -A config worker \
  --queues=ingestion \
  --concurrency=2 \
  --loglevel=info \
  --hostname=ingestion@%h

# Terminal 3 — Celery worker: correlation queue (separate pool)
source .venv/bin/activate
celery -A config worker \
  --queues=correlation \
  --concurrency=4 \
  --loglevel=info \
  --hostname=correlation@%h

# Terminal 4 — Celery Beat scheduler
source .venv/bin/activate
celery -A config beat \
  --loglevel=info \
  --scheduler django_celery_beat.schedulers:DatabaseScheduler

# Trigger a manual ingestion run to populate data immediately
python manage.py shell -c "
from apps.ingestion.tasks import ingest_osv_ecosystem
ingest_osv_ecosystem.apply_async(kwargs={'ecosystem': 'PyPI'})
"