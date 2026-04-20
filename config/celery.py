import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.local')

app = Celery('sentinel')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks(['apps.ingestion', 'apps.vulnerabilities'])

app.conf.beat_schedule = {
    'ingest-all-ecosystems': {
        'task': 'apps.ingestion.tasks.trigger_all_ecosystems',
        'schedule': crontab(
            minute=int(os.getenv('INGEST_SCHEDULE_MINUTE', '0')),
            hour=os.getenv('INGEST_SCHEDULE_HOUR', '*/6'),
        ),
    },
    'snapshot-risk-scores-hourly': {
        'task': 'apps.vulnerabilities.tasks.snapshot_risk_scores',
        'schedule': crontab(minute=int(os.getenv('SNAPSHOT_SCHEDULE_MINUTE', '5'))),
    },
}
