import pytest
@pytest.mark.parametrize("task_path, expected_queue", [
    ('apps.ingestion.tasks.ingest_osv_ecosystem', 'ingestion'),
    ('apps.ingestion.tasks.correlate_vulnerability', 'correlation'),
])
def test_celery_task_routing(task_path, expected_queue):
    """
    Ensures tasks are assigned to the correct Redis queue based on base.py logic.
    """
    from django.conf import settings
    routes = settings.CELERY_TASK_ROUTES
    
    assert task_path in routes
    assert routes[task_path]['queue'] == expected_queue