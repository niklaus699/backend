"""
Fires correlate_vulnerability automatically after any Vulnerability
is created or updated. Using post_save means the task runs after
the DB transaction commits — the task will always find the record.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.vulnerabilities.models import Vulnerability


@receiver(post_save, sender=Vulnerability)
def trigger_correlation_on_save(sender, instance: Vulnerability, created: bool, **kwargs):
    """
    We correlate on both create AND update because OSV sometimes
    expands the affected version range in a subsequent update —
    assets that were previously unaffected may now be affected.
    """
    # Import here to avoid circular imports
    from apps.ingestion.tasks import correlate_vulnerability

    # apply_async instead of delay gives us more control:
    # - countdown=5 gives the transaction time to fully commit
    # - queue='correlation' lets us scale correlation workers separately
    #   from ingestion workers in production
    correlate_vulnerability.apply_async(
        kwargs={"vulnerability_id": instance.id},
        countdown=5,
        queue="correlation",
    )