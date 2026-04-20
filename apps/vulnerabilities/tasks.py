from __future__ import annotations

import logging

from celery import shared_task

from apps.assets.models import Asset
from apps.tenants.context import tenant_context
from apps.tenants.models import Organization
from apps.vulnerabilities.models import Finding, RiskSnapshot
from apps.vulnerabilities.scoring import calculate_asset_risk_score


logger = logging.getLogger(__name__)


@shared_task(name="apps.vulnerabilities.tasks.snapshot_risk_scores")
def snapshot_risk_scores():
    snapshots_created = 0

    for organization_id in Organization.objects.values_list('id', flat=True):
        with tenant_context(organization_id):
            for asset in Asset.objects.only('id'):
                open_scores = list(
                    Finding.objects
                    .filter(asset=asset, status=Finding.Status.OPEN)
                    .values_list('risk_score', flat=True)
                )

                RiskSnapshot.objects.create(
                    asset=asset,
                    risk_score=calculate_asset_risk_score(open_scores),
                    critical_count=sum(1 for score in open_scores if score >= 90),
                    high_count=sum(1 for score in open_scores if 70 <= score < 90),
                    medium_count=sum(1 for score in open_scores if 40 <= score < 70),
                )
                snapshots_created += 1

    logger.info("Created %s risk snapshots", snapshots_created)
    return {"snapshots_created": snapshots_created}
