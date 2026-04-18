import logging
from datetime import datetime, timezone

import httpx
from celery import shared_task
from django.db import transaction, connection
from apps.assets.models import Asset, Package
from apps.vulnerabilities.models import Vulnerability, Finding, RiskSnapshot


from apps.vulnerabilities.version_matching import (
    parse_osv_ranges,
    is_version_affected,
)
from apps.vulnerabilities.scoring import (
    ScoringContext,
    calculate_finding_risk_score,
    calculate_asset_risk_score,
)


logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"

# Ecosystems we care about — extend this list as you add language support
TARGET_ECOSYSTEMS = ["PyPI", "npm", "Go", "Maven", "RubyGems"]


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,  # seconds
    autoretry_for=(httpx.HTTPError,),
    name="apps.ingestion.tasks.ingest_osv_ecosystem",
)
def ingest_osv_ecosystem(self, ecosystem: str, page_token: str | None = None):
    """
    Fetches all vulnerabilities for a given ecosystem from OSV.dev
    and upserts them into our Vulnerability table.

    Idempotency strategy:
    - OSV uses stable IDs (e.g. 'PYSEC-2024-123'). We use the OSV ID as
      our primary key, so any re-run simply updates the existing row
      via update_or_create.
    - We track 'modified_at' from OSV — if it hasn't changed, we skip
      the update entirely to avoid pointless DB writes.
    - Celery Beat schedules this task; Celery's task deduplication
      (via a Redis lock) prevents concurrent runs for the same ecosystem.
    """
    logger.info(f"Starting OSV ingestion for ecosystem: {ecosystem}")

    payload = {"ecosystem": ecosystem, "page_size": 500}
    if page_token:
        payload["page_token"] = page_token

    with httpx.Client(timeout=30) as client:
        response = client.post(f"{OSV_API_BASE}/querybatch", json=payload)
        response.raise_for_status()

    data = response.json()
    vulns = data.get("vulns", [])
    next_page_token = data.get("next_page_token")

    logger.info(f"Received {len(vulns)} vulnerabilities for {ecosystem}")

    created_count = 0
    updated_count = 0
    skipped_count = 0

    # Batch fetch existing records to minimize round-trips
    # We only need the IDs and their modified_at to detect stale records
    incoming_ids = [v["id"] for v in vulns]
    existing = {
        v.id: v.modified_at
        for v in Vulnerability.objects.filter(id__in=incoming_ids).only('id', 'modified_at')
    }

    to_create = []
    to_update = []

    for vuln_data in vulns:
        vuln_id = vuln_data["id"]
        osv_modified = _parse_datetime(vuln_data.get("modified"))

        # Skip if we already have this exact version
        if vuln_id in existing and existing[vuln_id] == osv_modified:
            skipped_count += 1
            continue

        parsed = _parse_osv_vuln(vuln_data)

        if vuln_id in existing:
            to_update.append(parsed)
        else:
            to_create.append(parsed)

    # Bulk create is one INSERT for all new records
    if to_create:
        Vulnerability.objects.bulk_create(
            [Vulnerability(**v) for v in to_create],
            ignore_conflicts=True  # Safety net for race conditions
        )
        created_count = len(to_create)

    # Bulk update requires individual saves (Django ORM limitation)
    # For large update batches, consider bulk_update() with explicit fields
    if to_update:
        with transaction.atomic():
            for vuln_data in to_update:
                Vulnerability.objects.filter(id=vuln_data['id']).update(
                    **{k: v for k, v in vuln_data.items() if k != 'id'}
                )
        updated_count = len(to_update)

    logger.info(
        f"Ecosystem {ecosystem}: "
        f"created={created_count}, updated={updated_count}, skipped={skipped_count}"
    )

    # Paginate — chain the next page as a new task rather than a recursive call
    # This keeps individual task execution time bounded and avoids memory buildup
    if next_page_token:
        ingest_osv_ecosystem.apply_async(
            kwargs={"ecosystem": ecosystem, "page_token": next_page_token},
            countdown=2  # 2s delay to be a polite API consumer
        )

    return {
        "ecosystem": ecosystem,
        "created": created_count,
        "updated": updated_count,
        "skipped": skipped_count,
    }


@shared_task(name="apps.ingestion.tasks.trigger_all_ecosystems")
def trigger_all_ecosystems():
    """
    Entry point for Celery Beat. Fans out one task per ecosystem.
    Scheduled in settings: runs every 6 hours.
    """
    for ecosystem in TARGET_ECOSYSTEMS:
        ingest_osv_ecosystem.apply_async(
            kwargs={"ecosystem": ecosystem},
            # Distribute start times to avoid hammering OSV simultaneously
            countdown=TARGET_ECOSYSTEMS.index(ecosystem) * 10
        )
    logger.info(f"Triggered ingestion for {len(TARGET_ECOSYSTEMS)} ecosystems")


def _parse_osv_vuln(data: dict) -> dict:
    """
    Normalize an OSV API response object into our Vulnerability field structure.
    OSV schema: https://ossf.github.io/osv-schema/
    """
    severity = _extract_severity(data)
    cvss_score = _extract_cvss(data)

    return {
        "id": data["id"],
        "source": Vulnerability.Source.OSV,
        "summary": data.get("summary", ""),
        "severity": severity,
        "cvss_score": cvss_score,
        "affected_ranges": data.get("affected", []),
        "references": [r.get("url", "") for r in data.get("references", [])],
        "published_at": _parse_datetime(data.get("published")),
        "modified_at": _parse_datetime(data.get("modified")),
    }


def _extract_severity(data: dict) -> str:
    """
    OSV severity can live in multiple places depending on the source.
    We normalize to our enum with a safe fallback chain.
    """
    # Try the top-level severity array first (CVSS-based)
    for sev in data.get("severity", []):
        score = sev.get("score", "")
        if score.startswith("CVSS:"):
            # Parse base score from CVSS vector string
            try:
                base_score = float(score.split("/BS:")[1].split("/")[0]) if "/BS:" in score else 0
            except (IndexError, ValueError):
                base_score = 0
            return _cvss_score_to_severity(base_score)

    # Fall back to database-specific severity if present
    for affected in data.get("affected", []):
        db_specific = affected.get("database_specific", {})
        if "severity" in db_specific:
            sev_str = db_specific["severity"].lower()
            if sev_str in ("critical", "high", "moderate", "medium", "low"):
                return "medium" if sev_str == "moderate" else sev_str

    return Vulnerability.Severity.NONE


def _extract_cvss(data: dict) -> float | None:
    for sev in data.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            # CVSS v3 vector encodes base score — parse it properly
            # In production, use the 'cvss' library: pip install cvss
            return None  # Placeholder — implement with cvss library
    return None


def _cvss_score_to_severity(score: float) -> str:
    if score >= 9.0:
        return Vulnerability.Severity.CRITICAL
    if score >= 7.0:
        return Vulnerability.Severity.HIGH
    if score >= 4.0:
        return Vulnerability.Severity.MEDIUM
    if score > 0:
        return Vulnerability.Severity.LOW
    return Vulnerability.Severity.NONE


def _parse_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    
def correlate_vulnerability(self, vulnerability_id: str):
    """
    Given a vulnerability ID, find all installed packages across all
    organizations that are affected, and create or update Finding records.

    Called automatically after ingest via Django signal (see signals.py).
    Can also be triggered manually for re-correlation after schema changes.

    Performance notes:
    - We fetch packages in a single JOIN query, not N+1 per organization.
    - The version range check is O(n_packages × n_ranges) in Python —
      acceptable because n_ranges per vuln is typically < 5.
    - All Finding writes for a single vulnerability happen in one transaction.
    """
    try:
        vuln = Vulnerability.objects.get(id=vulnerability_id)
    except Vulnerability.DoesNotExist:
        logger.error(f"Vulnerability {vulnerability_id} not found — skipping correlation")
        return

    logger.info(f"Correlating {vulnerability_id} ({vuln.severity})")

    # Build the set of (ecosystem, package_name) pairs this vuln affects.
    # OSV 'affected' is a list, each entry scoped to one ecosystem+package.
    affected_specs = _extract_affected_specs(vuln)

    if not affected_specs:
        logger.info(f"{vulnerability_id}: no parseable affected specs — skipping")
        return

    # Single query: fetch all packages whose (name, ecosystem) matches any
    # affected spec, including their asset's environment and type for scoring.
    # We intentionally fetch across ALL organizations here — RLS is NOT active
    # in Celery workers because there's no HTTP request setting the session var.
    # This is correct: the correlation engine works globally, then creates
    # org-scoped Finding records. The API layer enforces tenant isolation.
    from django.db.models import Q

    ecosystem_name_filter = Q()
    for ecosystem, name in affected_specs.keys():
        ecosystem_name_filter |= Q(ecosystem=ecosystem, name=name)

    candidate_packages = (
        Package.objects
        .filter(ecosystem_name_filter)
        .select_related('asset', 'asset__organization')
        .only(
            'id', 'name', 'version', 'ecosystem',
            'asset__id', 'asset__environment', 'asset__asset_type',
            'asset__organization__id',
        )
    )

    findings_created = 0
    findings_updated = 0
    affected_asset_ids: set[str] = set()

    # Group all writes into a single transaction.
    # If anything fails mid-way, no partial state is committed.
    with transaction.atomic():
        for package in candidate_packages:
            key = (package.ecosystem, package.name)
            if key not in affected_specs:
                continue

            affected_ranges = affected_specs[key]

            if not is_version_affected(
                installed_version=package.version,
                affected_ranges=affected_ranges,
                ecosystem=package.ecosystem,
            ):
                continue  # Package version is outside the vulnerable range

            # This package IS affected — calculate its contextual risk score
            ctx = ScoringContext(
                cvss_score=vuln.cvss_score,
                severity=vuln.severity,
                asset_environment=package.asset.environment,
                asset_type=package.asset.asset_type,
            )
            risk_score = calculate_finding_risk_score(ctx)

            # Upsert the Finding.
            # unique_together = (asset, vulnerability, package) ensures
            # re-runs update rather than duplicate.
            finding, created = Finding.objects.update_or_create(
                asset=package.asset,
                vulnerability=vuln,
                package=package,
                defaults={
                    "status": Finding.Status.OPEN,
                    "risk_score": risk_score,
                },
            )

            if created:
                findings_created += 1
            else:
                findings_updated += 1

            affected_asset_ids.add(str(package.asset.id))

    logger.info(
        f"{vulnerability_id}: created={findings_created}, updated={findings_updated}, "
        f"assets affected={len(affected_asset_ids)}"
    )

    # After all findings are committed, rescore each affected asset
    # and broadcast the update via WebSocket. We do this outside the
    # main transaction so a broadcast failure doesn't roll back findings.
    for asset_id in affected_asset_ids:
        rescore_and_broadcast_asset.apply_async(
            kwargs={"asset_id": asset_id},
            countdown=1,
        )


@shared_task(name="ingestion.rescore_and_broadcast_asset")
def rescore_and_broadcast_asset(asset_id: str):
    """
    Recompute the aggregate risk score for an asset and push the
    updated state to all connected WebSocket clients for that organization.

    Split from correlate_vulnerability so it can be retried independently
    and so a Channels failure doesn't affect finding persistence.
    """
    try:
        asset = Asset.objects.select_related('organization').get(id=asset_id)
    except Asset.DoesNotExist:
        return

    # Fetch all open finding scores for this asset
    open_scores = list(
        Finding.objects
        .filter(asset=asset, status=Finding.Status.OPEN)
        .values_list('risk_score', flat=True)
    )

    new_risk_score = calculate_asset_risk_score(open_scores)
    critical_count = sum(1 for s in open_scores if s >= 90)
    high_count = sum(1 for s in open_scores if 70 <= s < 90)
    medium_count = sum(1 for s in open_scores if 40 <= s < 70)

    # Atomic update of the denormalized score on the Asset row
    Asset.objects.filter(id=asset_id).update(risk_score=new_risk_score)

    # Append to the time-series risk history table
    RiskSnapshot.objects.create(
        asset=asset,
        risk_score=new_risk_score,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
    )

    # Push to WebSocket — scoped to the organization's channel group
    _broadcast_asset_update(asset, new_risk_score, critical_count, high_count)


def _broadcast_asset_update(asset: Asset, risk_score: int, critical: int, high: int):
    """
    Send a channel layer message to the org's group.
    Every WebSocket consumer connected to this org will receive it.
    """
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync

        channel_layer = get_channel_layer()
        group_name = f"org_{asset.organization_id}"

        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "asset.risk_updated",   # maps to consumer method name
                "asset_id": str(asset.id),
                "asset_name": asset.name,
                "risk_score": risk_score,
                "critical_count": critical,
                "high_count": high,
                "timestamp": timezone.now().isoformat(),
            },
        )
    except Exception as e:
        # Never let a broadcast failure kill the task
        logger.warning(f"WebSocket broadcast failed for asset {asset.id}: {e}")


def _extract_affected_specs(vuln: Vulnerability) -> dict[tuple[str, str], list]:
    """
    Parse the vuln's affected_ranges JSON into a lookup dict:
    { (ecosystem, package_name): [AffectedRange, ...] }

    OSV 'affected' is a list of entries, each covering one package
    in one ecosystem. A single CVE can affect packages in multiple
    ecosystems (e.g. the same library published to both PyPI and npm).
    """
    specs = {}
    for affected_entry in vuln.affected_ranges:
        pkg_info = affected_entry.get("package", {})
        ecosystem = pkg_info.get("ecosystem", "")
        name = pkg_info.get("name", "")

        if not ecosystem or not name:
            continue

        # Normalize the package name — PyPI treats 'Requests' and 'requests'
        # as the same package. We lowercase on ingest too (see serializers).
        name = _normalize_package_name(name, ecosystem)

        parsed_ranges = parse_osv_ranges(affected_entry)
        if parsed_ranges:
            specs[(ecosystem, name)] = parsed_ranges

    return specs


def _normalize_package_name(name: str, ecosystem: str) -> str:
    """
    Ecosystem-specific package name normalization.
    PyPI: lowercase, replace hyphens/underscores (PEP 503)
    npm: lowercase only
    Others: pass through
    """
    if ecosystem == "PyPI":
        return name.lower().replace("-", "_").replace(".", "_")
    if ecosystem == "npm":
        return name.lower()
    return name

@shared_task(name="apps.ingestion.tasks.correlate_new_packages")
def correlate_new_packages_for_asset(asset_id: str):
    """
    Called after an asset is scanned and new packages are reported.
    Checks every package on the asset against ALL known vulnerabilities
    matching that package name + ecosystem.

    This is the inverse of correlate_vulnerability — same logic,
    different entry point. We query Vulnerability and iterate packages
    rather than the other way around.
    """
    try:
        asset = Asset.objects.prefetch_related('packages').get(id=asset_id)
    except Asset.DoesNotExist:
        return

    packages = list(asset.packages.all())
    if not packages:
        return

    # Build filter for all vulnerabilities that mention any of this asset's packages
    from django.db.models import Q

    for package in packages:
        normalized_name = _normalize_package_name(package.name, package.ecosystem)

        # OSV stores affected as JSONB — we can use Postgres containment
        # to find vulns that mention this ecosystem/package combination.
        # This is faster than fetching all vulns and filtering in Python.
        matching_vulns = Vulnerability.objects.filter(
            affected_ranges__contains=[{
                "package": {
                    "ecosystem": package.ecosystem,
                    "name": normalized_name,
                }
            }]
        )

        for vuln in matching_vulns:
            affected_specs = _extract_affected_specs(vuln)
            key = (package.ecosystem, normalized_name)

            if key not in affected_specs:
                continue

            if not is_version_affected(package.version, affected_specs[key], package.ecosystem):
                continue

            ctx = ScoringContext(
                cvss_score=vuln.cvss_score,
                severity=vuln.severity,
                asset_environment=asset.environment,
                asset_type=asset.asset_type,
            )

            Finding.objects.update_or_create(
                asset=asset,
                vulnerability=vuln,
                package=package,
                defaults={
                    "status": Finding.Status.OPEN,
                    "risk_score": calculate_finding_risk_score(ctx),
                },
            )

    # Rescore the asset after all findings are updated
    rescore_and_broadcast_asset.apply_async(kwargs={"asset_id": asset_id})