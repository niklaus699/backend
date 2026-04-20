import logging
from datetime import datetime

import httpx
from celery import shared_task
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.assets.models import Asset, Package
from apps.tenants.context import tenant_context
from apps.tenants.models import Organization
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
TARGET_ECOSYSTEMS = ["PyPI", "npm", "Go", "Maven", "RubyGems"]


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(httpx.HTTPError,),
    name="apps.ingestion.tasks.ingest_osv_ecosystem",
)
def ingest_osv_ecosystem(self, ecosystem: str, page_token: str | None = None):
    """
    Paginated OSV ingestion for a whole ecosystem.
    """
    logger.info(f"Starting OSV ingestion for {ecosystem}, page_token={page_token!r}")

    payload = {"ecosystem": ecosystem, "page_size": 1000}
    if page_token:
        payload["page_token"] = page_token

    with httpx.Client(timeout=60) as client:
        response = client.post("https://api.osv.dev/v1/query", json=payload)
        response.raise_for_status()

    data = response.json()
    vulns = data.get("vulns", [])
    next_page_token = data.get("next_page_token")

    logger.info(f"{ecosystem}: received {len(vulns)} vulns (page_token={page_token!r})")

    if not vulns:
        logger.info(f"{ecosystem}: no vulnerabilities returned — done")
        return {"ecosystem": ecosystem, "created": 0, "updated": 0, "skipped": 0}

    incoming_ids = [v["id"] for v in vulns if "id" in v]
    existing = {
        v.id: v.modified_at
        for v in Vulnerability.objects.filter(id__in=incoming_ids).only("id", "modified_at")
    }

    to_create = []
    to_update = []
    skipped_count = 0

    for vuln_data in vulns:
        if "id" not in vuln_data:
            continue

        vuln_id = vuln_data["id"]
        osv_modified = _parse_datetime(vuln_data.get("modified"))

        if vuln_id in existing and existing[vuln_id] == osv_modified:
            skipped_count += 1
            continue

        parsed = _parse_osv_vuln(vuln_data)
        if vuln_id in existing:
            to_update.append(parsed)
        else:
            to_create.append(parsed)

    created_count = 0
    updated_count = 0

    if to_create:
        Vulnerability.objects.bulk_create(
            [Vulnerability(**v) for v in to_create],
            ignore_conflicts=True,
        )
        created_count = len(to_create)

    if to_update:
        with transaction.atomic():
            for v in to_update:
                Vulnerability.objects.filter(id=v["id"]).update(
                    **{k: val for k, val in v.items() if k != "id"}
                )
        updated_count = len(to_update)

    logger.info(
        f"{ecosystem}: created={created_count}, updated={updated_count}, skipped={skipped_count}"
    )

    if next_page_token:
        ingest_osv_ecosystem.apply_async(
            kwargs={"ecosystem": ecosystem, "page_token": next_page_token},
            queue="ingestion",
            countdown=2,
        )

    return {
        "ecosystem": ecosystem,
        "created": created_count,
        "updated": updated_count,
        "skipped": skipped_count,
    }


@shared_task
def query_package_vulnerabilities(ecosystem: str, name: str):
    """
    Query OSV for all vulnerabilities affecting a specific package.
    Called for each unique package in our database during discovery scan.
    """
    logger.info(f"Querying OSV for {ecosystem}/{name}")

    payload = {
        "package": {
            "name": name,
            "ecosystem": ecosystem,
        }
    }

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post("https://api.osv.dev/v1/query", json=payload)
            response.raise_for_status()

        data = response.json()
        vulns = data.get("vulns", [])

        if not vulns:
            logger.debug(f"No vulnerabilities found for {ecosystem}/{name}")
            return

        logger.info(f"Found {len(vulns)} vulnerabilities for {ecosystem}/{name}")

        for vuln_data in vulns:
            vuln_id = vuln_data.get("id")
            if not vuln_id:
                continue

            vuln_obj, created = Vulnerability.objects.update_or_create(
                id=vuln_id,
                defaults=_parse_osv_vuln(vuln_data)
            )

            if created:
                logger.debug(f"Created vulnerability {vuln_id}")
                correlate_vulnerability.apply_async(
                    kwargs={"vulnerability_id": vuln_id},
                    countdown=1
                )
            else:
                logger.debug(f"Updated vulnerability {vuln_id}")

    except Exception:
        logger.exception("Failed to query OSV for %s/%s", ecosystem, name)


@shared_task
def trigger_all_ecosystems():
    """
    Entry point for discovery scan: query OSV for vulnerabilities affecting
    packages already in our database (installed software).
    """
    package_specs: set[tuple[str, str]] = set()
    for organization_id in Organization.objects.values_list('id', flat=True):
        with tenant_context(organization_id):
            package_specs.update(
                Package.objects.values_list('ecosystem', 'name').distinct()
            )

    package_specs = sorted(package_specs)
    logger.info(f"Querying OSV for {len(package_specs)} unique package specs")

    for idx, (ecosystem, name) in enumerate(package_specs):
        query_package_vulnerabilities.apply_async(
            kwargs={"ecosystem": ecosystem, "name": name},
            countdown=idx * 0.1   # stagger requests
        )


def _parse_osv_vuln(data: dict) -> dict:
    """
    Normalize an OSV API response object into our Vulnerability field structure.
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
    OSV severity can live in multiple places. Normalize to our enum.
    """
    db_specific = data.get("database_specific", {})
    if "severity" in db_specific:
        sev_str = db_specific["severity"].lower()
        if sev_str in ("critical", "high", "moderate", "medium", "low"):
            return "medium" if sev_str == "moderate" else sev_str

    for sev in data.get("severity", []):
        score = sev.get("score", "")
        if score.startswith("CVSS:"):
            return "medium"

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
            # Use `pip install cvss` for full parsing; for now return None
            return None
    return None


def _parse_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


@shared_task(name="apps.ingestion.tasks.correlate_vulnerability")
def correlate_vulnerability(vulnerability_id: str):
    """
    Given a vulnerability ID, find all installed packages across all
    organizations that are affected, and create/update Finding records.
    """
    try:
        vuln = Vulnerability.objects.get(id=vulnerability_id)
    except Vulnerability.DoesNotExist:
        logger.error(f"Vulnerability {vulnerability_id} not found — skipping correlation")
        return

    logger.info(f"Correlating {vulnerability_id} ({vuln.severity})")

    affected_specs = _extract_affected_specs(vuln)
    if not affected_specs:
        logger.info(f"{vulnerability_id}: no parseable affected specs — skipping")
        return

    ecosystem_name_filter = Q()
    for ecosystem, name in affected_specs.keys():
        ecosystem_name_filter |= Q(ecosystem=ecosystem, name=name)

    findings_created = 0
    findings_updated = 0
    affected_assets_by_org: dict[str, set[str]] = {}

    for organization_id in Organization.objects.values_list('id', flat=True):
        with tenant_context(organization_id):
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

            with transaction.atomic():
                for package in candidate_packages:
                    normalized_pkg_name = _normalize_package_name(package.name, package.ecosystem)
                    key = (package.ecosystem, normalized_pkg_name)

                    if key not in affected_specs:
                        continue

                    affected_ranges = affected_specs[key]

                    if not is_version_affected(
                        installed_version=package.version,
                        affected_ranges=affected_ranges,
                        ecosystem=package.ecosystem,
                    ):
                        continue

                    ctx = ScoringContext(
                        cvss_score=vuln.cvss_score,
                        severity=vuln.severity,
                        asset_environment=package.asset.environment,
                        asset_type=package.asset.asset_type,
                    )
                    risk_score = calculate_finding_risk_score(ctx)

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

                    affected_assets_by_org.setdefault(
                        str(organization_id), set()
                    ).add(str(package.asset_id))

    logger.info(
        "%s: created=%s, updated=%s, assets affected=%s",
        vulnerability_id,
        findings_created,
        findings_updated,
        sum(len(asset_ids) for asset_ids in affected_assets_by_org.values()),
    )

    for organization_id, asset_ids in affected_assets_by_org.items():
        for asset_id in asset_ids:
            rescore_and_broadcast_asset.apply_async(
                kwargs={
                    "asset_id": asset_id,
                    "organization_id": organization_id,
                },
                countdown=1,
            )


@shared_task(name="apps.ingestion.tasks.rescore_and_broadcast_asset")
def rescore_and_broadcast_asset(asset_id: str, organization_id: str):
    """
    Recompute aggregate risk score for an asset and broadcast via WebSocket.
    """
    with tenant_context(organization_id):
        try:
            asset = Asset.objects.select_related('organization').get(id=asset_id)
        except Asset.DoesNotExist:
            return

        open_scores = list(
            Finding.objects
            .filter(asset=asset, status=Finding.Status.OPEN)
            .values_list('risk_score', flat=True)
        )

        new_risk_score = calculate_asset_risk_score(open_scores)
        critical_count = sum(1 for s in open_scores if s >= 90)
        high_count = sum(1 for s in open_scores if 70 <= s < 90)
        medium_count = sum(1 for s in open_scores if 40 <= s < 70)

        Asset.objects.filter(id=asset_id).update(risk_score=new_risk_score)

        RiskSnapshot.objects.create(
            asset=asset,
            risk_score=new_risk_score,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
        )

        _broadcast_asset_update(asset, new_risk_score, critical_count, high_count)


def _broadcast_asset_update(asset: Asset, risk_score: int, critical: int, high: int):
    """Send WebSocket message to the organization's channel group."""
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync

        channel_layer = get_channel_layer()
        group_name = f"org_{asset.organization_id}"

        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "asset.risk_updated",
                "asset_id": str(asset.id),
                "asset_name": asset.name,
                "risk_score": risk_score,
                "critical_count": critical,
                "high_count": high,
                "timestamp": timezone.now().isoformat(),
            },
        )
    except Exception as e:
        logger.warning(f"WebSocket broadcast failed for asset {asset.id}: {e}")


def _extract_affected_specs(vuln: Vulnerability) -> dict[tuple[str, str], list]:
    """
    Parse vuln.affected_ranges JSON into a lookup dict:
    { (ecosystem, normalized_package_name): [AffectedRange, ...] }
    """
    specs = {}
    for affected_entry in vuln.affected_ranges:
        pkg_info = affected_entry.get("package", {})
        ecosystem = pkg_info.get("ecosystem", "")
        name = pkg_info.get("name", "")

        if not ecosystem or not name:
            continue

        name = _normalize_package_name(name, ecosystem)
        parsed_ranges = parse_osv_ranges(affected_entry)
        if parsed_ranges:
            specs[(ecosystem, name)] = parsed_ranges

    return specs


def _normalize_package_name(name: str, ecosystem: str) -> str:
    """
    Ecosystem-specific package name normalization.
    """
    if ecosystem == "PyPI":
        return name.lower().replace("-", "_").replace(".", "_")
    if ecosystem == "npm":
        return name.lower()
    return name


@shared_task(name="apps.ingestion.tasks.correlate_new_packages")
def correlate_new_packages_for_asset(asset_id: str):
    try:
        asset = Asset.objects.prefetch_related('packages').get(id=asset_id)
    except Asset.DoesNotExist:
        return

    packages = list(asset.packages.all())
    if not packages:
        return

    logger.info(f"Correlating {len(packages)} packages for asset {asset.name}")

    findings_created = 0

    for pkg in packages:
        norm_name = _normalize_package_name(pkg.name, pkg.ecosystem)

        # Step 1 — fetch vulnerabilities for this specific package from OSV
        try:
            with httpx.Client(timeout=30) as client:
                response = client.post(
                    "https://api.osv.dev/v1/query",
                    json={"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}}
                )
                response.raise_for_status()
            osv_vulns = response.json().get("vulns", [])
        except Exception as e:
            logger.warning(f"OSV query failed for {pkg.ecosystem}/{pkg.name}: {e}")
            continue

        if not osv_vulns:
            continue

        # Step 2 — upsert each vulnerability into our DB
        for vuln_data in osv_vulns:
            if "id" not in vuln_data:
                continue
            vuln, _ = Vulnerability.objects.update_or_create(
                id=vuln_data["id"],
                defaults=_parse_osv_vuln(vuln_data)
            )

            # Step 3 — check if this specific installed version is affected
            affected_specs = _extract_affected_specs(vuln)
            key = (pkg.ecosystem, norm_name)

            if key not in affected_specs:
                continue

            if not is_version_affected(pkg.version, affected_specs[key], pkg.ecosystem):
                continue

            # Step 4 — create the finding
            ctx = ScoringContext(
                cvss_score=vuln.cvss_score,
                severity=vuln.severity,
                asset_environment=asset.environment,
                asset_type=asset.asset_type,
            )
            _, created = Finding.objects.update_or_create(
                asset=asset,
                vulnerability=vuln,
                package=pkg,
                defaults={
                    "status": Finding.Status.OPEN,
                    "risk_score": calculate_finding_risk_score(ctx),
                },
            )
            if created:
                findings_created += 1
                logger.info(f"Finding created: {vuln.id} affects {pkg.name}@{pkg.version} on {asset.name}")

    logger.info(f"Asset {asset.name}: {findings_created} new findings")
    rescore_and_broadcast_asset.apply_async(
        kwargs={
            "asset_id": str(asset.id),
            "organization_id": str(asset.organization_id),
        },
        countdown=1,
    )