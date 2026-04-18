"""
Risk score calculation for a Finding.

The score is not just the CVSS base score — it's contextual.
A critical CVE on a dev-only internal tool is less urgent than
a medium CVE on your public-facing production API server.

Formula:
    risk_score = round(cvss_base * env_multiplier * asset_multiplier)
    clamped to [0, 100]

This is a simplified model. In a real product you'd add:
  - Exploit availability (EPSS score from api.first.org/epss)
  - Asset network exposure (internal vs internet-facing)
  - Time since disclosure (aging factor)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScoringContext:
    cvss_score: float | None          # 0.0 – 10.0, None if unavailable
    severity: str                     # our Severity enum value
    asset_environment: str            # 'production', 'staging', 'development'
    asset_type: str                   # 'server', 'container', 'database', 'endpoint'


# Environment multipliers — production findings matter more
_ENV_MULTIPLIER: dict[str, float] = {
    "production": 1.0,
    "staging": 0.6,
    "development": 0.3,
}

# Asset type multipliers — databases and servers are more critical
_ASSET_MULTIPLIER: dict[str, float] = {
    "database": 1.2,
    "server": 1.1,
    "endpoint": 1.0,
    "container": 0.9,
}

# Fallback CVSS scores when the feed doesn't provide one
_SEVERITY_FALLBACK_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "none": 0.0,
}


def calculate_finding_risk_score(ctx: ScoringContext) -> int:
    """
    Returns an integer risk score in [0, 100].

    Using CVSS as the base gives us a principled starting point,
    but the multipliers adjust for real-world exposure context.
    """
    base_cvss = ctx.cvss_score
    if base_cvss is None:
        base_cvss = _SEVERITY_FALLBACK_CVSS.get(ctx.severity, 0.0)

    env_mult = _ENV_MULTIPLIER.get(ctx.asset_environment, 1.0)
    asset_mult = _ASSET_MULTIPLIER.get(ctx.asset_type, 1.0)

    # Normalize CVSS (0-10) to (0-100) then apply multipliers
    raw_score = (base_cvss / 10.0) * 100 * env_mult * asset_mult

    return max(0, min(100, round(raw_score)))


def calculate_asset_risk_score(finding_scores: list[int]) -> int:
    """
    Roll up individual finding risk scores into a single asset score.

    We don't use a simple average — a single critical finding should
    dominate the asset score, not get diluted by many low findings.

    Method: max score + a small contribution from the count of high findings.
    This is similar to how CVSS environmental scoring works.
    """
    if not finding_scores:
        return 0

    max_score = max(finding_scores)
    high_count = sum(1 for s in finding_scores if s >= 70)

    # Bonus: up to 10 points for having many high-severity findings
    # log scaling so the bonus grows slowly and can't exceed 10
    import math
    count_bonus = min(10, round(math.log1p(high_count) * 4))

    return min(100, max_score + count_bonus)