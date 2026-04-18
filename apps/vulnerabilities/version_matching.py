"""
Version range matching against the OSV vulnerability schema.

OSV 'affected[].ranges' can contain multiple range types:
  - ECOSYSTEM: version strings interpreted by the ecosystem's native tooling
  - SEMVER:    strict semantic versioning
  - GIT:       commit SHAs (we skip these — no git history in our model)

Reference: https://ossf.github.io/osv-schema/#affectedranges-field

We use the 'packaging' library for version parsing because it handles
the messy reality of PyPI versions (post-releases, epochs, dev versions).
For npm/semver ranges, we use 'semantic_version'. Both are battle-tested
and used by pip and npm themselves internally.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class RangeType(str, Enum):
    ECOSYSTEM = "ECOSYSTEM"
    SEMVER = "SEMVER"
    GIT = "GIT"


@dataclass
class VersionEvent:
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


@dataclass
class AffectedRange:
    range_type: RangeType
    events: list[VersionEvent] = field(default_factory=list)


def parse_osv_ranges(affected_entry: dict[str, Any]) -> list[AffectedRange]:
    """
    Parse a single entry from an OSV 'affected' array into structured ranges.

    OSV structure:
    {
      "package": {"ecosystem": "PyPI", "name": "requests"},
      "ranges": [
        {
          "type": "ECOSYSTEM",
          "events": [
            {"introduced": "0"},       <- vulnerable from this version
            {"fixed": "2.32.0"}        <- fixed at (exclusive upper bound)
          ]
        }
      ]
    }
    """
    ranges = []
    for raw_range in affected_entry.get("ranges", []):
        try:
            range_type = RangeType(raw_range.get("type", ""))
        except ValueError:
            continue  # Unknown type — skip silently

        if range_type == RangeType.GIT:
            continue  # We can't correlate commit SHAs to installed packages

        events = []
        for event in raw_range.get("events", []):
            events.append(VersionEvent(
                introduced=event.get("introduced"),
                fixed=event.get("fixed"),
                last_affected=event.get("last_affected"),
            ))

        ranges.append(AffectedRange(range_type=range_type, events=events))

    return ranges


def is_version_affected(
    installed_version: str,
    affected_ranges: list[AffectedRange],
    ecosystem: str,
) -> bool:
    """
    Returns True if installed_version falls within any of the affected ranges.

    We check all ranges with OR logic — if any range matches, the package
    is affected. Within a single range, events are processed in order:
    'introduced' opens a vulnerable window, 'fixed' closes it.
    """
    for version_range in affected_ranges:
        if _check_single_range(installed_version, version_range, ecosystem):
            return True
    return False


def _check_single_range(
    installed_version: str,
    version_range: AffectedRange,
    ecosystem: str,
) -> bool:
    """
    Process events sequentially. The OSV spec guarantees they are ordered.
    A version is affected if it falls in an open [introduced, fixed) window.
    """
    if version_range.range_type == RangeType.SEMVER:
        return _check_semver_range(installed_version, version_range.events)

    # ECOSYSTEM type — use ecosystem-appropriate parser
    return _check_ecosystem_range(installed_version, version_range.events, ecosystem)


def _check_semver_range(installed: str, events: list[VersionEvent]) -> bool:
    """
    Pure semver comparison using the 'semantic_version' library.
    Handles npm, Go, and other strict semver ecosystems.
    """
    try:
        import semantic_version
        installed_v = semantic_version.Version.coerce(installed)
    except (ValueError, TypeError):
        logger.debug(f"Could not parse semver: {installed!r}")
        return False

    return _evaluate_events(
        installed_v,
        events,
        parse_fn=lambda s: semantic_version.Version.coerce(s) if s and s != "0" else None,
    )


def _check_ecosystem_range(
    installed: str,
    events: list[VersionEvent],
    ecosystem: str,
) -> bool:
    """
    Use the 'packaging' library for Python-style version parsing.
    This handles PEP 440 versions used by PyPI, and works reasonably
    well for Maven and RubyGems versions too.
    """
    try:
        from packaging.version import Version, InvalidVersion
        installed_v = Version(installed)
    except Exception:
        logger.debug(f"Could not parse version {installed!r} for ecosystem {ecosystem}")
        return False

    def safe_parse(v_str: str | None):
        if not v_str or v_str == "0":
            return None
        try:
            from packaging.version import Version
            return Version(v_str)
        except Exception:
            return None

    return _evaluate_events(installed_v, events, parse_fn=safe_parse)


def _evaluate_events(installed_v, events: list[VersionEvent], parse_fn) -> bool:
    """
    Walk the event list and determine if installed_v is in a vulnerable window.

    OSV event semantics:
      introduced: "0" means "from the very beginning"
      fixed:      exclusive upper bound — fixed version itself is NOT affected
      last_affected: inclusive upper bound (use when no fix exists)

    State machine: we start "not vulnerable", flip to vulnerable at 'introduced',
    flip back at 'fixed' or 'last_affected'.
    """
    vulnerable = False

    for event in events:
        if event.introduced is not None:
            introduced_v = parse_fn(event.introduced)
            if introduced_v is None:
                # "0" parsed to None means "from the beginning"
                vulnerable = True
            elif installed_v >= introduced_v:
                vulnerable = True
            else:
                vulnerable = False

        if event.fixed is not None and vulnerable:
            fixed_v = parse_fn(event.fixed)
            if fixed_v and installed_v >= fixed_v:
                vulnerable = False  # installed is at or beyond the fix

        if event.last_affected is not None and vulnerable:
            last_v = parse_fn(event.last_affected)
            if last_v and installed_v > last_v:
                vulnerable = False  # installed is beyond the last affected version

    return vulnerable