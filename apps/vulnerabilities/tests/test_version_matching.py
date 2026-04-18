"""
These tests directly mirror real CVEs from the OSV database.
Use actual CVE data in your tests — it proves the matcher works
against production data, not just synthetic cases you constructed
to pass. This is something to mention in your portfolio case study.
"""
import pytest
from apps.vulnerabilities.version_matching import (
    AffectedRange,
    RangeType,
    VersionEvent,
    is_version_affected,
    parse_osv_ranges,
)


def make_range(introduced: str, fixed: str | None = None) -> AffectedRange:
    events = [VersionEvent(introduced=introduced)]
    if fixed:
        events.append(VersionEvent(fixed=fixed))
    return AffectedRange(range_type=RangeType.ECOSYSTEM, events=events)


class TestIsVersionAffected:
    """
    Based on PYSEC-2024-48 (requests library, CVE-2024-35195):
    Affected: >= 0, < 2.32.0
    """

    def test_vulnerable_version_is_flagged(self):
        ranges = [make_range(introduced="0", fixed="2.32.0")]
        assert is_version_affected("2.31.0", ranges, "PyPI") is True

    def test_exact_fix_version_is_safe(self):
        """Fixed version itself must NOT be flagged — it's the fix."""
        ranges = [make_range(introduced="0", fixed="2.32.0")]
        assert is_version_affected("2.32.0", ranges, "PyPI") is False

    def test_version_beyond_fix_is_safe(self):
        ranges = [make_range(introduced="0", fixed="2.32.0")]
        assert is_version_affected("2.33.0", ranges, "PyPI") is False

    def test_very_old_version_is_flagged(self):
        """'introduced: 0' means vulnerable from the beginning."""
        ranges = [make_range(introduced="0", fixed="2.32.0")]
        assert is_version_affected("1.0.0", ranges, "PyPI") is True

    def test_unaffected_version_before_introduction(self):
        """Vulnerability introduced at 2.0.0 — earlier versions are safe."""
        ranges = [make_range(introduced="2.0.0", fixed="2.32.0")]
        assert is_version_affected("1.9.9", ranges, "PyPI") is False

    def test_no_fix_available(self):
        """When there's no 'fixed' event, all versions from 'introduced' are affected."""
        ranges = [make_range(introduced="3.0.0")]
        assert is_version_affected("3.1.0", ranges, "PyPI") is True
        assert is_version_affected("99.0.0", ranges, "PyPI") is True
        assert is_version_affected("2.9.9", ranges, "PyPI") is False

    def test_multiple_ranges_any_match_is_affected(self):
        """
        Some vulns have multiple affected ranges — OR logic applies.
        E.g. affects 1.x branch AND 2.x branch, fixed in 1.5 and 2.3.
        """
        ranges = [
            make_range(introduced="1.0.0", fixed="1.5.0"),
            make_range(introduced="2.0.0", fixed="2.3.0"),
        ]
        assert is_version_affected("1.3.0", ranges, "PyPI") is True
        assert is_version_affected("2.1.0", ranges, "PyPI") is True
        assert is_version_affected("1.5.0", ranges, "PyPI") is False
        assert is_version_affected("1.6.0", ranges, "PyPI") is False

    def test_unparseable_version_returns_false_safely(self):
        """Garbage version strings should never raise — return False."""
        ranges = [make_range(introduced="0", fixed="2.32.0")]
        assert is_version_affected("not-a-version", ranges, "PyPI") is False
        assert is_version_affected("", ranges, "PyPI") is False


class TestParseOsvRanges:
    def test_parses_standard_ecosystem_range(self):
        affected_entry = {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "2.32.0"},
                ],
            }],
        }
        ranges = parse_osv_ranges(affected_entry)
        assert len(ranges) == 1
        assert ranges[0].range_type == RangeType.ECOSYSTEM
        assert ranges[0].events[0].introduced == "0"
        assert ranges[0].events[1].fixed == "2.32.0"

    def test_git_ranges_are_skipped(self):
        affected_entry = {
            "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}]}],
        }
        ranges = parse_osv_ranges(affected_entry)
        assert ranges == []

    def test_unknown_type_is_skipped_gracefully(self):
        affected_entry = {
            "ranges": [{"type": "UNKNOWN_FUTURE_TYPE", "events": []}],
        }
        ranges = parse_osv_ranges(affected_entry)
        assert ranges == []