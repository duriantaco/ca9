from __future__ import annotations

from ca9.models import VersionRange
from ca9.version import check_version, is_version_affected


class TestIsVersionAffected:
    def test_within_range(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("1.3", ranges) is True

    def test_at_introduced(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("1.0", ranges) is True

    def test_at_fixed(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("1.5", ranges) is False

    def test_after_fixed(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("2.0", ranges) is False

    def test_before_introduced(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.5"),)
        assert is_version_affected("0.9", ranges) is False

    def test_multiple_ranges(self):
        ranges = (
            VersionRange(introduced="1.0", fixed="1.5"),
            VersionRange(introduced="2.0", fixed="2.3"),
        )
        assert is_version_affected("1.2", ranges) is True
        assert is_version_affected("1.7", ranges) is False
        assert is_version_affected("2.1", ranges) is True
        assert is_version_affected("2.5", ranges) is False

    def test_last_affected(self):
        ranges = (VersionRange(introduced="1.0", last_affected="1.5"),)
        assert is_version_affected("1.5", ranges) is True
        assert is_version_affected("1.6", ranges) is False

    def test_no_upper_bound(self):
        ranges = (VersionRange(introduced="1.0"),)
        assert is_version_affected("1.0", ranges) is True
        assert is_version_affected("99.0", ranges) is True
        assert is_version_affected("0.5", ranges) is False

    def test_empty_ranges(self):
        assert is_version_affected("1.0", ()) is None

    def test_no_introduced(self):
        ranges = (VersionRange(fixed="1.5"),)
        assert is_version_affected("1.0", ranges) is None

    def test_three_part_versions(self):
        ranges = (VersionRange(introduced="2.1.0", fixed="2.1.2"),)
        assert is_version_affected("2.1.1", ranges) is True
        assert is_version_affected("2.1.2", ranges) is False
        assert is_version_affected("2.0.9", ranges) is False

    def test_zero_introduced(self):
        ranges = (VersionRange(introduced="0", fixed="1.5"),)
        assert is_version_affected("0.1", ranges) is True
        assert is_version_affected("1.5", ranges) is False


class TestPEP440:
    def test_pre_release_less_than_release(self):
        ranges = (VersionRange(introduced="0.9", fixed="1.0"),)
        assert is_version_affected("1.0rc1", ranges) is True
        assert is_version_affected("1.0", ranges) is False

    def test_dev_release_less_than_release(self):
        ranges = (VersionRange(introduced="0.9", fixed="1.0"),)
        assert is_version_affected("1.0.dev1", ranges) is True

    def test_post_release_greater_than_release(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.1"),)
        assert is_version_affected("1.0.post1", ranges) is True

    def test_epoch_overrides_version(self):
        ranges = (VersionRange(introduced="0", fixed="3.0"),)
        assert is_version_affected("1!1.0", ranges) is False

    def test_alpha_beta_ordering(self):
        ranges = (VersionRange(introduced="1.0a1", fixed="1.0"),)
        assert is_version_affected("1.0a2", ranges) is True
        assert is_version_affected("1.0b1", ranges) is True
        assert is_version_affected("1.0rc1", ranges) is True
        assert is_version_affected("1.0", ranges) is False

    def test_exact_boundary_at_fixed(self):
        ranges = (VersionRange(introduced="2.0.0", fixed="2.31.0"),)
        assert is_version_affected("2.30.0", ranges) is True
        assert is_version_affected("2.31.0", ranges) is False
        assert is_version_affected("2.31.1", ranges) is False

    def test_invalid_version_returns_none(self):
        ranges = (VersionRange(introduced="1.0", fixed="2.0"),)
        assert is_version_affected("not-a-version!!!", ranges) is None

    def test_invalid_introduced_skipped(self):
        ranges = (VersionRange(introduced="???", fixed="2.0"),)
        assert is_version_affected("1.5", ranges) is None

    def test_local_version(self):
        ranges = (VersionRange(introduced="1.0", fixed="1.1"),)
        assert is_version_affected("1.0+local", ranges) is True


class TestCheckVersion:
    def test_returns_matched_range(self):
        r = VersionRange(introduced="1.0", fixed="2.0")
        result = check_version("1.5", (r,))
        assert result.affected is True
        assert result.matched_range is r
        assert result.installed is not None
        assert str(result.installed) == "1.5"

    def test_returns_not_affected(self):
        r = VersionRange(introduced="1.0", fixed="2.0")
        result = check_version("2.5", (r,))
        assert result.affected is False
        assert result.matched_range is None

    def test_invalid_version_has_error(self):
        r = VersionRange(introduced="1.0", fixed="2.0")
        result = check_version("garbage!!!", (r,))
        assert result.affected is None
        assert result.installed is None
        assert result.error is not None
        assert "garbage" in result.error

    def test_empty_ranges(self):
        result = check_version("1.0", ())
        assert result.affected is None
        assert result.installed is not None
