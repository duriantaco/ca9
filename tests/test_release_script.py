from __future__ import annotations

import pytest
from scripts.bump_version import extract_changelog_section, validate_version


def test_validate_version_accepts_semver():
    assert validate_version("0.2.0") == "0.2.0"
    assert validate_version("1.0.0-rc.1") == "1.0.0-rc.1"


def test_validate_version_rejects_non_semver():
    with pytest.raises(ValueError):
        validate_version("v0.2.0")

    with pytest.raises(ValueError):
        validate_version("0.2")


def test_extract_changelog_section_for_version():
    changelog = """# Changelog

## [0.2.0] - 2026-04-26

### Added

- Release automation.

## [0.1.4] - 2026-03-08

### Fixed

- Previous fix.
"""

    notes = extract_changelog_section("0.2.0", changelog)

    assert "Release automation" in notes
    assert "Previous fix" not in notes


def test_extract_changelog_section_requires_target_version():
    with pytest.raises(ValueError):
        extract_changelog_section("0.2.0", "# Changelog\n\n## [0.1.4]\n\n- Older.\n")
