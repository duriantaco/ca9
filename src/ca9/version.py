from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from ca9.models import VersionRange


@dataclass(frozen=True)
class VersionCheckResult:
    affected: bool | None
    installed: Version | None
    matched_range: VersionRange | None = None
    error: str | None = None


def _try_parse(v: str) -> Version | None:
    if not v or not isinstance(v, str):
        return None
    try:
        return Version(v)
    except InvalidVersion:
        return None


def listed_pypi_version(version: str, affected_versions: tuple[str, ...] | list[str]) -> str | None:
    """Return the advisory spelling for an explicitly listed PyPI release."""
    if version in affected_versions:
        return version
    installed = _try_parse(version)
    if installed is None:
        return None
    return next((item for item in affected_versions if _try_parse(item) == installed), None)


def is_version_affected(version: str, ranges: tuple[VersionRange, ...]) -> bool | None:
    if not ranges:
        return None

    installed = _try_parse(version)
    if installed is None:
        return None

    has_usable_range = False

    for r in ranges:
        if not r.introduced:
            continue

        introduced = _try_parse(r.introduced)
        if introduced is None:
            continue

        has_usable_range = True

        if installed < introduced:
            continue

        if r.fixed:
            fixed = _try_parse(r.fixed)
            if fixed is not None and installed >= fixed:
                continue

        if r.last_affected:
            last = _try_parse(r.last_affected)
            if last is not None and installed > last:
                continue

        return True

    if not has_usable_range:
        return None

    return False


def check_version(version: str, ranges: tuple[VersionRange, ...]) -> VersionCheckResult:
    installed = _try_parse(version)

    if not ranges:
        return VersionCheckResult(affected=None, installed=installed)

    if installed is None:
        return VersionCheckResult(
            affected=None,
            installed=None,
            error=f"Could not parse version: {version!r}",
        )

    has_usable_range = False

    for r in ranges:
        if not r.introduced:
            continue

        introduced = _try_parse(r.introduced)
        if introduced is None:
            continue

        has_usable_range = True

        if installed < introduced:
            continue

        if r.fixed:
            fixed = _try_parse(r.fixed)
            if fixed is not None and installed >= fixed:
                continue

        if r.last_affected:
            last = _try_parse(r.last_affected)
            if last is not None and installed > last:
                continue

        return VersionCheckResult(affected=True, installed=installed, matched_range=r)

    if not has_usable_range:
        return VersionCheckResult(affected=None, installed=installed)

    return VersionCheckResult(affected=False, installed=installed)
