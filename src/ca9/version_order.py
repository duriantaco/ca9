"""Version ordering for npm (semver) and PyPI (PEP 440), and OSV range evaluation.

npm orders versions by SemVer 2.0 precedence: a prerelease sorts before its
release (``1.0.0-rc.1 < 1.0.0``), numeric prerelease identifiers compare
numerically and before alphanumeric ones, and build metadata is ignored. PyPI
uses ``packaging``'s PEP 440 ordering. Both parsers accept the loose spellings
package managers accept for an exact version (a leading ``v`` or ``=``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from packaging.version import InvalidVersion, Version

_NPM_SEMVER_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_LOOSE_PREFIX_RE = re.compile(r"^[=v\s]+")
OSV_VERSION_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM"})


def npm_semver_key(version: str) -> tuple[Any, ...] | None:
    """SemVer precedence key for an npm version, or None when it is not semver."""
    if not isinstance(version, str):
        return None
    candidate = _LOOSE_PREFIX_RE.sub("", version.strip())
    match = _NPM_SEMVER_RE.fullmatch(candidate)
    if match is None:
        return None
    major, minor, patch, prerelease = match.groups()
    if prerelease is None:
        release_marker: tuple[Any, ...] = (1,)
    else:
        identifiers = []
        for part in prerelease.split("."):
            if part.isdigit():
                identifiers.append((0, int(part), ""))
            else:
                identifiers.append((1, 0, part))
        release_marker = (0, *identifiers)
    return (int(major), int(minor), int(patch), release_marker)


def pypi_version_key(version: str) -> Version | None:
    if not isinstance(version, str):
        return None
    try:
        return Version(version.strip())
    except InvalidVersion:
        return None


def version_key(ecosystem: str, version: str) -> Any:
    """Comparable key for ``version`` in ``ecosystem``; None when it cannot be parsed."""
    normalized = ecosystem.lower()
    if normalized == "npm":
        return npm_semver_key(version)
    if normalized == "pypi":
        return pypi_version_key(version)
    return None


def is_prerelease(ecosystem: str, version: str) -> bool:
    """True for prereleases and for versions that cannot be parsed at all."""
    normalized = ecosystem.lower()
    if normalized == "npm":
        key = npm_semver_key(version)
        return key is None or key[3] != (1,)
    parsed = pypi_version_key(version)
    return parsed is None or parsed.is_prerelease or parsed.is_devrelease


def same_version(ecosystem: str, left: str, right: str) -> bool:
    if left == right:
        return True
    left_key = version_key(ecosystem, left)
    return left_key is not None and left_key == version_key(ecosystem, right)


def osv_range_includes(
    ecosystem: str,
    osv_range: dict[str, Any],
    version: str,
) -> bool | None:
    """Evaluate one OSV ``SEMVER``/``ECOSYSTEM`` range for ``version``.

    Returns None when the range type is not a version range or when the version
    or one of the range bounds cannot be compared; callers must treat None as
    "not shown to be affected", never as a match.
    """
    if not isinstance(osv_range, dict) or osv_range.get("type") not in OSV_VERSION_RANGE_TYPES:
        return None
    if osv_range.get("type") == "SEMVER":
        key_ecosystem = "npm"
    else:
        key_ecosystem = ecosystem
    installed = version_key(key_ecosystem, version)
    if installed is None:
        return None
    bounds: list[tuple[int, Any, str]] = []
    limits: list[Any] = []
    for event in _events(osv_range.get("events")):
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind not in event:
                continue
            raw = str(event[kind]).strip()
            if kind == "introduced" and raw == "0":
                bounds.append((0, None, kind))
                continue
            if kind == "limit" and raw == "*":
                limits.append(None)
                continue
            parsed = version_key(key_ecosystem, raw)
            if parsed is None:
                return None
            if kind == "limit":
                limits.append(parsed)
            else:
                bounds.append((1, parsed, kind))
    if not bounds:
        return None
    affected = False
    for _, bound, kind in sorted(bounds, key=_bound_sort_key):
        if kind == "introduced":
            if bound is None or installed >= bound:
                affected = True
        elif kind == "fixed":
            if installed >= bound:
                affected = False
        elif installed > bound:
            affected = False
    if affected and limits:
        affected = any(limit is None or installed < limit for limit in limits)
    return affected


def osv_ranges_include(
    ecosystem: str,
    ranges: Iterable[dict[str, Any]],
    version: str,
) -> bool:
    """True only when some range positively includes ``version``."""
    return any(osv_range_includes(ecosystem, item, version) is True for item in ranges)


def _events(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [event for event in raw if isinstance(event, dict)]


def _bound_sort_key(item: tuple[int, Any, str]) -> tuple[int, Any]:
    rank, bound, _ = item
    if bound is None:
        return (0, 0)
    return (rank, _Comparable(bound))


class _Comparable:
    """Wrap a version key so ``sorted`` never compares it against the "0" sentinel."""

    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value

    def __lt__(self, other: _Comparable) -> bool:
        return self.value < other.value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Comparable) and self.value == other.value

    __hash__ = None
