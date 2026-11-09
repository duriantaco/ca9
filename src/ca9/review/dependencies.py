"""Dependencies a release adds, which version of each would install, and whether it is
young enough to need its own first-release review.

A two-stage package keeps itself clean and puts the payload in a brand-new dependency it
adds. When a reviewed release declares a dependency the old release did not, the version
its range resolves to is reviewed as a first release if that version is the package's
first release or the package is young (its first release at most ``YOUNG_DAYS`` before).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ca9.artifacts.releases import RegistryRelease, previous_release
from ca9.version_order import is_prerelease, npm_semver_key

YOUNG_DAYS = 30
_NON_REGISTRY_NPM = re.compile(
    r"^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|workspace:|npm:|"
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)",
    re.I,
)
_COMPARATOR_RE = re.compile(
    r"(<=|>=|<|>|=|\^|~>?)?\s*v?([0-9xX*]+(?:\.[0-9xX*]+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"
)
_HYPHEN_RE = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")


@dataclass(frozen=True)
class Dependency:
    name: str
    spec: str


def resolve(ecosystem: str, spec: str, releases: list[RegistryRelease]) -> str | None:
    """The highest installable, non-yanked version ``spec`` allows, stable when possible."""
    candidates = [item.version for item in releases if item.available and not item.yanked]
    if ecosystem == "npm":
        allowed = [item for item in candidates if npm_satisfies(item, spec)]
        stable = [item for item in allowed if not is_prerelease("npm", item)]
        pool = stable or allowed
        if not pool:
            return None
        return max(pool, key=lambda item: npm_semver_key(item) or ())
    try:
        requirement = Requirement(spec)
    except InvalidRequirement:
        return None
    versions = []
    for item in candidates:
        try:
            versions.append(Version(item))
        except InvalidVersion:
            continue
    allowed = list(requirement.specifier.filter(versions, prereleases=False))
    if not allowed:
        allowed = list(requirement.specifier.filter(versions, prereleases=True))
    if not allowed:
        return None
    best = max(allowed)
    return next(item for item in candidates if _same_pep440(item, best))


def youth(ecosystem: str, version: str, releases: list[RegistryRelease]) -> str | None:
    """Why ``version`` needs a first-release review, or None for an established package."""
    if previous_release(ecosystem, version, releases) is None:
        return "first release"
    target = next((item for item in releases if item.version == version), None)
    stamps = [
        item.published
        for item in releases
        if item.published is not None and item.available and not item.yanked
    ]
    if target is None or target.published is None or not stamps:
        return None
    age = target.published - min(stamps)
    if age.days <= YOUNG_DAYS:
        return f"young: first release {age.days} days earlier"
    return None


def npm_satisfies(version: str, spec: str) -> bool | None:
    """Whether an npm version satisfies a range (``^``, ``~``, comparators, x-ranges,
    hyphen ranges, ``||``); None when ``spec`` is not a registry range."""
    key = npm_semver_key(version)
    text = spec.strip()
    if not text or text in {"*", "x", "X", "latest"}:
        return key is not None
    if _NON_REGISTRY_NPM.match(text):
        return None
    if key is None:
        return False
    for alternative in text.split("||"):
        hyphen = _HYPHEN_RE.match(alternative)
        if hyphen is not None:
            low = _bounds(">=", hyphen.group(1))
            high = _bounds("<=", hyphen.group(2))
            if low is None or high is None:
                return None
            if _within(key, [*low, *high]):
                return True
            continue
        comparators = _COMPARATOR_RE.findall(alternative)
        rest = _COMPARATOR_RE.sub("", alternative).strip()
        if not comparators or rest:
            return None
        limits = []
        for operator, value in comparators:
            bound = _bounds(operator or "=", value)
            if bound is None:
                return None
            limits.extend(bound)
        if _within(key, limits):
            return True
    return False


def _within(key: tuple[Any, ...], limits: list[tuple[str, tuple[Any, ...]]]) -> bool:
    for operator, bound in limits:
        if operator == ">=" and not key >= bound:
            return False
        if operator == "<" and not key < bound:
            return False
        if operator == "<=" and not key <= bound:
            return False
        if operator == ">" and not key > bound:
            return False
    return True


def _bounds(operator: str, value: str) -> list[tuple[str, tuple[Any, ...]]] | None:
    """Comparator limits as (op, semver key) pairs, with partial versions widened."""
    core, _dash, prerelease = value.partition("-")
    parts = [part for part in core.split(".") if part]
    numbers: list[int] = []
    for part in parts[:3]:
        if part in {"x", "X", "*"}:
            break
        if not part.isdigit():
            return None
        numbers.append(int(part))
    exact = len(numbers) == 3
    lower = _key(numbers, prerelease if exact else "")
    upper = _next(numbers)
    if operator == "^":
        if not numbers:
            return []
        position = next((index for index, item in enumerate(numbers) if item), len(numbers) - 1)
        position = min(position, len(numbers) - 1)
        return [(">=", lower), ("<", _key(_bump(numbers, position), "0"))]
    if operator in {"~", "~>"}:
        if not numbers:
            return []
        level = 1 if len(numbers) >= 2 else 0
        return [(">=", lower), ("<", _key(_bump(numbers, level), "0"))]
    if operator == "=":
        if not numbers:
            return []
        if exact:
            return [(">=", lower), ("<=", lower)]
        return [(">=", lower), ("<", upper)]
    if operator == ">=":
        return [(">=", lower)]
    if operator == "<":
        return [("<", lower)]
    if operator == ">":
        if exact:
            return [(">", lower)]
        return [(">=", upper)]
    if operator == "<=":
        if exact:
            return [("<=", lower)]
        return [("<", upper)]
    return None


def _key(numbers: list[int], prerelease: str) -> tuple[Any, ...]:
    padded = [*numbers, 0, 0, 0][:3]
    text = ".".join(str(item) for item in padded)
    if prerelease:
        text = f"{text}-{prerelease}"
    return npm_semver_key(text) or ()


def _next(numbers: list[int]) -> tuple[Any, ...]:
    if not numbers:
        return (10**9, 0, 0, (1,))
    return _key(_bump(numbers, len(numbers) - 1), "0")


def _bump(numbers: list[int], position: int) -> list[int]:
    bumped = list(numbers[: position + 1])
    bumped[position] += 1
    return bumped


def _same_pep440(text: str, version: Version) -> bool:
    try:
        return Version(text) == version
    except InvalidVersion:
        return False


def normalized(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return str(canonicalize_name(name))
    return name.lower()
