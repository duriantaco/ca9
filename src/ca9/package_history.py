"""How much history a package name has on its registry.

``package_history`` answers "is this name new or barely used on the registry?"
from facts an uploader cannot backdate: when the project's first file was
published and how many releases it has. A name an AI model invented and an
attacker then registered (slopsquatting) exists, so an existence check passes;
what gives it away is that the project is days old with one release.

Verdicts (``status``):

``new``
    First published less than ``new_days`` ago (default 30).
``thin_history``
    First published less than ``young_days`` ago (default 180) and it has at
    most ``max_thin_releases`` releases (default 2).
``established``
    Anything older or with more history.
``missing``
    The registry has no such project.
``unknown``
    The registry could not be read; never a claim of safety or of risk.

On 2,521 declared dependencies of 184 popular Python projects (Nov 2026) the
defaults mark 0.1% ``new`` and 0.5% ``thin_history``; every project created in
the preceding day is ``new`` and about half of those created 82 days earlier
are ``thin_history``. Links, descriptions and author fields are uploader
controlled, so they are returned for a reviewer but never decide the verdict.

An ``established`` answer cannot become ``new`` later, so it is served from the
release-time cache without a network call. Young and missing answers are
looked up again on every call.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from ca9.release_age import (
    FetchJSON,
    ReleaseLookupError,
    _cache_root,
    _default_fetch,
    _iso,
    _npm_record,
    _parse_time,
    _pypi_project_record,
    _pypi_url,
    _registry_origin,
    _ReleaseStore,
)

DEFAULT_NEW_DAYS = 30
DEFAULT_YOUNG_DAYS = 180
DEFAULT_MAX_THIN_RELEASES = 2
MAX_OWNERS = 10
_SOURCE_HOSTS = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "sr.ht",
    "gitee.com",
)


def package_history(
    ecosystem: str,
    name: str,
    *,
    new_days: int = DEFAULT_NEW_DAYS,
    young_days: int = DEFAULT_YOUNG_DAYS,
    max_thin_releases: int = DEFAULT_MAX_THIN_RELEASES,
    cache_dir: Path | str | None = None,
    fetch: FetchJSON | None = None,
    registry: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Registry history of ``name`` and whether it is new or barely used.

    Result keys: ``status`` (see the module docstring), ``ecosystem``, ``name``,
    ``first_published_at`` and ``latest_published_at`` (ISO 8601 or None),
    ``age_days`` (whole days since the first publish, or None),
    ``release_count`` (releases with at least one file, or None), ``owners``
    (registry account names, at most ``MAX_OWNERS``), ``source_url`` (a linked
    code host, uploader supplied), ``registry_url`` (the project page),
    ``report_url`` (where to report malware), ``thresholds``, ``source``
    ("cache" | "npm" | "pypi" | "policy" | "unsupported") and ``reason`` (why
    the status is "unknown", otherwise None).

    ``fetch`` takes a URL and returns the parsed JSON document (raising on any
    failure); it replaces the built-in HTTPS client, mainly for tests.
    """
    eco = (ecosystem or "").lower()
    clean = (name or "").strip()
    active_now = now or datetime.now(timezone.utc)
    thresholds = {
        "new_days": new_days,
        "young_days": young_days,
        "max_thin_releases": max_thin_releases,
    }
    if eco not in {"npm", "pypi"} or not clean:
        return _result(
            "unknown",
            eco,
            clean,
            thresholds,
            source="unsupported",
            reason="unsupported ecosystem or missing package name",
        )
    if not _valid_thresholds(new_days, young_days, max_thin_releases):
        return _result(
            "unknown",
            eco,
            clean,
            thresholds,
            source="policy",
            reason=(
                "new_days, young_days and max_thin_releases must be non-negative "
                "whole numbers with new_days <= young_days"
            ),
        )

    origin = _registry_origin(eco, registry)
    store = _ReleaseStore(_cache_root(cache_dir), eco, clean, origin)
    cached = _from_cache(store.load(), eco, clean, thresholds, active_now)
    if cached is not None:
        return cached

    getter = fetch or _default_fetch
    url = _pypi_url(clean) if eco == "pypi" else f"{origin}/{urllib.parse.quote(clean, safe='@')}"
    try:
        document = getter(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return _result("missing", eco, clean, thresholds, source=eco)
        return _unreadable(eco, clean, thresholds)
    except Exception:
        return _unreadable(eco, clean, thresholds)
    if not isinstance(document, dict):
        return _unreadable(eco, clean, thresholds)

    try:
        if eco == "pypi":
            record = _pypi_project_record(clean, document, now=active_now)
            first, latest, count = _pypi_times(document)
            owners = _pypi_owners(document)
            source_url = _pypi_source_url(document)
        else:
            record = _npm_record(clean, origin, document, now=active_now)
            first, latest, count = _npm_times(document)
            owners = _npm_owners(document)
            source_url = _npm_source_url(document)
    except ReleaseLookupError:
        return _unreadable(eco, clean, thresholds)
    store.save(record)
    if first is None or count == 0:
        # A project page with no files: nothing can be installed from it and
        # nothing dates it, so it is as unproven as a missing name.
        return _result("missing", eco, clean, thresholds, source=eco, owners=owners)
    return _result(
        _verdict(first, count, thresholds, active_now),
        eco,
        clean,
        thresholds,
        source=eco,
        first=first,
        latest=latest,
        release_count=count,
        owners=owners,
        source_url=source_url,
        now=active_now,
    )


def _valid_thresholds(new_days: Any, young_days: Any, max_thin_releases: Any) -> bool:
    for value in (new_days, young_days, max_thin_releases):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return False
    return new_days <= young_days


def _from_cache(
    record: dict[str, Any],
    eco: str,
    name: str,
    thresholds: dict[str, int],
    now: datetime,
) -> dict[str, Any] | None:
    """An ``established`` answer from cached publish times, else None.

    A cached PyPI time is the newest upload of each release, which is never
    earlier than the project's first upload: when even that says the project
    is older than ``young_days``, it is. Anything younger is fetched fresh.
    """
    if not record or not record.get("complete"):
        return None
    times = [
        parsed
        for parsed in (_parse_time(str(value)) for value in (record.get("versions") or {}).values())
        if parsed is not None
    ]
    if not times:
        return None
    first = min(times)
    if now - first < timedelta(days=thresholds["young_days"]):
        return None
    return _result(
        "established",
        eco,
        name,
        thresholds,
        source="cache",
        first=first,
        latest=max(times),
        release_count=len(times),
        now=now,
    )


def _verdict(first: datetime, count: int, thresholds: dict[str, int], now: datetime) -> str:
    age = now - first
    if age < timedelta(days=thresholds["new_days"]):
        return "new"
    if age < timedelta(days=thresholds["young_days"]) and count <= thresholds["max_thin_releases"]:
        return "thin_history"
    return "established"


def _pypi_times(document: dict[str, Any]) -> tuple[datetime | None, datetime | None, int]:
    releases = document.get("releases")
    if not isinstance(releases, dict):
        raise ReleaseLookupError("PyPI JSON has no releases map")
    uploads: list[datetime] = []
    count = 0
    for files in releases.values():
        if not isinstance(files, list):
            continue
        times = [
            parsed
            for parsed in (
                _parse_time(str(item.get("upload_time_iso_8601") or item.get("upload_time") or ""))
                for item in files
                if isinstance(item, dict)
            )
            if parsed is not None
        ]
        if times:
            count += 1
            uploads.extend(times)
    if not uploads:
        return None, None, 0
    return min(uploads), max(uploads), count


def _npm_times(document: dict[str, Any]) -> tuple[datetime | None, datetime | None, int]:
    times = document.get("time")
    if not isinstance(times, dict):
        raise ReleaseLookupError("npm packument has no time map")
    published = [
        parsed
        for version, value in times.items()
        if version not in {"created", "modified"}
        for parsed in (_parse_time(str(value)),)
        if parsed is not None
    ]
    if not published:
        return None, None, 0
    created = _parse_time(str(times.get("created") or ""))
    first = min([*published, created] if created is not None else published)
    return first, max(published), len(published)


def _pypi_owners(document: dict[str, Any]) -> list[str]:
    ownership = document.get("ownership")
    owners: list[str] = []
    if isinstance(ownership, dict):
        organization = ownership.get("organization")
        if isinstance(organization, str) and organization.strip():
            owners.append(organization.strip())
        for role in ownership.get("roles") or []:
            if isinstance(role, dict) and isinstance(role.get("user"), str):
                owners.append(role["user"].strip())
    return _bounded_names(owners)


def _npm_owners(document: dict[str, Any]) -> list[str]:
    owners = [
        item["name"].strip()
        for item in document.get("maintainers") or []
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    return _bounded_names(owners)


def _bounded_names(names: list[str]) -> list[str]:
    seen: list[str] = []
    for name in names:
        if name and len(name) <= 100 and name not in seen:
            seen.append(name)
    return seen[:MAX_OWNERS]


def _pypi_source_url(document: dict[str, Any]) -> str | None:
    info = document.get("info")
    if not isinstance(info, dict):
        return None
    candidates: list[Any] = []
    urls = info.get("project_urls")
    if isinstance(urls, dict):
        candidates.extend(urls.values())
    candidates.append(info.get("home_page"))
    return _first_source_url(candidates)


def _npm_source_url(document: dict[str, Any]) -> str | None:
    repository = document.get("repository")
    candidates: list[Any] = []
    if isinstance(repository, dict):
        candidates.append(repository.get("url"))
    else:
        candidates.append(repository)
    candidates.append(document.get("homepage"))
    return _first_source_url(candidates)


def _first_source_url(candidates: list[Any]) -> str | None:
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        text = candidate.strip()
        if text.startswith("git+"):
            text = text[4:]
        if text.startswith("git://"):
            text = "https://" + text[len("git://") :]
        parsed = urllib.parse.urlsplit(text)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or parsed.username or parsed.password or len(text) > 300:
            continue
        if any(host == known or host.endswith("." + known) for known in _SOURCE_HOSTS):
            return text[: -len(".git")] if text.endswith(".git") else text
    return None


def _registry_url(eco: str, name: str) -> str:
    if eco == "pypi":
        return (
            f"https://pypi.org/project/{urllib.parse.quote(str(canonicalize_name(name)), safe='')}/"
        )
    return f"https://www.npmjs.com/package/{urllib.parse.quote(name, safe='@/')}"


def _report_url(eco: str, name: str) -> str:
    if eco == "pypi":
        return _registry_url(eco, name) + "submit-malware-report/"
    return "https://docs.npmjs.com/reporting-malware-in-an-npm-package"


def _unreadable(eco: str, name: str, thresholds: dict[str, int]) -> dict[str, Any]:
    return _result(
        "unknown",
        eco,
        name,
        thresholds,
        source=eco,
        reason="registry metadata could not be fetched or parsed",
    )


def _result(
    status: str,
    eco: str,
    name: str,
    thresholds: dict[str, int],
    *,
    source: str,
    first: datetime | None = None,
    latest: datetime | None = None,
    release_count: int | None = None,
    owners: list[str] | None = None,
    source_url: str | None = None,
    reason: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    supported = eco in {"npm", "pypi"} and bool(name)
    return {
        "status": status,
        "ecosystem": eco,
        "name": name,
        "first_published_at": _iso(first) if first is not None else None,
        "latest_published_at": _iso(latest) if latest is not None else None,
        "age_days": (now - first).days if first is not None and now is not None else None,
        "release_count": release_count,
        "owners": list(owners or []),
        "source_url": source_url,
        "registry_url": _registry_url(eco, name) if supported else None,
        "report_url": _report_url(eco, name) if supported else None,
        "thresholds": dict(thresholds),
        "source": source,
        "reason": reason,
    }
