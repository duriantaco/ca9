"""Review recent npm publisher changes after a long release gap.

This is a provenance signal, not a malware determination. Only direct,
unambiguous package-lock entries from the public npm registry are eligible.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from ca9.core.models import Evidence, Finding, Package, RiskSignal, SourceEvidence

REGISTRY_ORIGIN = "https://registry.npmjs.org"
MAX_PACKUMENT_BYTES = 20 * 1024 * 1024
MAX_SEARCH_BYTES = 1024 * 1024
HTTP_TIMEOUT_SECONDS = 8
SEARCH_LIMIT = 25
MIN_DORMANT_DAYS = 180
MAX_EVENT_AGE_DAYS = 365
ESTABLISHED_WEEKLY_DOWNLOADS = 100_000

_PACKAGE_RE = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z")
_PUBLISHER_RE = re.compile(r"[a-z0-9][a-z0-9._~-]*\Z")
_STABLE_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:\+[0-9A-Za-z.-]+)?\Z"
)


class RegistryFetchError(ValueError):
    """A public npm response could not be used for this check."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class _Release:
    version: str
    published_at: datetime
    publisher: str | None
    trusted_publisher: bool


@dataclass(frozen=True)
class _Handover:
    previous: _Release
    first_new: _Release
    locked: _Release
    earlier_publisher_unknown: bool = False

    @property
    def gap_days(self) -> int:
        return (self.first_new.published_at - self.previous.published_at).days


def scan_npm_publisher_changes(
    packages: Iterable[Package], *, now: datetime | None = None
) -> tuple[list[Finding], list[str]]:
    """Find recent dormant-package handovers affecting direct locked npm releases.

    Packument fetch errors produce a report warning without a finding. Search
    errors leave an identified handover visible for review. Findings never
    claim the release is malicious.
    """
    current = _as_utc(now or datetime.now(timezone.utc))
    warnings: list[str] = []
    findings: list[Finding] = []
    documents: dict[str, dict[str, Any] | None] = {}
    seen_package_keys: set[str] = set()

    for package in packages:
        if not _eligible(package) or package.key in seen_package_keys:
            continue
        seen_package_keys.add(package.key)
        name = package.name.lower()
        url = f"{REGISTRY_ORIGIN}/{quote(name, safe='')}"
        if name not in documents:
            try:
                documents[name] = _fetch_json(url, max_bytes=MAX_PACKUMENT_BYTES)
            except (RegistryFetchError, urllib.error.URLError, OSError) as exc:
                documents[name] = None
                warnings.append(
                    f"npm publisher check skipped {name}: registry fetch failed ({exc})"
                )
        document = documents[name]
        if document is None:
            continue
        try:
            handover = _handover_for_locked_release(document, package, current)
        except ValueError as exc:
            warnings.append(f"npm publisher check skipped {name}@{package.version}: {exc}")
            continue
        if handover is None:
            continue
        if _has_established_package(
            handover.first_new.publisher or "",
            excluding=name,
            warnings=warnings,
        ):
            continue
        if handover.earlier_publisher_unknown:
            warnings.append(
                f"npm publisher check for {name}@{package.version}: earlier releases lack "
                "publisher metadata; the new publisher is first observed, not proven first ever"
            )
        findings.append(_finding(package, handover, url))

    unique_warnings = list(dict.fromkeys(warnings))
    return sorted(findings, key=lambda finding: finding.package_key), unique_warnings


def _eligible(package: Package) -> bool:
    if (
        package.ecosystem.lower() != "npm"
        or package.dependency_kind != "direct"
        or package.source_registry != REGISTRY_ORIGIN
        or not isinstance(package.version, str)
        or not _STABLE_VERSION_RE.fullmatch(package.version)
        or not _PACKAGE_RE.fullmatch(package.name.lower())
    ):
        return False
    metadata = package.metadata
    if (
        metadata.get("source_kind") != "registry"
        or metadata.get("identity_ambiguous")
        or metadata.get("identity_unverified")
        or metadata.get("local_workspace")
        or metadata.get("self_name")
        or metadata.get("link")
    ):
        return False
    lock_path = metadata.get("lock_path")
    installed_names = metadata.get("installed_names")
    specifiers = metadata.get("requested_specifiers")
    if (
        not isinstance(lock_path, str)
        or not lock_path.startswith("node_modules/")
        or ".." in lock_path.split("/")
        or "\\" in lock_path
        or not isinstance(installed_names, list)
        or len(installed_names) != 1
        or not isinstance(installed_names[0], str)
        or installed_names[0].lower() != package.name.lower()
        or not isinstance(specifiers, list)
        or not specifiers
        or any(
            not isinstance(specifier, str) or specifier.lower().startswith("npm:")
            for specifier in specifiers
        )
    ):
        return False
    return any(item.reader == "package-lock.json" for item in package.evidence)


def _handover_for_locked_release(
    document: dict[str, Any], package: Package, now: datetime
) -> _Handover | None:
    if str(document.get("name", "")).lower() != package.name.lower():
        raise ValueError("registry document has a different or missing package name")
    times = document.get("time")
    versions = document.get("versions")
    if not isinstance(times, dict) or not isinstance(versions, dict):
        raise ValueError("registry document lacks time or versions metadata")
    locked_version = package.version or ""
    if locked_version not in times or locked_version not in versions:
        raise ValueError("locked version lacks registry release metadata")

    releases: list[_Release] = []
    for version, raw_time in times.items():
        if version in {"created", "modified"}:
            continue
        if not isinstance(version, str) or not isinstance(raw_time, str):
            raise ValueError("registry release time is malformed")
        metadata = versions.get(version)
        # Unpublished versions can remain in `time`. Keep their timestamps in
        # the sequence, but never infer a new publisher across one of them.
        if not isinstance(metadata, dict):
            metadata = {}
        published_at = _parse_time(raw_time)
        if published_at is None:
            raise ValueError(f"release {version} has a malformed timestamp")
        npm_user = metadata.get("_npmUser")
        publisher = npm_user.get("name") if isinstance(npm_user, dict) else None
        if not isinstance(publisher, str) or not _PUBLISHER_RE.fullmatch(publisher.lower()):
            publisher = None
        else:
            publisher = publisher.lower()
        trusted = npm_user.get("trustedPublisher") if isinstance(npm_user, dict) else None
        releases.append(
            _Release(
                version=version,
                published_at=published_at,
                publisher=publisher,
                trusted_publisher=isinstance(trusted, dict) and bool(trusted.get("id")),
            )
        )

    releases.sort(key=lambda item: (item.published_at, item.version))
    locked = next((item for item in releases if item.version == locked_version), None)
    if locked is None:
        raise ValueError("locked release metadata is unavailable")
    if not locked.publisher:
        raise ValueError("locked release lacks npm publisher metadata")
    if locked.published_at > now:
        return None
    seen_publishers: set[str] = set()
    unknown_prior = False
    previous: _Release | None = None
    selected: _Handover | None = None
    for release in releases:
        if release.published_at > now:
            break
        if (
            previous is not None
            and previous.publisher
            and release.publisher
            and release.publisher != previous.publisher
            and release.publisher not in seen_publishers
            and _STABLE_VERSION_RE.fullmatch(release.version)
            and not release.trusted_publisher
            and release.published_at - previous.published_at >= timedelta(days=MIN_DORMANT_DAYS)
            and now - release.published_at <= timedelta(days=MAX_EVENT_AGE_DAYS)
            and release.published_at <= locked.published_at
            and release.publisher == locked.publisher
        ):
            selected = _Handover(
                previous=previous,
                first_new=release,
                locked=locked,
                earlier_publisher_unknown=unknown_prior,
            )
        if release.publisher:
            seen_publishers.add(release.publisher)
        else:
            unknown_prior = True
        previous = release
    if selected is None and any(
        release.published_at <= locked.published_at and not release.publisher
        for release in releases
    ):
        raise ValueError("publisher history before locked release is incomplete")
    return selected


def _has_established_package(
    publisher: str,
    *,
    excluding: str,
    warnings: list[str],
) -> bool:
    if not _PUBLISHER_RE.fullmatch(publisher):
        warnings.append(f"npm publisher check for {excluding}: publisher name cannot be searched")
        return False
    query = urlencode({"text": f"maintainer:{publisher}", "size": SEARCH_LIMIT})
    url = f"{REGISTRY_ORIGIN}/-/v1/search?{query}"
    try:
        results = _fetch_json(url, max_bytes=MAX_SEARCH_BYTES)
    except (RegistryFetchError, urllib.error.URLError, OSError) as exc:
        warnings.append(
            f"npm publisher check for {excluding}: maintainer search failed ({exc}); review finding kept"
        )
        return False
    objects = results.get("objects")
    if not isinstance(objects, list):
        warnings.append(
            f"npm publisher check for {excluding}: malformed maintainer search; review finding kept"
        )
        return False

    missing_weekly_counts = False
    for item in objects[:SEARCH_LIMIT]:
        candidate = item.get("package") if isinstance(item, dict) else None
        if not isinstance(candidate, dict):
            continue
        name = candidate.get("name")
        maintainers = candidate.get("maintainers")
        if (
            not isinstance(name, str)
            or not _PACKAGE_RE.fullmatch(name.lower())
            or name.lower() == excluding
            or not isinstance(maintainers, list)
            or not any(
                isinstance(maintainer, dict)
                and str(maintainer.get("username", "")).lower() == publisher
                for maintainer in maintainers
            )
        ):
            continue
        downloads = item.get("downloads") if isinstance(item, dict) else None
        weekly = downloads.get("weekly") if isinstance(downloads, dict) else None
        if not isinstance(weekly, int) or isinstance(weekly, bool) or weekly < 0:
            missing_weekly_counts = True
            continue
        if weekly >= ESTABLISHED_WEEKLY_DOWNLOADS:
            return True
    if missing_weekly_counts:
        warnings.append(
            f"npm publisher check for {excluding}: maintainer search lacks valid weekly "
            "download counts; review finding kept"
        )
    return False


def _finding(package: Package, handover: _Handover, registry_url: str) -> Finding:
    new_publisher = handover.first_new.publisher or "unknown"
    details = {
        "registry_url": registry_url,
        "previous_version": handover.previous.version,
        "previous_publisher": handover.previous.publisher,
        "previous_published_at": handover.previous.published_at.isoformat(),
        "handover_version": handover.first_new.version,
        "new_publisher": new_publisher,
        "handover_published_at": handover.first_new.published_at.isoformat(),
        "release_gap_days": handover.gap_days,
        "locked_version": handover.locked.version,
        "locked_published_at": handover.locked.published_at.isoformat(),
        "earlier_publisher_history_complete": not handover.earlier_publisher_unknown,
    }
    if handover.earlier_publisher_unknown:
        details["publisher_history_caveat"] = (
            "Earlier releases lack publisher metadata; this is the first observed "
            "publisher, not proven first ever."
        )
    evidence = Evidence(
        kind="npm_publisher_history",
        description=(
            f"{new_publisher} was first observed publishing {package.name} after "
            f"{handover.gap_days} days without a release"
        ),
        source=SourceEvidence(
            source="npm registry", path=registry_url, reader="npm publisher history"
        ),
        metadata=details,
    )
    signal = RiskSignal(
        signal_type="npm_publisher_change",
        package_key=package.key,
        severity="medium",
        confidence="medium",
        evidence=(evidence,),
        metadata={"package": package.name, "version": package.version, **details},
    )
    return Finding(
        title=f"Review npm publisher change for {package.name}",
        signal_type="npm_publisher_change",
        package_key=package.key,
        severity="medium",
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": "warn",
            "policy_id": "ca9.npm_publisher_change",
            "reason": "recent new publisher after a long release gap; review package provenance",
            "package": package.name,
            "version": package.version,
            "dependency_kind": package.dependency_kind,
            **details,
        },
    )


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _as_utc(parsed) if parsed.tzinfo is not None else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _fetch_json(url: str, *, max_bytes: int) -> dict[str, Any]:
    """Fetch a bounded JSON object from the fixed public npm registry."""
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if (
        origin != REGISTRY_ORIGIN
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RegistryFetchError("off-origin npm URL")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "ca9/npm-publisher-check"},
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            if response.getcode() != 200:
                raise RegistryFetchError(f"HTTP {response.getcode()}")
            if response.geturl() != url:
                raise RegistryFetchError("redirect or off-origin npm response")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    length = int(content_length)
                except ValueError as exc:
                    raise RegistryFetchError("invalid content length") from exc
                if length < 0:
                    raise RegistryFetchError("invalid content length")
                if length > max_bytes:
                    raise RegistryFetchError(f"response exceeds {max_bytes} bytes")
            raw = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise RegistryFetchError(f"HTTP {exc.code}") from exc
    if len(raw) > max_bytes:
        raise RegistryFetchError(f"response exceeds {max_bytes} bytes")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryFetchError("invalid JSON response") from exc
    if not isinstance(result, dict):
        raise RegistryFetchError("JSON response is not an object")
    return result
