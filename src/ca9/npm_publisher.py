"""Review recent npm publisher changes and provenance regressions.

A publisher change after a long release gap is a provenance signal, not a
malware determination. A provenance regression is a release published without
the registry attestation or trusted publisher its recent predecessors had,
which is how a stolen publish token shows up. Only direct, unambiguous
package-lock entries from the public npm registry are eligible in vet.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
PROVENANCE_HISTORY_WINDOW = 5
ABBREVIATED_PACKUMENT = "application/vnd.npm.install-v1+json"
_PROVENANCE_CACHE_VERSION = 1

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
        provenance = provenance_from_document(document, package.name, package.version or "")
        if provenance["status"] == "regressed":
            findings.append(provenance_regression_finding(package, provenance))
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


def check_npm_provenance(
    name: str,
    version: str,
    *,
    cache_dir: Path | None = None,
    documents: dict[str, dict[str, Any] | None] | None = None,
    allow_fetch: bool = True,
) -> dict[str, Any]:
    """Compare a release's provenance with the stable releases published before it.

    Returns ``status`` ok|regressed|unknown with ``evidence``. Registry or cache
    failures return unknown; they never raise. ``documents`` memoizes packuments
    across calls; with ``allow_fetch`` false only the cache and memo are used.
    """
    lowered = ""
    if isinstance(name, str):
        lowered = name.strip().lower()
    if not _PACKAGE_RE.fullmatch(lowered) or not isinstance(version, str) or not version:
        return _provenance_result("unknown", reason="invalid npm package name or version")
    cached = _read_provenance_cache(cache_dir, lowered, version)
    if cached is not None:
        return cached
    url = f"{REGISTRY_ORIGIN}/{quote(lowered, safe='')}"
    memo = documents
    if memo is None:
        memo = {}
    if lowered not in memo and not allow_fetch:
        return _provenance_result("unknown", reason="lookup budget exhausted")
    if lowered not in memo:
        try:
            memo[lowered] = _fetch_packument_for_provenance(url)
        except (RegistryFetchError, urllib.error.URLError, OSError, ValueError) as exc:
            memo[lowered] = None
            return _provenance_result("unknown", reason=f"registry fetch failed ({exc})")
    document = memo[lowered]
    if document is None:
        return _provenance_result("unknown", reason="registry fetch failed")
    result = provenance_from_document(document, lowered, version)
    result["source"] = "npm registry"
    if result["status"] in {"ok", "regressed"}:
        _write_provenance_cache(cache_dir, lowered, version, result)
    return result


def _fetch_packument_for_provenance(url: str) -> dict[str, Any]:
    """Full packument, or the abbreviated one when the full document is too large.

    The abbreviated document keeps ``dist.attestations`` but drops publish times
    and ``_npmUser``, so releases are then ordered by version number.
    """
    try:
        return _fetch_json(url, max_bytes=MAX_PACKUMENT_BYTES)
    except RegistryFetchError as exc:
        if "exceeds" not in str(exc):
            raise
    document = _fetch_json(url, max_bytes=MAX_PACKUMENT_BYTES, accept=ABBREVIATED_PACKUMENT)
    document["_ca9_abbreviated"] = True
    return document


def provenance_from_document(
    document: dict[str, Any],
    name: str,
    version: str,
) -> dict[str, Any]:
    """Decide provenance status from an npm packument.

    Provenance means registry-set ``dist.attestations`` or a trusted-publisher
    ``_npmUser``; fields a publisher controls in package.json do not count. The
    releases compared are the stable ones published just before this version.
    """
    if str(document.get("name", "")).lower() != name.lower():
        return _provenance_result("unknown", reason="registry document names a different package")
    versions = document.get("versions")
    if not isinstance(versions, dict) or not isinstance(versions.get(version), dict):
        return _provenance_result("unknown", reason="version is not in registry metadata")
    metadata = versions[version]
    if document.get("_ca9_abbreviated") is True:
        ordered = _earlier_by_version_number(versions, version)
        published_at = None
        ordering = "version"
    else:
        times = document.get("time")
        if not isinstance(times, dict):
            return _provenance_result("unknown", reason="registry document lacks publish times")
        raw_time = times.get(version)
        published_at = None
        if isinstance(raw_time, str):
            published_at = _parse_time(raw_time)
        if published_at is None:
            return _provenance_result("unknown", reason="version has no valid publish time")
        ordered = _earlier_by_publish_time(times, versions, version, published_at)
        ordering = "publish_time"
    line = _release_line(version)
    same_line = [item for item in ordered if _release_line(item) == line]
    newer_line: list[str] = []
    if ordering == "publish_time" and line is not None:
        newer_line = [item for item in ordered if _is_newer_line(item, line)]
    window = ordered[:PROVENANCE_HISTORY_WINDOW]
    if same_line:
        window = same_line[:PROVENANCE_HISTORY_WINDOW]
    with_provenance = [item for item in window if _has_provenance(versions[item])]
    relation = "same"
    if with_provenance and not same_line:
        relation = "older"
        if _is_newer_line(with_provenance[0], line):
            relation = "newer"
    if not with_provenance and same_line and newer_line:
        newer_window = newer_line[:PROVENANCE_HISTORY_WINDOW]
        newer_with = [item for item in newer_window if _has_provenance(versions[item])]
        if newer_with:
            window = newer_window
            with_provenance = newer_with
            relation = "newer"
    current = _provenance_state(metadata)
    evidence = {
        "registry_url": f"{REGISTRY_ORIGIN}/{quote(name.lower(), safe='')}",
        "version": version,
        "this_version": current,
        "previous_versions_checked": window,
        "previous_with_provenance": with_provenance,
        "ordering": ordering,
    }
    if published_at is not None:
        evidence["published_at"] = published_at.isoformat()
    if current["provenance"] or current["trusted_publisher"]:
        return _provenance_result("ok", evidence=evidence)
    if not with_provenance:
        return _provenance_result("ok", evidence=evidence)
    evidence["line"] = relation
    reason = (
        f"{name}@{version} was published without provenance or a trusted publisher, "
        f"but {', '.join(with_provenance)} had it"
    )
    if relation == "newer":
        reason = (
            f"{name}@{version} was published without provenance on a release line that never "
            f"had it, after newer releases {', '.join(with_provenance)} were published with "
            "provenance; a hand-published backport looks the same as a stolen publish token"
        )
    return _provenance_result("regressed", evidence=evidence, reason=reason)


def _is_newer_line(version: str, line: tuple[int, ...] | None) -> bool:
    other = _release_line(version)
    if other is None or line is None:
        return False
    return other > line


def _earlier_by_publish_time(
    times: dict[str, Any],
    versions: dict[str, Any],
    version: str,
    published_at: datetime,
) -> list[str]:
    earlier: list[tuple[datetime, str]] = []
    for other, other_time in times.items():
        if other in {"created", "modified", version} or not isinstance(other, str):
            continue
        if not _STABLE_VERSION_RE.fullmatch(other) or not isinstance(versions.get(other), dict):
            continue
        if not isinstance(other_time, str):
            continue
        parsed = _parse_time(other_time)
        if parsed is not None and parsed < published_at:
            earlier.append((parsed, other))
    earlier.sort(reverse=True)
    return [item for _, item in earlier]


def _earlier_by_version_number(versions: dict[str, Any], version: str) -> list[str]:
    target = _version_tuple(version)
    if target is None:
        return []
    earlier: list[tuple[tuple[int, int, int], str]] = []
    for other, metadata in versions.items():
        if other == version or not isinstance(other, str) or not isinstance(metadata, dict):
            continue
        if not _STABLE_VERSION_RE.fullmatch(other):
            continue
        number = _version_tuple(other)
        if number is not None and number < target:
            earlier.append((number, other))
    earlier.sort(reverse=True)
    return [item for _, item in earlier]


def _release_line(version: str) -> tuple[int, ...] | None:
    """Major version, or ``0.minor`` for 0.x, so backports compare with their own line."""
    number = _version_tuple(version)
    if number is None:
        return None
    if number[0] == 0:
        return (0, number[1])
    return (number[0],)


def _version_tuple(version: str) -> tuple[int, int, int] | None:
    match = re.match(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def provenance_regression_finding(package: Package, result: dict[str, Any]) -> Finding:
    evidence_metadata = dict(result.get("evidence") or {})
    reason = str(result.get("reason") or "release lost provenance its predecessors had")
    registry_url = str(evidence_metadata.get("registry_url") or REGISTRY_ORIGIN)
    evidence = Evidence(
        kind="npm_provenance_history",
        description=reason,
        source=SourceEvidence(
            source="npm registry", path=registry_url, reader="npm provenance history"
        ),
        metadata=evidence_metadata,
    )
    signal = RiskSignal(
        signal_type="provenance_regression",
        package_key=package.key,
        severity="high",
        confidence="medium",
        evidence=(evidence,),
        metadata={"package": package.name, "version": package.version},
    )
    return Finding(
        title=f"npm provenance regression for {package.name}",
        signal_type="provenance_regression",
        package_key=package.key,
        severity="high",
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": "block",
            "policy_id": "ca9.provenance_regression",
            "reason": reason,
            "package": package.name,
            "version": package.version,
            "dependency_kind": package.dependency_kind,
            "previous_with_provenance": evidence_metadata.get("previous_with_provenance", []),
        },
    )


def _provenance_state(metadata: dict[str, Any]) -> dict[str, bool]:
    dist = metadata.get("dist")
    attestations = None
    if isinstance(dist, dict):
        attestations = dist.get("attestations")
    provenance = False
    if isinstance(attestations, dict):
        url = attestations.get("url")
        provenance = (isinstance(url, str) and bool(url.strip())) or isinstance(
            attestations.get("provenance"), dict
        )
    npm_user = metadata.get("_npmUser")
    trusted = None
    if isinstance(npm_user, dict):
        trusted = npm_user.get("trustedPublisher")
    return {
        "provenance": provenance,
        "trusted_publisher": isinstance(trusted, dict) and bool(trusted.get("id")),
    }


def _has_provenance(metadata: dict[str, Any]) -> bool:
    state = _provenance_state(metadata)
    return state["provenance"] or state["trusted_publisher"]


def _provenance_result(
    status: str,
    *,
    evidence: dict[str, Any] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "evidence": evidence or {}}
    if reason:
        result["reason"] = reason
    return result


def _provenance_cache_path(cache_dir: Path, name: str, version: str) -> Path:
    digest = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()
    return cache_dir / "npm-provenance" / f"{digest}.json"


def _read_provenance_cache(
    cache_dir: Path | None, name: str, version: str
) -> dict[str, Any] | None:
    if cache_dir is None:
        return None
    try:
        raw = json.loads(_provenance_cache_path(Path(cache_dir), name, version).read_text())
    except (OSError, ValueError):
        return None
    if (
        not isinstance(raw, dict)
        or raw.get("cache_version") != _PROVENANCE_CACHE_VERSION
        or raw.get("name") != name
        or raw.get("version") != version
        or raw.get("status") not in {"ok", "regressed"}
        or not isinstance(raw.get("evidence"), dict)
    ):
        return None
    result = _provenance_result(raw["status"], evidence=raw["evidence"], reason=raw.get("reason"))
    result["source"] = "cache"
    return result


def _write_provenance_cache(
    cache_dir: Path | None, name: str, version: str, result: dict[str, Any]
) -> None:
    if cache_dir is None:
        return
    path = _provenance_cache_path(Path(cache_dir), name, version)
    payload = {
        "cache_version": _PROVENANCE_CACHE_VERSION,
        "name": name,
        "version": version,
        "status": result["status"],
        "evidence": result.get("evidence") or {},
    }
    if result.get("reason"):
        payload["reason"] = result["reason"]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temp.write_text(json.dumps(payload, sort_keys=True))
        temp.replace(path)
    except OSError:
        return


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


def _fetch_json(url: str, *, max_bytes: int, accept: str = "application/json") -> dict[str, Any]:
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
        headers={"Accept": accept, "User-Agent": "ca9/npm-publisher-check"},
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
