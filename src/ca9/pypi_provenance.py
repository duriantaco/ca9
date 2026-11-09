"""PyPI provenance regressions from PEP 740 attestations (PyPI Integrity API).

PyPI accepts attestations only from Trusted Publishers. The PEP 691 JSON simple index
(``https://pypi.org/simple/<project>/``) lists every file with its upload time and a
``provenance`` URL (PEP 740) or null; that URL
(``https://pypi.org/integrity/<project>/<version>/<file>/provenance``) returns the
attestation bundles and the publisher identity (kind, repository, workflow...).

A release regresses when the stable releases uploaded before it on the same release
line (major, or ``0.minor``; else any line) had attestations and it has none, carries a
publisher identity none of them had, or leaves files unattested where every earlier
file was attested: what a stolen API token or a hijacked account looks like. Network
errors, a missing version and a project with no earlier stable release are unknown.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

ORIGIN = "https://pypi.org"
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
MAX_INDEX_BYTES = 32 * 1024 * 1024
MAX_PROVENANCE_BYTES = 4 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 8
HISTORY_WINDOW = 5
MAX_NEW_FILES_CHECKED = 3
_CACHE_VERSION = 1
_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_IGNORED_PUBLISHER_KEYS = frozenset({"environment", "claims"})


class FetchError(ValueError):
    """A PyPI response could not be used for this check."""


class NotFound(FetchError):
    """PyPI answered 404."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def check_pypi_provenance(
    name: str, version: str, *, cache_dir: Path | None = None
) -> dict[str, Any]:
    """``status`` ok|regressed|unknown with ``evidence`` (and ``reason``); never raises."""
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name.strip()):
        return _result("unknown", reason="invalid PyPI project name")
    if not isinstance(version, str) or not version.strip():
        return _result("unknown", reason="invalid version")
    project = str(canonicalize_name(name.strip()))
    version = version.strip()
    try:
        target = Version(version)
    except InvalidVersion:
        return _result("unknown", reason="version is not a PEP 440 version")
    cached = _read_cache(cache_dir, project, version)
    if cached is not None:
        return cached
    try:
        result = _check(project, version, target)
    except (FetchError, urllib.error.URLError, OSError, ValueError) as exc:
        return _result("unknown", reason=f"PyPI lookup failed ({exc})")
    result["source"] = "pypi"
    if result["status"] in {"ok", "regressed"}:
        _write_cache(cache_dir, project, version, result)
    return result


def _check(project: str, version: str, target: Version) -> dict[str, Any]:
    simple_url = f"{ORIGIN}/simple/{quote(project, safe='')}/"
    document = _fetch_json(simple_url, max_bytes=MAX_INDEX_BYTES, accept=SIMPLE_JSON)
    listed = document.get("name")
    if isinstance(listed, str) and canonicalize_name(listed) != project:
        return _result("unknown", reason="index document names a different project")
    releases = _releases(project, document.get("files"))
    current = releases.get(target)
    if current is None:
        return _result("unknown", reason="version is not in registry metadata")
    published_at = current["uploaded"]
    if published_at is None:
        return _result("unknown", reason="version has no upload time in the index")
    earlier = sorted(
        (
            (release["uploaded"], number)
            for number, release in releases.items()
            if number != target
            and not number.is_prerelease
            and release["uploaded"] is not None
            and release["uploaded"] < published_at
        ),
        reverse=True,
    )
    ordered = [number for _uploaded, number in earlier]
    if not ordered:
        return _result("unknown", reason="no earlier stable release to compare with")
    line = _line(target)
    same_line = [number for number in ordered if _line(number) == line]
    newer_line = [number for number in ordered if _line(number) > line]
    window = ordered[:HISTORY_WINDOW]
    if same_line:
        window = same_line[:HISTORY_WINDOW]
    with_provenance = [number for number in window if _attested(releases[number])]
    relation = "same"
    if with_provenance and not same_line:
        relation = "older"
        if _line(with_provenance[0]) > line:
            relation = "newer"
    if not with_provenance and same_line and newer_line:
        newer_window = newer_line[:HISTORY_WINDOW]
        newer_with = [number for number in newer_window if _attested(releases[number])]
        if newer_with:
            window = newer_window
            with_provenance = newer_with
            relation = "newer"
    files = current["files"]
    attested = [item for item in files if item["provenance"]]
    evidence: dict[str, Any] = {
        "registry_url": simple_url,
        "version": version,
        "published_at": published_at.isoformat(),
        "ordering": "upload_time",
        "previous_versions_checked": [releases[number]["version"] for number in window],
        "previous_with_provenance": [releases[number]["version"] for number in with_provenance],
        "this_version": {"files": len(files), "attested_files": len(attested)},
    }
    if not with_provenance:
        return _result("ok", evidence=evidence)
    previous = _publishers(
        project, [_first_attested(releases[number]) for number in with_provenance]
    )
    evidence["previous_publishers"] = previous
    evidence["line"] = relation
    names = ", ".join(evidence["previous_with_provenance"])
    if not attested:
        reason = (
            f"{project}=={version} was published without PEP 740 attestations, but {names} "
            "had them from a Trusted Publisher"
        )
        if relation == "newer":
            reason = (
                f"{project}=={version} was published without attestations on a release line "
                f"that never had them, after newer releases {names} were attested; a "
                "hand-published backport looks the same as a stolen API token"
            )
        return _result("regressed", evidence=evidence, reason=reason)
    checked = sorted(attested, key=lambda item: item["filename"])[:MAX_NEW_FILES_CHECKED]
    current_publishers = _publishers(project, checked)
    evidence["this_version"]["publishers"] = current_publishers
    if len(attested) > len(checked):
        evidence["this_version"]["files_not_checked"] = len(attested) - len(checked)
    known = {_identity(item) for item in previous}
    foreign = [item for item in current_publishers if _identity(item) not in known]
    if foreign:
        return _result(
            "regressed",
            evidence=evidence,
            reason=(
                f"{project}=={version} was attested by {_describe(foreign[0])}, a Trusted "
                f"Publisher that did not publish {names} ({_describe(previous[0])})"
            ),
        )
    unattested = sorted(item["filename"] for item in files if not item["provenance"])
    fully_attested = all(
        all(item["provenance"] for item in releases[number]["files"]) for number in with_provenance
    )
    if unattested and fully_attested:
        evidence["files_without_provenance"] = unattested
        return _result(
            "regressed",
            evidence=evidence,
            reason=(
                f"{', '.join(unattested)} of {project}=={version} were uploaded without "
                f"attestations, while every file of {names} was attested"
            ),
        )
    return _result("ok", evidence=evidence)


def _releases(project: str, files: Any) -> dict[Version, dict[str, Any]]:
    if not isinstance(files, list):
        raise FetchError("index document has no file list")
    releases: dict[Version, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            continue
        filename = item["filename"]
        number = _file_version(project, filename)
        if number is None:
            continue
        uploaded = _parse_time(item.get("upload-time"))
        release = releases.setdefault(
            number, {"version": str(number), "files": [], "uploaded": None}
        )
        release["files"].append(
            {
                "filename": filename,
                "provenance": isinstance(item.get("provenance"), str)
                and bool(item["provenance"].strip()),
                "listed_url": item.get("provenance"),
                "version": str(number),
            }
        )
        if uploaded is not None and (release["uploaded"] is None or uploaded < release["uploaded"]):
            release["uploaded"] = uploaded
    return releases


def _file_version(project: str, filename: str) -> Version | None:
    try:
        if filename.endswith(".whl"):
            wheel_name, number, _build, _tags = parse_wheel_filename(filename)
            if wheel_name == project:
                return number
            return None
        sdist_name, number = parse_sdist_filename(filename)
    except (InvalidWheelFilename, InvalidSdistFilename, InvalidVersion):
        return None
    if sdist_name == project:
        return number
    return None


def _attested(release: dict[str, Any]) -> bool:
    return any(item["provenance"] for item in release["files"])


def _first_attested(release: dict[str, Any]) -> dict[str, Any]:
    return sorted(
        (item for item in release["files"] if item["provenance"]),
        key=lambda item: item["filename"],
    )[0]


def _publishers(project: str, files: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Distinct publisher identities of ``files``; any failed lookup raises."""
    found: list[dict[str, str]] = []
    for item in files:
        url = _integrity_url(project, item)
        document = _fetch_json(url, max_bytes=MAX_PROVENANCE_BYTES)
        bundles = document.get("attestation_bundles")
        if not isinstance(bundles, list) or not bundles:
            raise FetchError(f"provenance for {item['filename']} has no attestation bundles")
        for bundle in bundles:
            publisher = bundle.get("publisher") if isinstance(bundle, dict) else None
            if not isinstance(publisher, dict):
                raise FetchError(f"provenance for {item['filename']} names no publisher")
            identity = {
                str(key): str(value)
                for key, value in publisher.items()
                if key not in _IGNORED_PUBLISHER_KEYS and isinstance(value, str) and value
            }
            if identity not in found:
                found.append(identity)
    return found


def _integrity_url(project: str, item: dict[str, Any]) -> str:
    """The index's own provenance URL when it is a pypi.org integrity URL, else the
    URL PyPI documents for that file."""
    listed = item.get("listed_url")
    if isinstance(listed, str):
        try:
            parts = urlsplit(listed)
        except ValueError:
            parts = None
        if (
            parts is not None
            and f"{parts.scheme}://{parts.netloc}" == ORIGIN
            and parts.path.startswith("/integrity/")
            and not parts.query
            and not parts.fragment
        ):
            return listed
    return (
        f"{ORIGIN}/integrity/{quote(project, safe='')}/{quote(item['version'], safe='')}/"
        f"{quote(item['filename'], safe='')}/provenance"
    )


def _identity(publisher: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(publisher.items()))


def _describe(publisher: dict[str, str]) -> str:
    parts = [publisher.get("kind", "publisher")]
    for key in ("repository", "workflow", "workflow_filepath", "email"):
        if publisher.get(key):
            parts.append(publisher[key])
    return " ".join(parts)


def _line(number: Version) -> tuple[int, ...]:
    release = number.release
    if release and release[0] == 0:
        return (0, release[1] if len(release) > 1 else 0)
    return (release[0] if release else 0,)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _result(
    status: str, *, evidence: dict[str, Any] | None = None, reason: str | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "evidence": evidence or {}}
    if reason:
        result["reason"] = reason
    return result


def _cache_path(cache_dir: Path, project: str, version: str) -> Path:
    digest = hashlib.sha256(f"{project}=={version}".encode()).hexdigest()
    return Path(cache_dir) / "pypi-provenance" / f"{digest}.json"


def _read_cache(cache_dir: Path | None, project: str, version: str) -> dict[str, Any] | None:
    if cache_dir is None:
        return None
    try:
        raw = json.loads(_cache_path(cache_dir, project, version).read_text())
    except (OSError, ValueError):
        return None
    if (
        not isinstance(raw, dict)
        or raw.get("cache_version") != _CACHE_VERSION
        or raw.get("project") != project
        or raw.get("version") != version
        or raw.get("status") not in {"ok", "regressed"}
        or not isinstance(raw.get("evidence"), dict)
    ):
        return None
    result = _result(raw["status"], evidence=raw["evidence"], reason=raw.get("reason"))
    result["source"] = "cache"
    return result


def _write_cache(
    cache_dir: Path | None, project: str, version: str, result: dict[str, Any]
) -> None:
    if cache_dir is None:
        return
    path = _cache_path(cache_dir, project, version)
    payload = {
        "cache_version": _CACHE_VERSION,
        "project": project,
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


def _fetch_json(url: str, *, max_bytes: int, accept: str = "application/json") -> dict[str, Any]:
    """A bounded JSON object from https://pypi.org, without redirects."""
    parsed = urlsplit(url)
    if (
        f"{parsed.scheme}://{parsed.netloc}" != ORIGIN
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise FetchError("off-origin PyPI URL")
    request = urllib.request.Request(
        url, headers={"Accept": accept, "User-Agent": "ca9/pypi-provenance-check"}
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            if response.getcode() != 200:
                raise FetchError(f"HTTP {response.getcode()}")
            if response.geturl() != url:
                raise FetchError("redirected PyPI response")
            length = response.headers.get("Content-Length")
            if length is not None and length.isdigit() and int(length) > max_bytes:
                raise FetchError(f"response exceeds {max_bytes} bytes")
            raw = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFound(f"HTTP 404 from {url}") from exc
        raise FetchError(f"HTTP {exc.code}") from exc
    if len(raw) > max_bytes:
        raise FetchError(f"response exceeds {max_bytes} bytes")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchError("invalid JSON response") from exc
    if not isinstance(document, dict):
        raise FetchError("JSON response is not an object")
    return document
