"""Registry metadata for one published release: which file to fetch and who published it.

Upgrade review compares two releases of a package, so both sides must be the
same kind of file. npm has one tarball per version. PyPI releases list several
files; the comparable pair is a pure-Python wheel when both releases have one,
else wheels for the same platform (what most installs use), else the sdists.
Every document is fetched through the artifact URL policy and size caps.
"""

from __future__ import annotations

import base64
import binascii
import functools
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from packaging.tags import Tag, sys_tags
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from ca9.artifacts import fetch
from ca9.artifacts.pypi import PYPI_JSON_ORIGIN, parse_release_document, release_json_url
from ca9.version_order import is_prerelease, version_key

NPM_PUBLIC_REGISTRY = "https://registry.npmjs.org"
NPM_REGISTRY_ALIASES = frozenset({"https://registry.npmjs.org", "https://registry.yarnpkg.com"})
PYPI_PUBLIC_INDEXES = frozenset(
    {"https://pypi.org", "https://pypi.org/simple", "https://pypi.python.org/simple"}
)
PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"
_SRI = re.compile(r"(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})\Z")
_SHA1_HEX = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z")
_MAINSTREAM_PLATFORM = re.compile(
    r"any|win_amd64|(?:many|musl)?linux(?:_\d+_\d+|1|2010|2014)?_(?:x86_64|aarch64)"
    r"|macosx_\d+_\d+_(?:arm64|x86_64|universal2)"
)
_PLATFORM_RANK = (
    ("manylinux", "x86_64"),
    ("linux", "x86_64"),
    ("musllinux", "x86_64"),
    ("macosx", "arm64"),
    ("macosx", "x86_64"),
    ("macosx", "universal2"),
    ("win", "amd64"),
    ("manylinux", "aarch64"),
)


class ReleaseUnavailable(ValueError):
    """The registry does not publish this release (removed, never published, or 404)."""


class ReleaseMetadataError(ValueError):
    """Registry metadata exists but cannot be used for a verified fetch."""


@dataclass(frozen=True)
class ReleaseFile:
    kind: str
    filename: str
    url: str
    hash: str
    size: int | None = None
    basis: str = ""
    publisher: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind, "filename": self.filename}
        if self.size is not None:
            result["size"] = self.size
        algorithm = self.hash.split(":", 1)[0].split("-", 1)[0]
        result["hash_algorithm"] = algorithm
        return result


@dataclass(frozen=True)
class RegistryRelease:
    version: str
    published: datetime | None
    available: bool = True
    yanked: bool = False


def registry_releases(
    ecosystem: str, name: str, registry: str | None, config: fetch.ArtifactScanConfig
) -> list[RegistryRelease]:
    """Every version the registry lists for a package, with publish time, whether it is
    still installable (npm unpublish) and whether it is yanked (every PyPI file yanked).

    npm: the packument (the abbreviated one, without publish times, when the full one is
    over the size cap). PyPI: the JSON API on pypi.org, PEP 691 elsewhere."""
    if ecosystem == "npm":
        if not _NPM_NAME.fullmatch(name.lower()):
            raise ReleaseMetadataError("invalid npm package name")
        url = f"{npm_registry_base(registry)}/{quote(name, safe='@')}"
        try:
            document = _registry_document(url, config)
        except ValueError as exc:
            if "exceeds" not in str(exc):
                raise
            document = _json_object(_registry_bytes(url, config, NPM_ABBREVIATED))
        return _npm_releases(document, name)
    project = quote(str(canonicalize_name(name)), safe="")
    if is_public_registry("pypi", registry):
        document = _registry_document(f"{PYPI_JSON_ORIGIN}/pypi/{project}/json", config)
        return _pypi_releases(document)
    base = (registry or "").strip().rstrip("/") + "/"
    url = urljoin(base, f"{project}/")
    return _simple_releases(_json_object(_registry_bytes(url, config, PYPI_SIMPLE_JSON)), name)


def previous_release(ecosystem: str, version: str, releases: list[RegistryRelease]) -> str | None:
    """The release a new one is compared with: the highest version below it that was
    published before it, is installable and not yanked, stable when any stable one exists
    (the rule ca9's sentinel uses). None means a first release."""
    target_key = version_key(ecosystem, version)
    if target_key is None:
        raise ReleaseMetadataError(f"{version} is not a valid {ecosystem} version")
    target = next((item for item in releases if item.version == version), None)
    if target is None:
        raise ReleaseUnavailable(f"{version} is not listed in the registry metadata")
    earlier = []
    for other in releases:
        if other.version == version or not other.available or other.yanked:
            continue
        if (
            target.published is not None
            and other.published is not None
            and other.published >= target.published
        ):
            continue
        key = version_key(ecosystem, other.version)
        if key is not None and key < target_key:
            earlier.append((key, other.version))
    stable = [item for item in earlier if not is_prerelease(ecosystem, item[1])]
    pool = stable or earlier
    if not pool:
        return None
    return max(pool, key=lambda item: item[0])[1]


def _npm_releases(document: dict[str, Any], name: str) -> list[RegistryRelease]:
    if str(document.get("name", "")).lower() != name.lower():
        raise ReleaseMetadataError("registry document names a different package")
    versions = document.get("versions")
    if not isinstance(versions, dict):
        versions = {}
    times = document.get("time")
    releases = []
    if isinstance(times, dict):
        for version, stamp in times.items():
            if version in {"created", "modified"} or not isinstance(version, str):
                continue
            releases.append(
                RegistryRelease(version, _parse_time(stamp), available=version in versions)
            )
        return releases
    return [RegistryRelease(str(version), None) for version in versions]


def _pypi_releases(document: dict[str, Any]) -> list[RegistryRelease]:
    listed = document.get("releases")
    if not isinstance(listed, dict):
        raise ReleaseMetadataError("project metadata has no releases map")
    releases = []
    for version, files in listed.items():
        entries = [item for item in files or [] if isinstance(item, dict)]
        if not entries:
            continue
        stamps = [
            _parse_time(item.get("upload_time_iso_8601") or item.get("upload_time"))
            for item in entries
        ]
        known = [stamp for stamp in stamps if stamp is not None]
        yanked = all(bool(item.get("yanked")) for item in entries)
        releases.append(RegistryRelease(str(version), min(known, default=None), yanked=yanked))
    return releases


def _simple_releases(document: dict[str, Any], name: str) -> list[RegistryRelease]:
    files = document.get("files")
    if not isinstance(files, list):
        raise ReleaseMetadataError("simple index response has no file list")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            continue
        _kind, version = _filename_release(item["filename"], name)
        if version is not None:
            grouped.setdefault(version, []).append(item)
    releases = []
    for version, entries in grouped.items():
        stamps = [_parse_time(item.get("upload-time")) for item in entries]
        known = [stamp for stamp in stamps if stamp is not None]
        yanked = all(bool(item.get("yanked")) for item in entries)
        releases.append(RegistryRelease(version, min(known, default=None), yanked=yanked))
    return releases


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


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseMetadataError("registry metadata is not valid JSON") from None
    if not isinstance(document, dict):
        raise ReleaseMetadataError("registry metadata is not an object")
    return document


def npm_registry_base(registry: str | None) -> str:
    if not registry:
        return NPM_PUBLIC_REGISTRY
    base = registry.strip().rstrip("/")
    if base.lower() in NPM_REGISTRY_ALIASES:
        return NPM_PUBLIC_REGISTRY
    return base


def is_public_registry(ecosystem: str, registry: str | None) -> bool:
    if not registry:
        return True
    base = registry.strip().rstrip("/").lower()
    if ecosystem == "npm":
        return base in NPM_REGISTRY_ALIASES
    return base in PYPI_PUBLIC_INDEXES


def npm_release(
    name: str,
    version: str,
    registry: str | None,
    config: fetch.ArtifactScanConfig,
) -> ReleaseFile:
    """Tarball, digest and publisher of one npm version, from the version document."""
    if not _NPM_NAME.fullmatch(name.lower()):
        raise ReleaseMetadataError("invalid npm package name")
    base = npm_registry_base(registry)
    url = f"{base}/{quote(name, safe='@')}/{quote(version, safe='')}"
    document = _registry_document(url, config)
    if str(document.get("name", "")).lower() != name.lower():
        raise ReleaseMetadataError("registry document names a different package")
    if document.get("version") != version:
        raise ReleaseMetadataError("registry document names a different version")
    dist = document.get("dist")
    if not isinstance(dist, dict):
        raise ReleaseMetadataError("registry document has no dist record")
    tarball = dist.get("tarball")
    if not isinstance(tarball, str) or urlsplit(tarball).scheme.lower() != "https":
        raise ReleaseMetadataError("registry document has no HTTPS tarball URL")
    digest = _npm_digest(dist)
    if digest is None:
        raise ReleaseMetadataError("registry document has no usable tarball digest")
    filename = tarball.rsplit("/", 1)[-1] or f"{name}-{version}.tgz"
    return ReleaseFile(
        kind="npm-tarball",
        filename=filename,
        url=tarball,
        hash=digest,
        size=None,
        basis="npm tarball",
        publisher=_npm_publisher(document, dist),
    )


def pypi_release_entries(
    name: str,
    version: str,
    registry: str | None,
    config: fetch.ArtifactScanConfig,
) -> list[dict[str, Any]]:
    """File entries for one PyPI release: the JSON API on pypi.org, PEP 691 elsewhere."""
    if is_public_registry("pypi", registry):
        url = release_json_url(name, version)
        raw = _registry_bytes(url, config)
        try:
            files = parse_release_document(raw, name, version)
        except ValueError as exc:
            raise ReleaseMetadataError(str(exc)) from None
        entries = [entry for entry in (_pypi_entry(item) for item in files) if entry is not None]
    else:
        base = (registry or "").strip().rstrip("/") + "/"
        url = urljoin(base, f"{quote(str(canonicalize_name(name)), safe='')}/")
        raw = _registry_bytes(url, config, PYPI_SIMPLE_JSON)
        entries = _simple_entries(raw, name, version, url)
    if not entries:
        raise ReleaseUnavailable("the registry lists no files for this release")
    return entries


def select_pypi_pair(
    old_entries: list[dict[str, Any]],
    new_entries: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """The same kind of file on both sides: pure wheel, same-platform wheel, else sdist."""
    old_pure = _pure_wheels(old_entries)
    new_pure = _pure_wheels(new_entries)
    if old_pure and new_pure:
        return old_pure[0], new_pure[0], "pure-python wheel"
    platform_pair = _platform_pair(old_entries, new_entries)
    if platform_pair is not None:
        return platform_pair
    old_sdist = sorted(
        (entry for entry in old_entries if entry["kind"] == "sdist"),
        key=lambda entry: entry["filename"],
    )
    new_sdist = sorted(
        (entry for entry in new_entries if entry["kind"] == "sdist"),
        key=lambda entry: entry["filename"],
    )
    if old_sdist and new_sdist:
        return old_sdist[0], new_sdist[0], "sdist"
    return None


@functools.lru_cache(maxsize=1)
def _tag_ranks() -> dict[Tag, int]:
    return {tag: index for index, tag in enumerate(sys_tags())}


def pip_choice(entries: list[dict[str, Any]]) -> tuple[dict[str, Any], str] | None:
    """The file pip would install on this machine: best-ranked compatible wheel, else sdist."""
    ranks = _tag_ranks()
    best: tuple[tuple[int, str], dict[str, Any]] | None = None
    for entry in entries:
        if entry["kind"] != "wheel":
            continue
        priorities = [ranks[tag] for tag in entry["tags"] if tag in ranks]
        if not priorities:
            continue
        key = (min(priorities), entry["filename"])
        if best is None or key < best[0]:
            best = (key, entry)
    if best is not None:
        return best[1], "wheel pip selects on this machine"
    sdists = sorted(
        (entry for entry in entries if entry["kind"] == "sdist"),
        key=lambda entry: entry["filename"],
    )
    if sdists:
        return sdists[0], "sdist (no wheel matches this machine)"
    return None


def comparable_pairs(
    old_entries: list[dict[str, Any]], new_entries: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any], str]]:
    """What pip installs here for each version; plus a same-type pair when those differ."""
    pairs: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    old_pick = pip_choice(old_entries)
    new_pick = pip_choice(new_entries)
    if old_pick is not None and new_pick is not None:
        pairs.append((old_pick[0], new_pick[0], new_pick[1]))
    same = select_pypi_pair(old_entries, new_entries)
    if same is None:
        return pairs
    differing = (
        not pairs
        or _file_type(pairs[0][0]) != _file_type(pairs[0][1])
        or same[1]["filename"] != pairs[0][1]["filename"]
    )
    if differing and not any(
        same[0]["filename"] == old["filename"] and same[1]["filename"] == new["filename"]
        for old, new, _basis in pairs
    ):
        pairs.append(same)
    return pairs


def other_wheels(
    entries: list[dict[str, Any]], reviewed: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Wheels of a release that no reviewed file covers (by name or identical bytes).

    pip installs a different wheel on each platform, so a payload can sit in one
    platform's wheel only; every wheel has to be reviewed for the release to be complete.
    """
    names = {entry["filename"] for entry in reviewed}
    digests = {entry["sha256"] for entry in reviewed}
    found = []
    for entry in sorted(entries, key=lambda item: item["filename"]):
        if entry["kind"] != "wheel" or entry["filename"] in names or entry["sha256"] in digests:
            continue
        names.add(entry["filename"])
        digests.add(entry["sha256"])
        found.append(entry)
    return found


def counterpart(
    old_entries: list[dict[str, Any]], new_entry: dict[str, Any]
) -> dict[str, Any] | None:
    """The old release's file that installs where ``new_entry`` does: the same tags, the
    same platform, the same platform family, else the pure wheel, pip's choice here, any
    wheel or the sdist."""
    wheels = sorted(
        (entry for entry in old_entries if entry["kind"] == "wheel"),
        key=lambda entry: entry["filename"],
    )
    tags = new_entry["tags"]
    platforms = {tag.platform for tag in tags}
    ranks = {key[0] for key in _wheel_keys(new_entry)}
    for matches in (
        lambda entry: bool(entry["tags"] & tags),
        lambda entry: bool({tag.platform for tag in entry["tags"]} & platforms),
        lambda entry: bool({key[0] for key in _wheel_keys(entry)} & ranks),
    ):
        found = [entry for entry in wheels if matches(entry)]
        if found:
            return found[0]
    pure = _pure_wheels(old_entries)
    if pure:
        return pure[0]
    choice = pip_choice(old_entries)
    if choice is not None and choice[0]["kind"] == "wheel":
        return choice[0]
    if wheels:
        return wheels[0]
    if choice is not None:
        return choice[0]
    return None


def pure_wheels(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Wheels that install on any platform (py3-none-any)."""
    return _pure_wheels(entries)


def mainstream_wheel(tags: frozenset[Tag]) -> bool:
    """A wheel most installs use: CPython or pure Python on Linux (glibc or musl) x86_64 or
    aarch64, macOS arm64, x86_64 or universal2, or 64-bit Windows. Free-threaded (``t``)
    ABIs, PyPy and GraalPy, 32-bit and other architectures are uncommon platforms."""
    return any(
        tag.interpreter.startswith(("cp", "py"))
        and not tag.abi.endswith("t")
        and _MAINSTREAM_PLATFORM.fullmatch(tag.platform) is not None
        for tag in tags
    )


def _file_type(entry: dict[str, Any]) -> str:
    if entry["kind"] == "sdist":
        return "sdist"
    if _pure_wheels([entry]):
        return "pure"
    return "platform"


def release_file(entry: dict[str, Any], basis: str) -> ReleaseFile:
    return ReleaseFile(
        kind=entry["kind"],
        filename=entry["filename"],
        url=entry["url"],
        hash=f"sha256:{entry['sha256']}",
        size=entry.get("size"),
        basis=basis,
        publisher=dict(entry.get("publisher") or {}),
    )


def pypi_provenance_publisher(
    name: str,
    version: str,
    filename: str,
    config: fetch.ArtifactScanConfig,
) -> dict[str, Any] | None:
    """The trusted publisher recorded in PyPI's PEP 740 provenance, or None when absent."""
    url = (
        f"https://pypi.org/integrity/{quote(str(canonicalize_name(name)), safe='')}/"
        f"{quote(version, safe='')}/{quote(filename, safe='')}/provenance"
    )
    try:
        document = _registry_document(url, config)
    except ReleaseUnavailable:
        return None
    bundles = document.get("attestation_bundles")
    if not isinstance(bundles, list):
        return None
    for bundle in bundles:
        if not isinstance(bundle, dict):
            continue
        publisher = bundle.get("publisher")
        if isinstance(publisher, dict):
            return {
                key: str(publisher[key])
                for key in ("kind", "repository", "workflow", "environment")
                if isinstance(publisher.get(key), str) and publisher.get(key)
            }
    return None


def _registry_bytes(
    url: str,
    config: fetch.ArtifactScanConfig,
    accept: str = "application/json",
) -> bytes:
    try:
        if accept == "application/json":
            return fetch._fetch_registry_json(url, config)
        return fetch._fetch_registry_json(url, config, accept)
    except fetch.RegistryDocumentNotFound as exc:
        raise ReleaseUnavailable(str(exc)) from None


def _registry_document(url: str, config: fetch.ArtifactScanConfig) -> dict[str, Any]:
    raw = _registry_bytes(url, config)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseMetadataError("registry metadata is not valid JSON") from None
    if not isinstance(document, dict):
        raise ReleaseMetadataError("registry metadata is not an object")
    return document


def _npm_digest(dist: dict[str, Any]) -> str | None:
    integrity = dist.get("integrity")
    if isinstance(integrity, str):
        strongest: tuple[int, str] | None = None
        for token in integrity.split():
            match = _SRI.fullmatch(token)
            if match is None:
                continue
            algorithm, encoded = match.groups()
            try:
                digest = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                continue
            bits = int(algorithm[3:])
            if len(digest) == bits // 8 and (strongest is None or bits > strongest[0]):
                strongest = (bits, token)
        if strongest is not None:
            return strongest[1]
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and _SHA1_HEX.fullmatch(shasum.lower()):
        return f"sha1:{shasum.lower()}"
    return None


def _npm_publisher(document: dict[str, Any], dist: dict[str, Any]) -> dict[str, Any]:
    user = document.get("_npmUser")
    publisher: dict[str, Any] = {"source": "npm _npmUser"}
    if isinstance(user, dict):
        if isinstance(user.get("name"), str):
            publisher["name"] = user["name"]
        if isinstance(user.get("email"), str):
            publisher["email"] = user["email"]
        trusted = user.get("trustedPublisher")
        if isinstance(trusted, dict) and trusted.get("id"):
            publisher["trusted_publisher"] = str(trusted["id"])
    maintainers = document.get("maintainers")
    names = []
    if isinstance(maintainers, list):
        for item in maintainers:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
    publisher["maintainers"] = sorted(set(names))
    attestations = dist.get("attestations")
    publisher["provenance"] = isinstance(attestations, dict) and bool(
        attestations.get("url") or attestations.get("provenance")
    )
    return publisher


def _pypi_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    filename = item.get("filename")
    url = item.get("url")
    digests = item.get("digests")
    if not isinstance(filename, str) or not isinstance(url, str) or not isinstance(digests, dict):
        return None
    packagetype = item.get("packagetype")
    kind = None
    if packagetype == "bdist_wheel" and filename.endswith(".whl"):
        kind = "wheel"
    elif packagetype == "sdist" and filename.endswith((".tar.gz", ".zip")):
        kind = "sdist"
    return _entry(filename, url, digests.get("sha256"), item.get("size"), kind)


def _simple_entries(raw: bytes, name: str, version: str, base_url: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseMetadataError("simple index response is not PEP 691 JSON") from None
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise ReleaseMetadataError("simple index response has no file list")
    listed = document.get("name")
    if isinstance(listed, str) and canonicalize_name(listed) != canonicalize_name(name):
        raise ReleaseMetadataError("simple index response names a different project")
    entries = []
    for item in document["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            continue
        filename = item["filename"]
        kind, file_version = _filename_release(filename, name)
        if kind is None or file_version is None or not _same_version(file_version, version):
            continue
        hashes = item.get("hashes")
        sha256 = None
        if isinstance(hashes, dict):
            sha256 = hashes.get("sha256")
        url = urljoin(base_url, str(item.get("url") or ""))
        entry = _entry(filename, url, sha256, item.get("size"), kind)
        if entry is not None:
            entries.append(entry)
    return entries


def _entry(
    filename: str, url: str, sha256: object, size: object, kind: str | None
) -> dict[str, Any] | None:
    if kind is None or not isinstance(sha256, str) or not _SHA256_HEX.fullmatch(sha256.lower()):
        return None
    if urlsplit(url).scheme.lower() != "https":
        return None
    tags: frozenset = frozenset()
    if kind == "wheel":
        try:
            tags = parse_wheel_filename(filename)[3]
        except InvalidWheelFilename:
            return None
    if not isinstance(size, int) or isinstance(size, bool):
        size = None
    return {
        "filename": filename,
        "url": url,
        "kind": kind,
        "sha256": sha256.lower(),
        "size": size,
        "tags": tags,
    }


def _filename_release(filename: str, name: str) -> tuple[str | None, str | None]:
    try:
        if filename.endswith(".whl"):
            wheel_name, wheel_version, _build, _tags = parse_wheel_filename(filename)
            if wheel_name == canonicalize_name(name):
                return "wheel", str(wheel_version)
            return None, None
        sdist_name, sdist_version = parse_sdist_filename(filename)
        if sdist_name == canonicalize_name(name):
            return "sdist", str(sdist_version)
    except (InvalidWheelFilename, InvalidSdistFilename, InvalidVersion):
        return None, None
    return None, None


def _same_version(listed: str, requested: str) -> bool:
    if listed == requested:
        return True
    try:
        return Version(listed) == Version(requested)
    except InvalidVersion:
        return False


def _pure_wheels(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pure = [
        entry
        for entry in entries
        if entry["kind"] == "wheel"
        and any(
            tag.abi == "none" and tag.platform == "any" and tag.interpreter.startswith("py3")
            for tag in entry["tags"]
        )
    ]
    return sorted(pure, key=lambda entry: entry["filename"])


def _platform_family(platform: str) -> tuple[str, str] | None:
    for family, arch in _PLATFORM_RANK:
        if platform.startswith(family) and platform.endswith(arch):
            if family == "manylinux" or (family == "linux" and platform == "linux_x86_64"):
                return ("manylinux", arch)
            return (family, arch)
    return None


def _wheel_keys(entry: dict[str, Any]) -> set[tuple[int, str, str]]:
    keys = set()
    for tag in entry["tags"]:
        family = _platform_family(tag.platform)
        if family is None:
            continue
        rank = _PLATFORM_RANK.index(family)
        keys.add((rank, tag.interpreter, tag.abi))
    return keys


def _platform_pair(
    old_entries: list[dict[str, Any]],
    new_entries: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    old_wheels = [entry for entry in old_entries if entry["kind"] == "wheel"]
    new_wheels = [entry for entry in new_entries if entry["kind"] == "wheel"]
    if not old_wheels or not new_wheels:
        return None
    exact = []
    family_only = []
    for new in new_wheels:
        new_keys = _wheel_keys(new)
        for old in old_wheels:
            old_keys = _wheel_keys(old)
            for key in new_keys & old_keys:
                exact.append(
                    (key[0], _interpreter_order(key[1], key[2]), new["filename"], old, new)
                )
            new_ranks = {key[0] for key in new_keys}
            for rank in new_ranks & {key[0] for key in old_keys}:
                family_only.append((rank, 0, new["filename"] + old["filename"], old, new))
    for candidates, basis in ((exact, "same-platform wheel"), (family_only, "platform wheel")):
        if candidates:
            best = min(candidates, key=lambda item: (item[0], item[1], item[2]))
            return best[3], best[4], basis
    return None


def _interpreter_order(interpreter: str, abi: str) -> tuple[int, int]:
    """Prefer the running CPython's tag, then abi3, then the newest non-free-threaded tag."""
    current = f"cp{sys.version_info.major}{sys.version_info.minor}"
    if interpreter == current and not abi.endswith("t"):
        return (0, 0)
    if abi == "abi3":
        return (1, 0)
    digits = re.sub(r"\D", "", interpreter)
    if not digits:
        return (3, 0)
    if abi.endswith("t"):
        return (3, -int(digits[:4]))
    return (2, -int(digits[:4]))
