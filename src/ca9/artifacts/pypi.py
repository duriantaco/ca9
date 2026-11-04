"""Resolve a pinned PyPI release to one distribution file for inspection.

Requirements files name versions, not files. For a pinned registry dependency
that installs only from PyPI, the PyPI JSON API lists the release files and
their sha256 digests; one bounded file is chosen: the pure-Python wheel when
there is one, otherwise the sdist. With ``--hash`` pins only a file whose
digest is pinned is chosen, so a pin set built for another index never turns
into a false hash mismatch.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import quote, urlsplit

from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from ca9.core.models import Artifact, Package, SourceEvidence
from ca9.readers.requirements import valid_hash_pins

PYPI_JSON_ORIGIN = "https://pypi.org"
PYPI_SIMPLE_INDEXES = frozenset({"https://pypi.org/simple", "https://pypi.python.org/simple"})
MAX_PYPI_JSON_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_PYPI_RESOLUTIONS = 200
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ARTIFACT_KINDS = frozenset({"wheel", "sdist", "npm-tarball"})
_REGISTRY_SOURCE_KINDS = frozenset({"", "registry"})


@dataclass(frozen=True)
class PyPISelection:
    artifact: Artifact | None
    reason: str = ""


def is_pypi_resolution_candidate(
    package: Package,
    internal_patterns: tuple[str, ...] = (),
) -> tuple[bool, str]:
    """Return whether the package's artifact should be resolved from PyPI, and why not."""
    if package.ecosystem.lower() != "pypi":
        return False, "not a PyPI package"
    if any(artifact.kind in _ARTIFACT_KINDS for artifact in package.artifacts):
        return False, "artifact already recorded"
    if str(package.metadata.get("source_kind") or "") not in _REGISTRY_SOURCE_KINDS:
        return False, "not a registry dependency"
    if not package.version:
        return False, "version is not pinned"
    if package.metadata.get("registry_mode") == "merged":
        return False, "merged index setup; the serving index is not known"
    if package.metadata.get("registry_mode") == "local":
        return False, "installs from local find-links only"
    if package.source_registry and _normalized(package.source_registry) not in PYPI_SIMPLE_INDEXES:
        return False, f"installs from {package.source_registry}, not PyPI"
    normalized_name = _glob_name(package.name)
    for pattern in internal_patterns:
        if fnmatch(normalized_name, _glob_name(pattern)):
            return False, "internal package name is not looked up on PyPI"
    return True, ""


def release_json_url(name: str, version: str) -> str:
    return (
        f"{PYPI_JSON_ORIGIN}/pypi/{quote(str(canonicalize_name(name)), safe='')}/"
        f"{quote(version, safe='')}/json"
    )


def parse_release_document(raw: bytes, name: str, version: str) -> list[dict]:
    """Validate a PyPI release JSON document and return its file entries."""
    if len(raw) > MAX_PYPI_JSON_BYTES:
        raise ValueError(f"PyPI release metadata exceeds {MAX_PYPI_JSON_BYTES} bytes")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("PyPI release metadata is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("PyPI release metadata is not an object")
    info = document.get("info")
    if not isinstance(info, dict):
        raise ValueError("PyPI release metadata has no info block")
    listed_name = info.get("name")
    listed_version = info.get("version")
    if not isinstance(listed_name, str) or canonicalize_name(listed_name) != canonicalize_name(
        name
    ):
        raise ValueError("PyPI release metadata names a different project")
    if not isinstance(listed_version, str) or not _same_version(listed_version, version):
        raise ValueError("PyPI release metadata names a different version")
    files = document.get("urls")
    if not isinstance(files, list):
        raise ValueError("PyPI release metadata has no file list")
    return [item for item in files if isinstance(item, dict)]


def select_release_file(
    package: Package,
    files: list[dict],
    json_url: str,
) -> PyPISelection:
    """Pick one file: a py3-none-any wheel, else the sdist; pinned files only when pinned."""
    entries = [entry for entry in (_file_entry(item) for item in files) if entry is not None]
    if not entries:
        return PyPISelection(None, "PyPI lists no files for this release")
    pins = valid_hash_pins(_metadata_hashes(package))
    pinned_sha256 = {pin.split(":", 1)[1] for pin in pins if pin.startswith("sha256:")}
    if pins and not pinned_sha256:
        return PyPISelection(None, "--hash pins use no sha256 digest that PyPI lists")
    pool = entries
    if pinned_sha256:
        pool = [entry for entry in entries if entry["sha256"] in pinned_sha256]
        if not pool:
            return PyPISelection(
                None,
                "no PyPI file matches the --hash pins; the pinned files may come from "
                "another index",
            )
    chosen = _preferred(pool, allow_platform_wheels=bool(pinned_sha256))
    if chosen is None:
        return PyPISelection(None, "release has no py3-none-any wheel or sdist")
    return PyPISelection(
        Artifact(
            kind=chosen["kind"],
            url=chosen["url"],
            hash=f"sha256:{chosen['sha256']}",
            size=chosen["size"],
            upload_time=chosen["upload_time"],
            source=PYPI_JSON_ORIGIN,
            evidence=(
                SourceEvidence(
                    source="PyPI JSON API",
                    path=json_url,
                    reader="ca9 PyPI artifact resolver",
                    detail=chosen["filename"],
                ),
            ),
        )
    )


def _preferred(entries: list[dict], *, allow_platform_wheels: bool) -> dict | None:
    ordered = sorted(entries, key=lambda entry: entry["filename"])
    for entry in ordered:
        if entry["kind"] == "wheel" and entry["pure"]:
            return entry
    for entry in ordered:
        if entry["kind"] == "sdist":
            return entry
    if allow_platform_wheels:
        for entry in ordered:
            if entry["kind"] == "wheel":
                return entry
    return None


def _file_entry(item: dict) -> dict | None:
    filename = item.get("filename")
    url = item.get("url")
    packagetype = item.get("packagetype")
    digests = item.get("digests")
    if not isinstance(filename, str) or not isinstance(url, str):
        return None
    if not isinstance(digests, dict):
        return None
    sha256 = digests.get("sha256")
    if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256.lower()):
        return None
    if urlsplit(url).scheme.lower() != "https":
        return None
    if packagetype == "bdist_wheel" and filename.endswith(".whl"):
        kind = "wheel"
    elif packagetype == "sdist":
        kind = "sdist"
    else:
        return None
    size = item.get("size")
    if not isinstance(size, int) or isinstance(size, bool):
        size = None
    upload_time = item.get("upload_time_iso_8601")
    if not isinstance(upload_time, str):
        upload_time = None
    return {
        "filename": filename,
        "url": url,
        "kind": kind,
        "sha256": sha256.lower(),
        "size": size,
        "upload_time": upload_time,
        "pure": kind == "wheel" and _is_pure_python3_wheel(filename),
    }


def _is_pure_python3_wheel(filename: str) -> bool:
    try:
        _name, _version, _build, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return False
    return any(
        tag.abi == "none" and tag.platform == "any" and tag.interpreter.startswith("py3")
        for tag in tags
    )


def _metadata_hashes(package: Package) -> list[str]:
    hashes = package.metadata.get("hashes")
    if not isinstance(hashes, list):
        return []
    return [item for item in hashes if isinstance(item, str)]


def _same_version(listed: str, requested: str) -> bool:
    if listed == requested:
        return True
    try:
        return Version(listed) == Version(requested)
    except InvalidVersion:
        return False


def _normalized(value: str) -> str:
    split = urlsplit(value.strip())
    if split.scheme and split.netloc:
        return f"{split.scheme.lower()}://{split.netloc.lower()}{split.path.rstrip('/')}"
    return value.strip().rstrip("/").lower()


def _glob_name(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(".", "-")
