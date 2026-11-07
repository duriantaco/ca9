"""Parse requirement-file lines that name a source instead of a registry release.

pip accepts bare VCS URLs (``git+https://host/repo@ref#egg=name``), bare archive
URLs and local paths on a requirements line, as well as PEP 508 ``name @ url``.
These helpers derive the package identity and the evidence a consumer needs to
judge the source: whether a VCS reference is a full commit and whether an
archive carries a usable hash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
_URL_SCHEMES = ("http://", "https://", "ftp://")
_ARCHIVE_SUFFIXES = (
    ".whl",
    ".tar.gz",
    ".tgz",
    ".zip",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar",
)
_COMMIT_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_HASH_LENGTHS = {"sha256": 64, "sha384": 96, "sha512": 128}
_MARKER_SPLIT_RE = re.compile(r"\s+;|;\s")
_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")


_REQUIREMENT_LONG_OPTIONS = (
    "--index-url",
    "--extra-index-url",
    "--no-index",
    "--find-links",
    "--constraint",
    "--requirement",
    "--editable",
    "--trusted-host",
    "--pre",
    "--prefer-binary",
    "--require-hashes",
    "--only-binary",
    "--no-binary",
    "--use-feature",
    "--global-option",
    "--config-settings",
    "--hash",
)
_REQUIREMENT_SHORT_OPTIONS = {
    "-i": "--index-url",
    "-f": "--find-links",
    "-c": "--constraint",
    "-r": "--requirement",
    "-e": "--editable",
}
_VALUE_OPTIONS = frozenset(
    {
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--constraint",
        "--requirement",
        "--editable",
        "--trusted-host",
        "--only-binary",
        "--no-binary",
        "--use-feature",
        "--global-option",
        "--config-settings",
        "--hash",
    }
)


@dataclass(frozen=True)
class RequirementReference:
    """A requirement that installs from a VCS, a URL, or a local path."""

    name: str
    source_kind: str
    url: str
    version: str | None = None
    name_inferred: bool = False
    vcs_ref: str | None = None
    pinned_commit: bool = False
    local_path: Path | None = None
    artifact_kind: str | None = None
    fragment_hashes: tuple[str, ...] = ()

    @property
    def mutable(self) -> bool:
        if self.source_kind in {"git", "vcs"}:
            return not self.pinned_commit
        return True


def requirement_option(line: str) -> tuple[str, str | None] | None:
    """Return (canonical option, value) for a pip requirements-file option line.

    Long options may be abbreviated to any unique prefix, as optparse allows, and
    take their value after "=" or whitespace.
    """
    if not line.startswith("-"):
        return None
    if line.startswith("--"):
        token = re.match(r"--[A-Za-z0-9-]*", line).group(0)
        rest = line[len(token) :]
        if token in _REQUIREMENT_LONG_OPTIONS:
            option = token
        else:
            matches = [name for name in _REQUIREMENT_LONG_OPTIONS if name.startswith(token)]
            if len(matches) != 1:
                return (token, None)
            option = matches[0]
    else:
        option = _REQUIREMENT_SHORT_OPTIONS.get(line[:2])
        if option is None:
            return (line[:2], None)
        rest = line[2:]
    if option not in _VALUE_OPTIONS:
        return (option, None)
    if rest.startswith("="):
        rest = rest[1:]
    value = rest.strip()
    if option != "--editable":
        parts = value.split()
        if parts:
            value = parts[0]
        else:
            value = ""
    return (option, value or None)


def is_local_location(value: str) -> bool:
    """True for a local directory or file:// location; remote and unexpanded ${VAR} are not."""
    raw = value.strip()
    if not raw or "${" in raw:
        return False
    if raw.lower().startswith("file:"):
        return True
    return "://" not in raw


def valid_hash_pins(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Keep only pip hash pins that can verify a file (``algo:hexdigest``)."""
    pins: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        algorithm, separator, digest = value.strip().partition(":")
        if not separator:
            algorithm, separator, digest = value.strip().partition("=")
        algorithm = algorithm.lower()
        expected_length = _HASH_LENGTHS.get(algorithm)
        if expected_length is None or len(digest) != expected_length:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]+", digest):
            continue
        pins.append(f"{algorithm}:{digest.lower()}")
    return tuple(dict.fromkeys(pins))


def strip_requirement_marker(requirement: str) -> str:
    match = _MARKER_SPLIT_RE.search(requirement)
    if match is None:
        return requirement.strip()
    return requirement[: match.start()].strip()


def looks_like_source_reference(requirement: str) -> bool:
    """True for bare VCS URLs, bare archive URLs and local paths."""
    value = strip_requirement_marker(requirement)
    if not value:
        return False
    lowered = value.lower()
    if lowered.startswith(_VCS_PREFIXES) or lowered.startswith(_URL_SCHEMES):
        return True
    if lowered.startswith("file:"):
        return True
    return _looks_like_path(value)


def parse_requirement_reference(
    requirement: str,
    *,
    base_dir: Path | None = None,
) -> RequirementReference | None:
    """Parse a requirement string that points at a source, or return None.

    Accepts PEP 508 ``name @ url`` as well as pip's bare VCS URLs, archive URLs
    and local paths. Registry requirements (``name==1.0``) return None.
    """
    value = strip_requirement_marker(requirement)
    if not value:
        return None
    if looks_like_source_reference(value):
        return _reference_from_location(value, None, base_dir)
    try:
        parsed = Requirement(value)
    except InvalidRequirement:
        return None
    if not parsed.url:
        return None
    return _reference_from_location(parsed.url.strip(), parsed.name, base_dir)


def _reference_from_location(
    location: str,
    declared_name: str | None,
    base_dir: Path | None,
) -> RequirementReference | None:
    lowered = location.lower()
    fragment = _fragment(location)
    egg = _egg_name(fragment)
    fragment_hashes = _fragment_hashes(fragment)

    if lowered.startswith(_VCS_PREFIXES):
        source_kind = "vcs"
        if lowered.startswith("git+"):
            source_kind = "git"
        vcs_ref = vcs_reference(location)
        inferred = _vcs_repository_name(location)
        name, name_inferred = _choose_name(declared_name, egg, inferred)
        if name is None:
            return None
        return RequirementReference(
            name=name,
            source_kind=source_kind,
            url=location,
            name_inferred=name_inferred,
            vcs_ref=vcs_ref,
            pinned_commit=bool(vcs_ref and _COMMIT_RE.fullmatch(vcs_ref)),
            fragment_hashes=fragment_hashes,
        )

    if lowered.startswith(_URL_SCHEMES):
        path = unquote(urlsplit(location).path)
        filename = path.rstrip("/").rsplit("/", 1)[-1]
        file_name, file_version, artifact_kind = _archive_identity(filename)
        inferred = file_name or _plain_stem(filename) or _host_name(location)
        name, name_inferred = _choose_name(declared_name, egg, inferred)
        if name is None:
            return None
        return RequirementReference(
            name=name,
            source_kind="direct_url",
            url=location,
            version=_matching_version(name, file_name, file_version),
            name_inferred=name_inferred,
            artifact_kind=artifact_kind,
            fragment_hashes=fragment_hashes,
        )

    local_path = _local_path(location, base_dir)
    if local_path is None:
        return None
    file_name, file_version, artifact_kind = _archive_identity(local_path.name)
    inferred = file_name or _plain_stem(local_path.name)
    name, name_inferred = _choose_name(declared_name, egg, inferred)
    if name is None:
        return None
    return RequirementReference(
        name=name,
        source_kind="path",
        url=location,
        version=_matching_version(name, file_name, file_version),
        name_inferred=name_inferred,
        local_path=local_path,
        artifact_kind=artifact_kind,
        fragment_hashes=fragment_hashes,
    )


def vcs_reference(url: str) -> str | None:
    """Return the revision a VCS URL names.

    pip puts it after the last ``@`` of the URL path; npm lockfiles put the
    committish in the fragment (``#<sha>``).
    """
    raw = url.strip()
    if "#" in raw:
        without_fragment, fragment = raw.split("#", 1)
    else:
        without_fragment, fragment = raw, ""
    for prefix in _VCS_PREFIXES:
        if without_fragment.lower().startswith(prefix):
            without_fragment = without_fragment[len(prefix) :]
            break
    split = urlsplit(without_fragment)
    if split.netloc:
        path = split.path
    else:
        path = without_fragment.split(":", 1)[-1]
    if "@" in path:
        ref = path.rsplit("@", 1)[1].strip()
        if ref:
            return ref
    if fragment and "=" not in fragment:
        committish = fragment.strip()
        if committish:
            return committish
    return None


def _fragment(location: str) -> str:
    if "#" not in location:
        return ""
    return location.split("#", 1)[1]


def _egg_name(fragment: str) -> str | None:
    if not fragment:
        return None
    values = parse_qs(fragment).get("egg")
    if not values:
        return None
    egg = values[0].strip()
    match = _NAME_RE.match(egg)
    if match is None:
        return None
    return match.group(0)


def _fragment_hashes(fragment: str) -> tuple[str, ...]:
    if not fragment:
        return ()
    pins: list[str] = []
    for key, values in parse_qs(fragment).items():
        for value in values:
            pins.append(f"{key}:{value}")
    return valid_hash_pins(pins)


def _choose_name(
    declared: str | None,
    egg: str | None,
    inferred: str | None,
) -> tuple[str | None, bool]:
    if declared:
        return declared, False
    if egg:
        return egg, False
    if inferred:
        return inferred, True
    return None, False


def _vcs_repository_name(url: str) -> str | None:
    without_fragment = url.split("#", 1)[0]
    for prefix in _VCS_PREFIXES:
        if without_fragment.lower().startswith(prefix):
            without_fragment = without_fragment[len(prefix) :]
            break
    split = urlsplit(without_fragment)
    if split.netloc:
        path = split.path
    else:
        path = without_fragment.split(":", 1)[-1]
    if "@" in path:
        path = path.rsplit("@", 1)[0]
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    if segment.endswith(".git"):
        segment = segment[: -len(".git")]
    return _safe_name(segment)


def _archive_identity(filename: str) -> tuple[str | None, str | None, str | None]:
    lowered = filename.lower()
    if lowered.endswith(".whl"):
        try:
            name, version, _build, _tags = parse_wheel_filename(filename)
        except InvalidWheelFilename:
            return None, None, "wheel"
        return str(name), str(version), "wheel"
    if not lowered.endswith(_ARCHIVE_SUFFIXES):
        return None, None, None
    stem = filename
    for suffix in _ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            stem = filename[: -len(suffix)]
            break
    try:
        name, version = parse_sdist_filename(f"{stem}.tar.gz")
    except InvalidSdistFilename:
        return _safe_name(stem), None, "sdist"
    return str(name), str(version), "sdist"


def _matching_version(
    name: str,
    file_name: str | None,
    file_version: str | None,
) -> str | None:
    if not file_name or not file_version:
        return None
    if canonicalize_name(name) != canonicalize_name(file_name):
        return None
    return file_version


def _plain_stem(filename: str) -> str | None:
    stem = filename
    lowered = filename.lower()
    for suffix in _ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            stem = filename[: -len(suffix)]
            break
    return _safe_name(stem)


def _host_name(url: str) -> str | None:
    host = urlsplit(url).hostname or ""
    return _safe_name(host.replace(".", "-"))


def _safe_name(value: str) -> str | None:
    match = _NAME_RE.search(value or "")
    if match is None:
        return None
    return match.group(0)


def _looks_like_path(value: str) -> bool:
    if value in {".", "./"}:
        return False
    if value.startswith(("./", "../", "/", "~/", ".\\", "..\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    if "://" in value or " " in value:
        return False
    first = value.split("#", 1)[0]
    if "/" in first or "\\" in first:
        return True
    return first.lower().endswith(_ARCHIVE_SUFFIXES)


def _local_path(location: str, base_dir: Path | None) -> Path | None:
    raw = location.split("#", 1)[0].strip()
    if not raw or "\x00" in raw:
        return None
    if raw.lower().startswith("file:"):
        split = urlsplit(raw)
        if split.netloc not in {"", "localhost"}:
            return None
        raw = unquote(split.path)
        if not raw:
            return None
    path = Path(raw)
    if raw.startswith("~"):
        path = path.expanduser()
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None
