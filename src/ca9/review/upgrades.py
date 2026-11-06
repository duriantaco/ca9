"""Review dependency upgrades by diffing the old and new published artifacts.

For each (ecosystem, name, old, new) pair both releases are fetched from a
trusted registry with digest verification and size caps, unpacked safely and
compared with deterministic static rules. Only behaviours that the new release
adds are reported; behaviours already present in the old release are counted
as unchanged. Package code is never installed, imported or executed.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import re
import shutil
import tempfile
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any

from ca9.analyzers.supply_chain import internal_pattern_for, registry_matches
from ca9.artifacts import fetch
from ca9.artifacts.releases import (
    ReleaseFile,
    ReleaseMetadataError,
    ReleaseUnavailable,
    comparable_pairs,
    is_public_registry,
    npm_release,
    pip_choice,
    pypi_provenance_publisher,
    pypi_release_entries,
    release_file,
    select_pypi_pair,
)
from ca9.core.models import Artifact, Inventory, Package
from ca9.review.upgrade_rules import (
    BLOCK_KINDS,
    WARN_KINDS,
    AnalysisTimeout,
    diff_artifacts,
    diff_new_package,
)

SCHEMA = "ca9.upgrade_review.v1"
DEFAULT_MAX_PAIRS = 50
DEFAULT_MAX_ARTIFACT_MB = 50
DEFAULT_MAX_SECONDS = 120
DEFAULT_REQUEST_TIMEOUT = 20
NEW_PACKAGE_WARN_KINDS = (*WARN_KINDS, "new_install_hook", "new_sitecustomize")
SDIST_LIMITATION = "sdist not compared: a payload present only in the sdist would not be seen"
MAX_EXTRACTED_FILES = 20000
REGISTRY_METADATA_PATH = "(registry metadata)"
_ECOSYSTEMS = {"npm": "npm", "pypi": "pypi"}
_NON_BLOCKING_SKIPS = frozenset({"same_version"})
_NAMES = {
    "npm": re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*"),
    "pypi": re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"),
}
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_!-]*")


@dataclass
class _Receipt:
    pairs: int = 0
    reviewed: int = 0
    artifacts_fetched: int = 0
    skipped: Counter = field(default_factory=Counter)
    invalid_options: list[str] = field(default_factory=list)
    unchanged: Counter = field(default_factory=Counter)
    pairs_with_block: int = 0
    pairs_with_warn: int = 0
    block_deltas: int = 0
    warn_deltas: int = 0
    incomplete_results: int = 0

    def to_dict(self, network: bool) -> dict[str, Any]:
        skipped = [
            {"reason": reason, "count": count} for reason, count in sorted(self.skipped.items())
        ]
        incomplete = self.incomplete_results > 0 or any(
            reason not in _NON_BLOCKING_SKIPS for reason in self.skipped
        )
        return {
            "schema": SCHEMA,
            "pairs": self.pairs,
            "reviewed": self.reviewed,
            "skipped": skipped,
            "complete": not incomplete and not self.invalid_options,
            "invalid_options": sorted(set(self.invalid_options)),
            "network": network,
            "artifacts_fetched": self.artifacts_fetched,
            "pairs_with_block": self.pairs_with_block,
            "pairs_with_warn": self.pairs_with_warn,
            "block_deltas": self.block_deltas,
            "warn_deltas": self.warn_deltas,
            "incomplete_results": self.incomplete_results,
            "unchanged_risky_behaviours": sum(self.unchanged.values()),
            "unchanged_risky_by_kind": dict(sorted(self.unchanged.items())),
            "method": (
                "deterministic static diff of the two published artifacts; registry digests "
                "verified; no package code installed, imported or executed"
            ),
        }


@dataclass(frozen=True)
class _Options:
    network: bool = True
    max_pairs: int = DEFAULT_MAX_PAIRS
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_MB * 1024 * 1024
    max_seconds: float = DEFAULT_MAX_SECONDS
    changed_binaries: str = "info"
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    cache_dir: Path | None = None
    trusted_registries: tuple[str, ...] = ()
    private_registries: tuple[str, ...] = ()
    internal_packages: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Pair:
    ecosystem: str
    name: str
    old: str | None
    new: str
    registry: str | None
    integrity: str | None = None
    resolved: str | None = None


class _Skip(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def review_upgrades(pairs: object, options: object = None) -> dict[str, Any]:
    receipt = _Receipt()
    active = _parse_options(options, receipt)
    deadline = time.monotonic() + active.max_seconds
    results: list[dict[str, Any]] = []
    memo: dict[_Pair, dict[str, Any]] = {}
    work_root = active.cache_dir
    temporary = None
    if work_root is None:
        temporary = Path(tempfile.mkdtemp(prefix="ca9-upgrade-review-"))
        work_root = temporary
    try:
        for index, raw in enumerate(_iterate(pairs, receipt)):
            receipt.pairs += 1
            result = _review_one(
                index, raw, active, work_root, temporary is not None, memo, deadline
            )
            if result["status"] == "skipped":
                receipt.skipped[result["reason"]] += 1
            else:
                receipt.reviewed += 1
                receipt.block_deltas += len(result["block"])
                receipt.warn_deltas += len(result["warn"])
                receipt.pairs_with_block += bool(result["block"])
                receipt.pairs_with_warn += bool(result["warn"])
                receipt.unchanged.update(result.get("unchanged_risky_by_kind", {}))
                receipt.incomplete_results += not result.get("complete", True)
                receipt.artifacts_fetched += result.pop("_fetched", 0)
            results.append(result)
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return {"results": results, "receipt": receipt.to_dict(active.network)}


def _iterate(pairs: object, receipt: _Receipt) -> Iterable[object]:
    if isinstance(pairs, (str, bytes, Mapping)) or not isinstance(pairs, Iterable):
        receipt.skipped["malformed_input"] += 1
        return
    try:
        iterator = iter(pairs)
    except Exception:
        receipt.skipped["malformed_input"] += 1
        return
    while True:
        try:
            item = next(iterator)
        except StopIteration:
            return
        except Exception:
            receipt.skipped["malformed_input"] += 1
            return
        yield item


def _review_one(
    index: int,
    raw: object,
    options: _Options,
    work_root: Path,
    cleanup: bool,
    memo: dict[_Pair, dict[str, Any]],
    deadline: float,
) -> dict[str, Any]:
    echo = _echo(raw)
    try:
        pair = _parse_pair(raw)
        if index >= options.max_pairs:
            raise _Skip("max_pairs", f"only the first {options.max_pairs} pairs are reviewed")
        if pair.old == pair.new:
            raise _Skip("same_version")
        if pair in memo:
            cached = dict(memo[pair])
            cached.pop("_fetched", None)
            return cached
        _check_policy(pair, options)
        if not options.network:
            raise _Skip("network_disabled", "artifacts must be fetched from the registry")
        if time.monotonic() >= deadline:
            raise _Skip("timeout", f"the {options.max_seconds:g}s review deadline was reached")
        result = _review_pair(pair, options, work_root, cleanup, deadline)
    except (fetch.TransferTimeout, AnalysisTimeout) as exc:
        return {
            **echo,
            "status": "skipped",
            "reason": "timeout",
            "detail": str(exc)[:300],
            "block": [],
            "warn": [],
        }
    except _Skip as skip:
        skipped = {**echo, "status": "skipped", "reason": skip.reason, "block": [], "warn": []}
        if skip.detail:
            skipped["detail"] = skip.detail
        return skipped
    except Exception as exc:
        return {
            **echo,
            "status": "skipped",
            "reason": "review_error",
            "detail": f"{type(exc).__name__}: {exc}"[:300],
            "block": [],
            "warn": [],
        }
    memo[pair] = result
    return result


def _echo(raw: object) -> dict[str, Any]:
    values: dict[str, Any] = {"ecosystem": None, "name": None, "old": None, "new": None}
    if isinstance(raw, Mapping) and "old" in raw and raw.get("old") is None:
        values["basis"] = "new_package"
    if isinstance(raw, Mapping):
        for key in values:
            value = raw.get(key)
            if isinstance(value, str):
                values[key] = value.strip()
        ecosystem = values["ecosystem"]
        if isinstance(ecosystem, str) and ecosystem.lower() in _ECOSYSTEMS:
            values["ecosystem"] = _ECOSYSTEMS[ecosystem.lower()]
    return values


def _parse_pair(raw: object) -> _Pair:
    if not isinstance(raw, Mapping):
        raise _Skip("invalid_pair", "pair must be an object")
    ecosystem = raw.get("ecosystem")
    if not isinstance(ecosystem, str) or ecosystem.strip().lower() not in _ECOSYSTEMS:
        raise _Skip("unsupported_ecosystem", "only npm and pypi upgrades are reviewed")
    values: dict[str, str | None] = {"old": None}
    keys = ("name", "old", "new")
    if "old" in raw and raw.get("old") is None:
        keys = ("name", "new")
    for key in keys:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 214:
            raise _Skip("invalid_pair", f"{key} must be a non-empty string")
        if any(ord(char) <= 32 or ord(char) == 127 for char in value.strip()):
            raise _Skip("invalid_pair", f"{key} contains whitespace or control characters")
        values[key] = value.strip()
    registry = raw.get("registry")
    if registry is not None and (not isinstance(registry, str) or not registry.strip()):
        raise _Skip("invalid_pair", "registry must be a URL string when given")
    if isinstance(registry, str):
        registry = registry.strip()
    normalized = _ECOSYSTEMS[ecosystem.strip().lower()]
    name = values["name"] or ""
    new = values["new"] or ""
    old = values["old"]
    if not _NAMES[normalized].fullmatch(name):
        raise _Skip("invalid_pair", f"invalid {normalized} package name")
    if not _VERSION.fullmatch(new) or (old is not None and not _VERSION.fullmatch(old)):
        raise _Skip("invalid_pair", "versions must be exact registry versions")
    lock = {}
    for key in ("integrity", "resolved"):
        value = raw.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > 4096):
            raise _Skip("invalid_pair", f"{key} must be a string when given")
        if isinstance(value, str) and value.strip():
            lock[key] = value.strip()
    return _Pair(normalized, name, old, new, registry, **lock)


def _check_policy(pair: _Pair, options: _Options) -> None:
    public = is_public_registry(pair.ecosystem, pair.registry)
    if not public:
        registry = pair.registry or ""
        if not registry.lower().startswith("https://") or not (
            registry_matches(registry, options.private_registries)
            or registry_matches(registry, options.trusted_registries)
        ):
            raise _Skip(
                "untrusted_registry",
                "the registry is not HTTPS or not listed in trusted_registries/private_registries",
            )
    if public and internal_pattern_for(pair.name, options.internal_packages) is not None:
        raise _Skip(
            "internal_package",
            "internal package names are never looked up on a public registry",
        )


def _scan_config(
    options: _Options, cache_dir: Path, deadline: float | None = None
) -> fetch.ArtifactScanConfig:
    trusted = tuple(
        value
        for value in (*options.trusted_registries, *options.private_registries)
        if value.lower().startswith("https://")
    )
    return fetch.ArtifactScanConfig(
        cache_dir=cache_dir,
        max_artifact_bytes=options.max_artifact_bytes,
        max_extracted_files=MAX_EXTRACTED_FILES,
        trusted_indexes=trusted,
        private_indexes=tuple(
            value for value in options.private_registries if value.lower().startswith("https://")
        ),
        allowed_local_roots=(),
        request_timeout=options.request_timeout,
        deadline=deadline,
    )


def _review_pair(
    pair: _Pair, options: _Options, work_root: Path, cleanup: bool, deadline: float
) -> dict[str, Any]:
    pair_dir = work_root
    if cleanup:
        pair_dir = Path(tempfile.mkdtemp(prefix="pair-", dir=work_root))
    config = _scan_config(options, pair_dir, deadline)
    try:
        if pair.old is None:
            return _review_new_package(pair, options, config, deadline)
        comparisons, served = _release_files(pair, config)
        _check_sizes(tuple(file for both in comparisons for file in both), options)
        snapshots: dict[str, tuple[Any, list[str]]] = {}
        diffs = []
        for old_file, new_file in comparisons:
            old_snapshot = _cached_snapshot(snapshots, pair, pair.old, old_file, config)
            new_snapshot = _cached_snapshot(snapshots, pair, pair.new, new_file, config)
            diffs.append(
                diff_artifacts(
                    old_snapshot,
                    new_snapshot,
                    pair.ecosystem,
                    deadline=deadline,
                    changed_binaries=options.changed_binaries,
                )
            )
        old_file, new_file = comparisons[0]
        block, warn, info = _merged(diffs)
        publisher_warn, publisher_info = _publisher_deltas(pair, old_file, new_file)
        lock_block, lock_notes = _lockfile_check(pair, served, new_file)
        result = _result(
            pair,
            "upgrade",
            [*block, *lock_block],
            [*warn, *publisher_warn],
            [*info, *publisher_info],
            WARN_KINDS,
        )
        result["unchanged_risky"] = sum(diffs[0].unchanged_risky.values())
        result["unchanged_risky_by_kind"] = dict(sorted(diffs[0].unchanged_risky.items()))
        result["artifacts"] = {
            "basis": new_file.basis,
            "old": old_file.describe(),
            "new": new_file.describe(),
        }
        if len(comparisons) > 1:
            result["artifacts"]["also"] = [
                {"basis": new.basis, "old": old.describe(), "new": new.describe()}
                for old, new in comparisons[1:]
            ]
        result["_fetched"] = len(snapshots)
        notes = [note for _snapshot, extra in snapshots.values() for note in extra]
        _finish(result, pair, new_file, diffs, [*notes, *lock_notes])
        return result
    finally:
        if cleanup:
            shutil.rmtree(pair_dir, ignore_errors=True)


def _cached_snapshot(
    snapshots: dict[str, tuple[Any, list[str]]],
    pair: _Pair,
    version: str,
    release: ReleaseFile,
    config: fetch.ArtifactScanConfig,
) -> Any:
    if release.url not in snapshots:
        snapshots[release.url] = _snapshot(pair, version, release, config)
    return snapshots[release.url][0]


def _merged(diffs: list[Any]) -> tuple[list, list, list]:
    merged: tuple[list, list, list] = ([], [], [])
    seen: set[tuple] = set()
    for diff in diffs:
        for target, items in zip(merged, (diff.block, diff.warn, diff.info), strict=True):
            for item in items:
                key = (item["kind"], item["path"], item["line"], item["snippet"])
                if key not in seen:
                    seen.add(key)
                    target.append(item)
    return merged


def _finish(
    result: dict[str, Any], pair: _Pair, release: ReleaseFile, diffs: list[Any], notes: list[str]
) -> None:
    incomplete = sorted({reason for diff in diffs for reason in diff.incomplete})
    limitations = [*notes, *incomplete, *(item for diff in diffs for item in diff.limitations)]
    if pair.ecosystem == "pypi" and release.kind == "wheel":
        limitations.append(SDIST_LIMITATION)
    if limitations:
        result["limitations"] = sorted(set(limitations))
    result["complete"] = not incomplete


def _review_new_package(
    pair: _Pair, options: _Options, config: fetch.ArtifactScanConfig, deadline: float
) -> dict[str, Any]:
    new_file, served = _new_release_file(pair, config)
    _check_sizes((new_file,), options)
    snapshot, notes = _snapshot(pair, pair.new, new_file, config)
    diff = diff_new_package(snapshot, pair.ecosystem, deadline=deadline)
    lock_block, lock_notes = _lockfile_check(pair, served, new_file)
    result = _result(
        pair,
        "new_package",
        [*diff.block, *lock_block],
        diff.warn,
        diff.info,
        NEW_PACKAGE_WARN_KINDS,
    )
    result["artifacts"] = {"basis": new_file.basis, "new": new_file.describe()}
    result["_fetched"] = 1
    _finish(result, pair, new_file, [diff], [*notes, *lock_notes])
    return result


def _result(
    pair: _Pair,
    basis: str,
    block: list[dict[str, Any]],
    warn: list[dict[str, Any]],
    info: list[dict[str, Any]],
    warn_kinds: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "ecosystem": pair.ecosystem,
        "name": pair.name,
        "old": pair.old,
        "new": pair.new,
        "status": "reviewed",
        "basis": basis,
        "block": sorted((item for item in block if item["kind"] in BLOCK_KINDS), key=_delta_order),
        "warn": sorted((item for item in warn if item["kind"] in warn_kinds), key=_delta_order),
        "info": sorted(info, key=_delta_order),
    }


def _lockfile_check(
    pair: _Pair, served: set[tuple[str, str]], release: ReleaseFile
) -> tuple[list[dict[str, Any]], list[str]]:
    """A lockfile digest the registry does not serve for this version means other bytes."""
    notes: list[str] = []
    block: list[dict[str, Any]] = []
    if pair.resolved and pair.resolved.split("?", 1)[0] != release.url.split("?", 1)[0]:
        notes.append(
            "lockfile resolved URL differs from the registry file reviewed; the lockfile "
            "artifact itself was not fetched"
        )
    if not pair.integrity:
        return block, notes
    pinned = _digests(pair.integrity)
    algorithms = {algorithm for algorithm, _value in served}
    comparable = {item for item in pinned if item[0] in algorithms}
    if not comparable:
        notes.append("lockfile integrity uses no digest algorithm the registry lists")
        return block, notes
    if not comparable & served:
        block.append(
            {
                "kind": "lockfile_artifact_mismatch",
                "path": "(lockfile)",
                "line": None,
                "snippet": pair.integrity[:200],
                "detail": "the lockfile digest does not match any file the registry serves for "
                "this version: the locked artifact is not the one reviewed",
            }
        )
    return block, notes


def _digests(value: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for token in value.replace(",", " ").split():
        sri = re.fullmatch(r"(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})", token)
        if sri is not None:
            try:
                found.add((sri.group(1), base64.b64decode(sri.group(2), validate=True).hex()))
            except (binascii.Error, ValueError):
                continue
            continue
        hexed = re.fullmatch(r"(sha1|sha256|sha384|sha512)[:=]([0-9a-fA-F]+)", token)
        if hexed is not None:
            found.add((hexed.group(1), hexed.group(2).lower()))
        elif re.fullmatch(r"[0-9a-fA-F]{64}", token):
            found.add(("sha256", token.lower()))
    return found


def _check_sizes(releases: tuple[ReleaseFile, ...], options: _Options) -> None:
    for release in releases:
        if release.size is not None and release.size > options.max_artifact_bytes:
            raise _Skip(
                "artifact_too_large",
                f"{release.filename} is {release.size} bytes; max_artifact_mb is "
                f"{options.max_artifact_bytes // (1024 * 1024)}",
            )


def _new_release_file(
    pair: _Pair, config: fetch.ArtifactScanConfig
) -> tuple[ReleaseFile, set[tuple[str, str]]]:
    try:
        if pair.ecosystem == "npm":
            release = _side(npm_release, pair, pair.new, config)
            return release, _digests(release.hash)
        entries = _side(pypi_release_entries, pair, pair.new, config)
    except fetch._UntrustedArtifactURL as exc:
        raise _Skip("untrusted_registry", str(exc)) from None
    served = {("sha256", entry["sha256"]) for entry in entries}
    choice = pip_choice(entries)
    if choice is None:
        selection = select_pypi_pair(entries, entries)
        if selection is None:
            raise _Skip("no_comparable_artifacts", "the release has no wheel or sdist to inspect")
        choice = (selection[1], selection[2])
    return release_file(choice[0], choice[1]), served


def _delta_order(item: dict[str, Any]) -> tuple:
    return (item["kind"], item["path"], item["line"] or 0, item["snippet"])


def _release_files(
    pair: _Pair, config: fetch.ArtifactScanConfig
) -> tuple[list[tuple[ReleaseFile, ReleaseFile]], set[tuple[str, str]]]:
    """Files to compare (what pip installs here first) and the digests the registry serves."""
    old_version = pair.old or ""
    try:
        if pair.ecosystem == "npm":
            old_file = _side(npm_release, pair, old_version, config)
            new_file = _side(npm_release, pair, pair.new, config)
            return [(old_file, new_file)], _digests(new_file.hash)
        old_entries = _side(pypi_release_entries, pair, old_version, config)
        new_entries = _side(pypi_release_entries, pair, pair.new, config)
    except fetch._UntrustedArtifactURL as exc:
        raise _Skip("untrusted_registry", str(exc)) from None
    served = {("sha256", entry["sha256"]) for entry in new_entries}
    pairs = comparable_pairs(old_entries, new_entries)
    if not pairs:
        raise _Skip(
            "no_comparable_artifacts",
            "no wheel installs on this machine and the releases share no wheel or sdist",
        )
    comparisons = [
        (release_file(old, basis), release_file(new, basis)) for old, new, basis in pairs
    ]
    old_file, new_file = comparisons[0]
    if is_public_registry("pypi", pair.registry):
        publishers = []
        for version, release in ((old_version, old_file), (pair.new, new_file)):
            try:
                publishers.append(
                    pypi_provenance_publisher(pair.name, version, release.filename, config)
                )
            except (OSError, ValueError, http.client.HTTPException):
                publishers.append({"lookup": "failed"})
        comparisons[0] = (
            _with_publisher(old_file, publishers[0]),
            _with_publisher(new_file, publishers[1]),
        )
    return comparisons, served


def _with_publisher(release: ReleaseFile, publisher: dict[str, Any] | None) -> ReleaseFile:
    value: dict[str, Any] = {"source": "PyPI provenance", "trusted": None}
    if publisher is not None:
        value = {"source": "PyPI provenance", **publisher}
    return ReleaseFile(
        release.kind,
        release.filename,
        release.url,
        release.hash,
        release.size,
        release.basis,
        value,
    )


def _side(function: Any, pair: _Pair, version: str, config: fetch.ArtifactScanConfig) -> Any:
    side = "old"
    if version == pair.new:
        side = "new"
    try:
        return function(pair.name, version, pair.registry, config)
    except ReleaseUnavailable:
        raise _Skip(
            "release_unavailable",
            f"{pair.name} {version} ({side}) is not published on the registry",
        ) from None
    except ReleaseMetadataError as exc:
        raise _Skip("registry_metadata_invalid", f"{side}: {exc}") from None
    except (fetch._UntrustedArtifactURL, fetch.TransferTimeout):
        raise
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise _Skip("registry_unreachable", f"{side}: {exc}"[:300]) from None


def _snapshot(
    pair: _Pair, version: str, release: ReleaseFile, config: fetch.ArtifactScanConfig
) -> tuple[Any, list[str]]:
    package = Package(
        name=pair.name,
        version=version,
        ecosystem=pair.ecosystem,
        dependency_kind="unknown",
        artifacts=(
            Artifact(kind=release.kind, url=release.url, hash=release.hash, size=release.size),
        ),
    )
    collection = fetch.collect_artifact_snapshots(
        Inventory(repo_path=".", packages=(package,)), config
    )
    notes = []
    for finding in collection.findings:
        signal = finding.signal_type
        reason = str(finding.metadata.get("reason", ""))
        if signal == "artifact_weak_integrity":
            notes.append(f"{release.filename} is verified only by a SHA-1 digest")
            continue
        if signal == "artifact_hash_mismatch":
            raise _Skip(
                "artifact_integrity_failed",
                f"{release.filename} does not match the registry digest",
            )
        if signal == "artifact_untrusted_url":
            raise _Skip("untrusted_registry", reason[:300])
        if signal in {"artifact_unpack_error", "artifact_ambiguous_archive"}:
            raise _Skip("artifact_unpack_failed", f"{release.filename}: {reason}"[:300])
        if "timed out" in reason:
            raise _Skip("timeout", f"{release.filename}: {reason}"[:300])
        if "too large" in reason or "exceeds" in reason:
            raise _Skip("artifact_too_large", f"{release.filename}: {reason}"[:300])
        raise _Skip("artifact_fetch_failed", f"{release.filename}: {reason}"[:300])
    if len(collection.snapshots) != 1:
        raise _Skip("artifact_fetch_failed", f"{release.filename} was not collected")
    return collection.snapshots[0], notes


def _publisher_deltas(
    pair: _Pair, old: ReleaseFile, new: ReleaseFile
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if pair.ecosystem == "npm":
        return _npm_publisher_deltas(pair, old.publisher, new.publisher)
    return _pypi_publisher_deltas(pair, old.publisher, new.publisher)


def _publisher_delta(kind: str, snippet: str, detail: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": REGISTRY_METADATA_PATH,
        "line": None,
        "snippet": snippet[:200],
        "detail": detail,
    }


def _npm_publisher_deltas(
    pair: _Pair, old: dict[str, Any], new: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    warn: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []
    old_name = old.get("name")
    new_name = new.get("name")
    old_trusted = old.get("trusted_publisher")
    new_trusted = new.get("trusted_publisher")
    maintainers = set(old.get("maintainers") or [])
    snippet = f"_npmUser: {new_name or 'unknown'}"
    if old_trusted and not new_trusted:
        warn.append(
            _publisher_delta(
                "publisher_change",
                snippet,
                f"{pair.old} was published by trusted publisher {old_trusted} "
                f"({old_name}); {pair.new} was published by account {new_name or 'unknown'}",
            )
        )
    elif (
        not new_trusted
        and old_name
        and new_name
        and new_name != old_name
        and new_name not in maintainers
    ):
        warn.append(
            _publisher_delta(
                "publisher_change",
                snippet,
                f"{pair.new} was published by {new_name}, who did not publish {pair.old} "
                "and is not among its maintainers",
            )
        )
    elif not new_trusted and old_name == new_name and old.get("email") != new.get("email"):
        if old.get("email") and new.get("email"):
            info.append(
                _publisher_delta(
                    "publisher_email_changed",
                    snippet,
                    f"publisher {new_name} published with a different email address",
                )
            )
    if old.get("provenance") and not new.get("provenance") and not warn:
        info.append(
            _publisher_delta(
                "provenance_dropped",
                "dist.attestations missing",
                f"{pair.old} had npm provenance; {pair.new} has none",
            )
        )
    return warn, info


def _pypi_publisher_deltas(
    pair: _Pair, old: dict[str, Any], new: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    warn: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []
    if old.get("lookup") == "failed" or new.get("lookup") == "failed":
        info.append(
            _publisher_delta(
                "publisher_unknown", "", "PyPI provenance lookup failed; publisher not compared"
            )
        )
        return warn, info
    old_identity = tuple(old.get(key) for key in ("kind", "repository", "workflow"))
    new_identity = tuple(new.get(key) for key in ("kind", "repository", "workflow"))
    old_has = bool(old.get("repository"))
    new_has = bool(new.get("repository"))
    if old_has and new_has and old_identity != new_identity:
        warn.append(
            _publisher_delta(
                "publisher_change",
                f"{new.get('repository')} {new.get('workflow')}",
                f"trusted publisher changed from {old.get('repository')} "
                f"{old.get('workflow')} to {new.get('repository')} {new.get('workflow')}",
            )
        )
    elif old_has and not new_has:
        info.append(
            _publisher_delta(
                "provenance_dropped",
                "",
                f"{pair.old} had PEP 740 provenance from {old.get('repository')}; "
                f"{pair.new} has none",
            )
        )
    elif old_has and new_has and old.get("environment") != new.get("environment"):
        info.append(
            _publisher_delta(
                "publisher_environment_changed",
                str(new.get("environment") or ""),
                f"publish environment changed from {old.get('environment')} to "
                f"{new.get('environment')}",
            )
        )
    return warn, info


def _parse_options(options: object, receipt: _Receipt) -> _Options:
    if options is None:
        return _Options()
    if not isinstance(options, Mapping):
        receipt.invalid_options.append("options")
        return _Options()
    values: dict[str, Any] = {}
    network = options.get("network")
    if network is not None:
        if isinstance(network, bool):
            values["network"] = network
        else:
            receipt.invalid_options.append("network")
    max_pairs = options.get("max_pairs")
    if max_pairs is not None:
        if isinstance(max_pairs, int) and not isinstance(max_pairs, bool) and max_pairs >= 0:
            values["max_pairs"] = max_pairs
        else:
            receipt.invalid_options.append("max_pairs")
    size = options.get("max_artifact_mb")
    if size is not None:
        if isinstance(size, (int, float)) and not isinstance(size, bool) and 0 < size <= 1024:
            values["max_artifact_bytes"] = int(size * 1024 * 1024)
        else:
            receipt.invalid_options.append("max_artifact_mb")
    for key, limit in (("max_seconds", 86400), ("request_timeout", 600)):
        value = options.get(key)
        if value is None:
            continue
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value <= limit:
            values[key] = float(value)
        else:
            receipt.invalid_options.append(key)
    strict_binaries = options.get("warn_on_changed_binaries")
    if strict_binaries is not None:
        if isinstance(strict_binaries, bool):
            values["changed_binaries"] = "warn"
            if not strict_binaries:
                values["changed_binaries"] = "info"
        else:
            receipt.invalid_options.append("warn_on_changed_binaries")
    cache_dir = options.get("cache_dir")
    if cache_dir is not None:
        if isinstance(cache_dir, (str, PurePath)) and str(cache_dir):
            values["cache_dir"] = Path(cache_dir)
        else:
            receipt.invalid_options.append("cache_dir")
    for key in ("trusted_registries", "private_registries", "internal_packages"):
        value = options.get(key)
        if value is None:
            continue
        parsed = _strings(value)
        if parsed is None:
            receipt.invalid_options.append(key)
        else:
            values[key] = parsed
    return _Options(**values)


def _strings(value: object) -> tuple[str, ...] | None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        return None
    items = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or re.search(r"\s", item.strip()):
            return None
        items.append(item.strip())
    return tuple(items)
