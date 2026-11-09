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
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import unquote, urlsplit

from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from ca9.analyzers.supply_chain import internal_pattern_for, registry_matches
from ca9.artifacts import fetch
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.artifacts.partial import ByteBudget, OverBudget, PartialWheel, read_wheel, wheel_names
from ca9.artifacts.releases import (
    ReleaseFile,
    ReleaseMetadataError,
    ReleaseUnavailable,
    comparable_pairs,
    counterpart,
    is_public_registry,
    mainstream_wheel,
    npm_release,
    other_wheels,
    pip_choice,
    previous_release,
    pure_wheels,
    pypi_provenance_publisher,
    pypi_release_entries,
    registry_releases,
    release_file,
    select_pypi_pair,
)
from ca9.core.models import Artifact, Inventory, Package
from ca9.review import code_context
from ca9.review.dependencies import npm_satisfies, resolve, youth
from ca9.review.upgrade_rules import (
    BLOCK_KINDS,
    WARN_KINDS,
    AnalysisTimeout,
    DiffResult,
    _native_identity,
    analysis_cache,
    content_digest,
    declared_dependencies,
    diff_artifacts,
    diff_new_package,
    native_head,
    native_name,
    native_paths,
    paired_files,
)

SCHEMA = "ca9.upgrade_review.v1"
DEFAULT_MAX_PAIRS = 50
DEFAULT_MAX_ARTIFACT_MB = 100
DEFAULT_MAX_RELEASE_MB = 400
DEFAULT_MAX_DEPENDENCY_REVIEWS = 10
MAX_DEPENDENCY_LOOKUPS_PER_PAIR = 5
MAX_UNSEEN_LISTED = 10
DEFAULT_MAX_SECONDS = 120
DEFAULT_REQUEST_TIMEOUT = 20
OTHER_WHEEL_BASIS = "other wheel of the release (installed on other platforms)"
SDIST_LIMITATION = "sdist not compared: a payload present only in the sdist would not be seen"
MAX_EXTRACTED_FILES = 20000
REGISTRY_METADATA_PATH = "(registry metadata)"
_ECOSYSTEMS = {"npm": "npm", "pypi": "pypi"}
_NATIVE_KINDS = frozenset({"new_native_binary", "native_binary_changed"})
_WHEEL_BOOKKEEPING = re.compile(r"[^/]+\.dist-info/(?:RECORD|WHEEL)")
_NEWLINE_BLIND_SUFFIXES = (".py", ".pyi", ".pth")
_PREFETCH = 4
_SOURCE_COMPARE_BYTES = 8 * 1024 * 1024
_NON_BLOCKING_SKIPS = frozenset({"same_version", "internal_package", "private_registry"})
_REGISTRY_MODES = frozenset({"exclusive", "merged"})
_CREDENTIALS_RE = re.compile(r"HTTP 40[13]\b")
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
    first_release_reviews: int = 0
    dependency_reviews: int = 0
    context_lines: int | None = None

    def to_dict(self, network: bool) -> dict[str, Any]:
        skipped = [
            {"reason": reason, "count": count} for reason, count in sorted(self.skipped.items())
        ]
        incomplete = self.incomplete_results > 0 or any(
            reason not in _NON_BLOCKING_SKIPS for reason in self.skipped
        )
        receipt = {
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
            "first_release_reviews": self.first_release_reviews,
            "dependency_reviews": self.dependency_reviews,
            "unchanged_risky_behaviours": sum(self.unchanged.values()),
            "unchanged_risky_by_kind": dict(sorted(self.unchanged.items())),
            "method": (
                "deterministic static diff of the two published artifacts; registry digests "
                "verified; no package code installed, imported or executed"
            ),
        }
        if self.context_lines is not None:
            receipt["context_lines"] = self.context_lines
        return receipt


@dataclass
class _Budget:
    """Dependency first-release reviews left for this call."""

    remaining: int = DEFAULT_MAX_DEPENDENCY_REVIEWS


@dataclass(frozen=True)
class _Options:
    network: bool = True
    max_pairs: int = DEFAULT_MAX_PAIRS
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_MB * 1024 * 1024
    max_release_bytes: int = DEFAULT_MAX_RELEASE_MB * 1024 * 1024
    max_seconds: float = DEFAULT_MAX_SECONDS
    changed_binaries: str = "info"
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    cache_dir: Path | None = None
    trusted_registries: tuple[str, ...] = ()
    private_registries: tuple[str, ...] = ()
    internal_packages: tuple[str, ...] = ()
    max_dependency_reviews: int = DEFAULT_MAX_DEPENDENCY_REVIEWS
    budget: _Budget | None = None
    context_lines: int = 0
    identity_diff_bytes: int = 0


@dataclass(frozen=True)
class _Pair:
    ecosystem: str
    name: str
    old: str | None
    new: str
    registry: str | None
    integrity: str | None = None
    resolved: str | None = None
    registry_mode: str | None = None
    added: bool = False


@dataclass(frozen=True)
class _Served:
    """Digests and URLs of the files the registry serves for the new version."""

    digests: frozenset[tuple[str, str]]
    urls: frozenset[str]


@dataclass(frozen=True)
class _ReleaseContext:
    """What the registry serves for the new version, the release's other wheels with their
    old counterparts, and whether the old release shipped compiled wheels."""

    served: _Served
    extras: list[tuple[ReleaseFile | None, ReleaseFile]] = field(default_factory=list)
    native_release: bool = False


class _Skip(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class _Unseen(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _OtherWheels:
    """What the review of a release's other wheels found: diffs of the wheels reviewed
    against their old counterparts, wheels left unseen, wheels for uncommon platforms
    (listed, not reviewed) and wheels whose code matched a reviewed wheel."""

    diffs: list[DiffResult] = field(default_factory=list)
    unseen: list[str] = field(default_factory=list)
    uncommon: list[str] = field(default_factory=list)
    same_code: list[tuple[ReleaseFile, ReleaseFile]] = field(default_factory=list)


def review_upgrades(pairs: object, options: object = None) -> dict[str, Any]:
    receipt = _Receipt()
    active = _parse_options(options, receipt)
    active = replace(active, budget=_Budget(active.max_dependency_reviews))
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
                receipt.first_release_reviews += bool(result.get("first_release"))
                receipt.dependency_reviews += sum(
                    item.get("status") == "reviewed"
                    for item in result.get("dependency_reviews", [])
                )
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
        same = pair.old == pair.new
        if same and not (pair.integrity or pair.resolved):
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
        if same:
            result = _review_lockfile(pair, options, work_root, deadline)
        elif pair.old is None and pair.added:
            result = _review_added(pair, options, work_root, cleanup, deadline)
        else:
            result = _review_pair(pair, options, work_root, cleanup, deadline)
        if pair.added:
            result["added"] = True
        if options.context_lines:
            _cap_contexts(result)
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


def _first_release(raw: Mapping[str, Any]) -> bool:
    """A pair with no earlier version: ``old`` missing, None or blank."""
    old = raw.get("old")
    return old is None or (isinstance(old, str) and not old.strip())


def _echo(raw: object) -> dict[str, Any]:
    values: dict[str, Any] = {"ecosystem": None, "name": None, "old": None, "new": None}
    if isinstance(raw, Mapping) and raw.get("added") is True:
        values["added"] = True
    elif isinstance(raw, Mapping) and _first_release(raw):
        values["basis"] = "new_package"
    if isinstance(raw, Mapping):
        for key in values:
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
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
    if _first_release(raw):
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
    mode = raw.get("registry_mode")
    if mode is not None and mode not in _REGISTRY_MODES:
        raise _Skip("invalid_pair", "registry_mode must be exclusive or merged when given")
    added = raw.get("added")
    if added is not None and not isinstance(added, bool):
        raise _Skip("invalid_pair", "added must be true or false when given")
    return _Pair(
        normalized, name, old, new, registry, registry_mode=mode, added=added is True, **lock
    )


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
    if (
        public
        and pair.resolved
        and pair.registry_mode != "merged"
        and registry_matches(pair.resolved, options.private_registries)
    ):
        raise _Skip(
            "private_registry",
            "the lockfile resolves this entry from a private registry; it is never looked up "
            "on a public registry",
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
        comparisons, context = _release_files(pair, config)
        served = context.served
        extras = context.extras
        _check_sizes(comparisons[0], options)
        oversized = [
            new
            for old, new in comparisons[1:]
            if _too_large(old, options) or _too_large(new, options)
        ]
        comparisons = [
            comparisons[0],
            *(item for item in comparisons[1:] if item[1] not in oversized),
        ]
        snapshots: dict[str, tuple[Any, list[str]]] = {}
        cache = analysis_cache(deadline)
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
                    native_release=context.native_release,
                    cache=cache,
                    context_lines=options.context_lines,
                )
            )
        others = _other_wheel_diffs(
            pair,
            extras,
            snapshots,
            config,
            options,
            deadline,
            context.native_release,
            reviewed=[new for _old, new in comparisons],
            cache=cache,
        )
        unseen = [f"{new.filename} (over max_artifact_mb)" for new in oversized] + others.unseen
        diffs.extend(others.diffs)
        old_file, new_file = comparisons[0]
        block, warn, info = _merged(diffs)
        publisher_warn, publisher_info = _publisher_deltas(pair, old_file, new_file)
        lock_block, lock_notes, lock_incomplete = _lockfile_check(pair, served)
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
        also = [
            {"basis": new.basis, "old": old.describe(), "new": new.describe()}
            for old, new in comparisons[1:]
        ]
        also.extend(
            {"basis": new.basis, "old": old.describe(), "new": new.describe()}
            for old, new in extras
            if old is not None and new.url in snapshots
        )
        also.extend(_same_code_entries(others))
        if also:
            result["artifacts"]["also"] = also
        result["_fetched"] = len(snapshots)
        notes = [note for _snapshot, extra in snapshots.values() for note in extra]
        _finish(
            result,
            pair,
            new_file,
            diffs,
            [*notes, *lock_notes],
            unseen,
            lock_incomplete,
            others.uncommon,
        )
        old_dependencies = declared_dependencies(snapshots[old_file.url][0], pair.ecosystem)
        added = {
            name: spec
            for name, spec in declared_dependencies(
                snapshots[new_file.url][0], pair.ecosystem
            ).items()
            if name not in old_dependencies
        }
        _review_new_dependencies(result, pair, added, options, config, deadline)
        if options.identity_diff_bytes and _identity_changed(result):
            diff, truncated = _identity_diff(
                snapshots[old_file.url][0], snapshots[new_file.url][0], pair, options, deadline
            )
            result["identity_diff"] = diff
            result["identity_diff_truncated"] = truncated
        return result
    finally:
        if cleanup:
            shutil.rmtree(pair_dir, ignore_errors=True)


def _identity_diff(
    old: ArtifactSnapshot,
    new: ArtifactSnapshot,
    pair: _Pair,
    options: _Options,
    deadline: float,
) -> tuple[str, bool]:
    """The identity diff of the compared artifacts; empty and truncated when it could not
    be built, as it is for display and never fails the review."""
    try:
        files = paired_files(old, new, pair.ecosystem)
        return code_context.identity_diff(files, options.identity_diff_bytes, deadline)
    except Exception:
        return "", True


def _cap_contexts(result: dict[str, Any]) -> None:
    """Hold the result's contexts to the per-result cap; when that fails each context is
    replaced by the truncation line, so the cap still holds."""
    deltas = [*result["block"], *result["warn"]]
    try:
        code_context.cap_contexts(deltas)
    except Exception:
        for delta in deltas:
            if "context" in delta:
                delta["context"] = code_context.TRUNCATED


def _identity_changed(result: dict[str, Any]) -> bool:
    """The publisher changed or provenance was dropped (a delta at any level)."""
    return any(
        delta["kind"] in code_context.IDENTITY_KINDS
        for level in ("block", "warn", "info")
        for delta in result[level]
    )


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


def _other_wheel_diffs(
    pair: _Pair,
    extras: list[tuple[ReleaseFile | None, ReleaseFile]],
    snapshots: dict[str, tuple[Any, list[str]]],
    config: fetch.ArtifactScanConfig,
    options: _Options,
    deadline: float,
    native_release: bool = False,
    *,
    reviewed: list[ReleaseFile],
    cache: Any,
) -> _OtherWheels:
    """Review the release's other wheels within ``max_release_mb`` and the deadline.

    Wheels for uncommon platforms are listed, not reviewed. A wheel whose files other than
    native binaries match a reviewed wheel of the release (or differ without adding any
    behaviour), and whose binaries are ELF, PE or Mach-O images of modules that wheel or
    the wheel's old counterpart already ships, is covered by that review: it is read by
    byte ranges and its old counterpart is not downloaded. Every other wheel is diffed
    whole against its old counterpart (or against nothing for a first release); wheels
    beyond the budget or deadline are listed unseen."""
    budget = ByteBudget(options.max_release_bytes)
    found = _OtherWheels()
    wheels = [file for file in reviewed if file.kind == "wheel" and file.url in snapshots]
    common = []
    for old_file, new_file in extras:
        if _mainstream(new_file):
            common.append((old_file, new_file))
        else:
            found.uncommon.append(new_file.filename)
    if not common:
        return found
    Path(config.cache_dir).mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="wheels-", dir=config.cache_dir))
    reads = _Reads(config, root, budget, cache)
    try:
        for index, (old_file, new_file) in enumerate(common):
            if wheels:
                reads.ahead(snapshots[wheels[0].url][0], common[index : index + _PREFETCH])
            try:
                if time.monotonic() >= deadline:
                    raise _Unseen("review deadline reached")
                if wheels and _same_code(
                    pair,
                    old_file,
                    new_file,
                    wheels,
                    snapshots,
                    config,
                    options,
                    deadline,
                    reads,
                ):
                    found.same_code.append((wheels[0], new_file))
                    continue
                diff = _whole_wheel_diff(
                    pair,
                    old_file,
                    new_file,
                    snapshots,
                    config,
                    options,
                    deadline,
                    budget,
                    cache,
                    native_release,
                )
            except _Unseen as unseen:
                found.unseen.append(f"{new_file.filename} ({unseen.reason})")
                continue
            except (fetch.TransferTimeout, AnalysisTimeout):
                found.unseen.append(f"{new_file.filename} (timeout)")
                continue
            except _Skip as skip:
                found.unseen.append(f"{new_file.filename} ({skip.reason})")
                continue
            for delta in (*diff.block, *diff.warn, *diff.info):
                delta["detail"] = f"{delta['detail']} (in {new_file.filename})"
            found.diffs.append(diff)
            if new_file.kind == "wheel":
                wheels.append(new_file)
    finally:
        reads.close()
        shutil.rmtree(root, ignore_errors=True)
    return found


class _Reads:
    """Byte-range reads of the release's other wheels, a few ahead of the review so that
    fetching overlaps analysis. Each read is capped at the budget left when it starts and
    charged, in review order, when the review uses it."""

    def __init__(
        self, config: fetch.ArtifactScanConfig, root: Path, budget: ByteBudget, cache: Any
    ) -> None:
        self.config = config
        self.root = root
        self.budget = budget
        self.cache = cache
        self.pool = ThreadPoolExecutor(max_workers=_PREFETCH)
        self.pending: dict[str, Future] = {}
        self.natives: set[str] = set()
        self.expected: dict[str, str] = {}
        self.reference: ArtifactSnapshot | None = None
        self.started = 0

    def ahead(
        self, reference: ArtifactSnapshot, upcoming: list[tuple[ReleaseFile | None, ReleaseFile]]
    ) -> None:
        if self.reference is not reference:
            self.reference = reference
            self.natives = native_paths(reference, self.cache)
            self.expected = {
                file.relative_path: content_digest(file, self.cache)
                for file in reference.files
                if file.relative_path not in self.natives
            }
        for _old, new in upcoming:
            if new.url in self.pending or new.kind != "wheel" or new.size is None:
                continue
            self.pending[new.url] = self._submit(new)

    def take(self, release: ReleaseFile) -> tuple[PartialWheel, Path]:
        """The wheel read in part, charged to the budget; OverBudget when it does not fit."""
        future = self.pending.pop(release.url, None)
        if future is None:
            future = self._submit(release)
        wheel, fetched, directory = future.result()
        if fetched > self.budget.remaining:
            shutil.rmtree(directory, ignore_errors=True)
            raise OverBudget(f"{release.filename} needs more than the bytes left")
        self.budget.remaining -= fetched
        return wheel, directory

    def _submit(self, release: ReleaseFile) -> Future:
        self.started += 1
        directory = self.root / str(self.started)
        return self.pool.submit(
            self._read,
            release,
            directory,
            set(self.natives),
            dict(self.expected),
            self.budget.remaining,
        )

    def _read(
        self,
        release: ReleaseFile,
        directory: Path,
        natives: set[str],
        expected: dict[str, str],
        cap: int,
    ) -> tuple[PartialWheel, int, Path]:
        allowance = ByteBudget(cap)
        directory.mkdir(parents=True, exist_ok=True)
        wheel = read_wheel(
            release.url,
            release.size or 0,
            self.config,
            directory,
            partial=lambda name: native_name(name) or name in natives,
            budget=allowance,
            expected=expected,
        )
        return wheel, cap - allowance.remaining, directory

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)


def _mainstream(release: ReleaseFile) -> bool:
    try:
        tags = parse_wheel_filename(release.filename)[3]
    except InvalidWheelFilename:
        return True
    return mainstream_wheel(tags)


def _whole_wheel_diff(
    pair: _Pair,
    old_file: ReleaseFile | None,
    new_file: ReleaseFile,
    snapshots: dict[str, tuple[Any, list[str]]],
    config: fetch.ArtifactScanConfig,
    options: _Options,
    deadline: float,
    budget: ByteBudget,
    cache: Any,
    native_release: bool,
) -> DiffResult:
    files = [file for file in (old_file, new_file) if file is not None]
    if any(file.size is not None and file.size > options.max_artifact_bytes for file in files):
        raise _Unseen("over max_artifact_mb")
    cost = sum(_fetch_cost(file, snapshots, options) for file in files)
    if cost > budget.remaining:
        raise _Unseen("over max_release_mb")
    budget.remaining -= cost
    new_snapshot = _cached_snapshot(snapshots, pair, pair.new, new_file, config)
    if old_file is None:
        return diff_new_package(
            new_snapshot, pair.ecosystem, deadline=deadline, context_lines=options.context_lines
        )
    old_snapshot = _cached_snapshot(snapshots, pair, pair.old or "", old_file, config)
    return diff_artifacts(
        old_snapshot,
        new_snapshot,
        pair.ecosystem,
        deadline=deadline,
        changed_binaries=options.changed_binaries,
        native_release=native_release,
        cache=cache,
        context_lines=options.context_lines,
    )


def _same_code(
    pair: _Pair,
    old_file: ReleaseFile | None,
    new_file: ReleaseFile,
    wheels: list[ReleaseFile],
    snapshots: dict[str, tuple[Any, list[str]]],
    config: fetch.ArtifactScanConfig,
    options: _Options,
    deadline: float,
    reads: _Reads,
) -> bool:
    """True when ``new_file`` adds nothing to the review of ``wheels[0]``: the same files
    apart from native binaries (and wheel bookkeeping), or a diff against that wheel with
    no delta, and every binary a native image of a module already known."""
    if new_file.kind != "wheel" or new_file.size is None:
        return False
    cache = reads.cache
    reference = snapshots[wheels[0].url][0]
    natives = native_paths(reference, cache)
    known = {
        _native_identity(path)
        for wheel in wheels
        for path in native_paths(snapshots[wheel.url][0], cache)
    }
    try:
        wheel, directory = reads.take(new_file)
    except OverBudget:
        raise _Unseen("over max_release_mb") from None
    except fetch.TransferTimeout:
        raise
    except ValueError:
        return False
    try:
        if not all(native_head(head, wheel.sizes[path]) for path, head in wheel.heads.items()):
            return False
        missing = {_native_identity(path) for path in wheel.heads} - known
        if missing and old_file is not None and old_file.kind == "wheel" and old_file.size:
            try:
                names = wheel_names(old_file.url, old_file.size, config, budget=reads.budget)
            except OverBudget:
                raise _Unseen("over max_release_mb") from None
            except fetch.TransferTimeout:
                raise
            except ValueError:
                return False
            missing -= {_native_identity(name) for name in names if native_name(name)}
        if missing:
            return False
        try:
            candidate, differs = _candidate(reference, wheel, natives, new_file, cache)
        except ValueError:
            return False
        if not differs:
            return True
        diff = diff_artifacts(
            reference,
            candidate,
            pair.ecosystem,
            deadline=deadline,
            changed_binaries=options.changed_binaries,
            cache=cache,
        )
        return not (diff.block or diff.warn or diff.info or diff.incomplete)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _candidate(
    reference: ArtifactSnapshot,
    wheel: Any,
    natives: set[str],
    release: ReleaseFile,
    cache: Any,
) -> tuple[ArtifactSnapshot, bool]:
    """The reference wheel with this wheel's files other than native binaries, and whether
    any of those differ beyond wheel bookkeeping (RECORD, WHEEL)."""
    by_path = {file.relative_path: file for file in reference.files}
    files = [file for file in reference.files if file.relative_path in natives]
    differs = False
    for path, digest in wheel.digests.items():
        known = by_path.get(path)
        location = wheel.files.get(path)
        if known is not None and path not in natives:
            if content_digest(known, cache) == digest or (
                location is not None and _same_source(known.path, location, path)
            ):
                files.append(known)
                continue
        if location is None:
            raise ValueError(f"{path} of {release.filename} was not kept")
        files.append(ArtifactFile(path, location, wheel.sizes[path]))
        differs = differs or not _WHEEL_BOOKKEEPING.fullmatch(path)
    for path in by_path:
        if path not in natives and path not in wheel.digests and path not in wheel.heads:
            differs = differs or not _WHEEL_BOOKKEEPING.fullmatch(path)
    artifact = Artifact(kind="wheel", url=release.url, hash=release.hash, size=release.size)
    return replace(reference, artifact=artifact, files=tuple(files)), differs


def _same_source(reference: Path, other: Path, path: str) -> bool:
    """Python source and .pth files that differ only in CRLF line ends: Python reads both
    with universal newlines, so they run the same code."""
    if not path.lower().endswith(_NEWLINE_BLIND_SUFFIXES):
        return False
    try:
        if reference.stat().st_size > _SOURCE_COMPARE_BYTES:
            return False
        first, second = reference.read_bytes(), other.read_bytes()
    except OSError:
        return False
    return first.replace(b"\r\n", b"\n") == second.replace(b"\r\n", b"\n")


def _same_code_entries(others: _OtherWheels) -> list[dict[str, Any]]:
    return [
        {"basis": new.basis, "new": new.describe(), "same_code_as": reference.filename}
        for reference, new in others.same_code
    ]


def _fetch_cost(
    release: ReleaseFile, snapshots: dict[str, tuple[Any, list[str]]], options: _Options
) -> int:
    if release.url in snapshots:
        return 0
    if release.size is None:
        return options.max_artifact_bytes
    return release.size


def _merged(diffs: list[Any]) -> tuple[list, list, list]:
    """Deltas of every compared file, each once: a native module rebuilt for every wheel
    (``_x.cp312-win_amd64.pyd``, ``_x.cpython-313-darwin.so``) counts as one."""
    merged: tuple[list, list, list] = ([], [], [])
    seen: set[tuple] = set()
    for diff in diffs:
        for target, items in zip(merged, (diff.block, diff.warn, diff.info), strict=True):
            for item in items:
                path = item["path"]
                if item["kind"] in _NATIVE_KINDS:
                    path = _native_identity(path)
                key = (item["kind"], path, item["line"], item["snippet"])
                if key not in seen:
                    seen.add(key)
                    target.append(item)
    return merged


def _finish(
    result: dict[str, Any],
    pair: _Pair,
    release: ReleaseFile,
    diffs: list[Any],
    notes: list[str],
    unseen: list[str] | None = None,
    reasons: list[str] | None = None,
    uncommon: list[str] | None = None,
) -> None:
    """Limitations and completeness. Unseen files of the release make it incomplete;
    wheels for uncommon platforms are named as a limitation only."""
    incomplete = sorted({reason for diff in diffs for reason in diff.incomplete})
    incomplete.extend(reasons or [])
    if unseen:
        incomplete.append(
            f"{len(unseen)} other file(s) of this release were not reviewed, so a payload "
            f"in them would not be seen: {_listed(unseen)}"
        )
    if uncommon:
        notes = [
            *notes,
            f"{len(uncommon)} wheel(s) for uncommon platforms (free-threaded, PyPy or GraalPy "
            "builds, 32-bit or other architectures) were not reviewed, so a payload in them "
            f"would not be seen: {_listed(uncommon)}",
        ]
    limitations = [*notes, *incomplete, *(item for diff in diffs for item in diff.limitations)]
    if pair.ecosystem == "pypi" and release.kind == "wheel":
        limitations.append(SDIST_LIMITATION)
    if limitations:
        result["limitations"] = sorted(set(limitations))
    result["complete"] = not incomplete


def _listed(names: list[str]) -> str:
    listed = ", ".join(names[:MAX_UNSEEN_LISTED])
    if len(names) > MAX_UNSEEN_LISTED:
        listed += f" and {len(names) - MAX_UNSEEN_LISTED} more"
    return listed


def _review_new_package(
    pair: _Pair,
    options: _Options,
    config: fetch.ArtifactScanConfig,
    deadline: float,
    *,
    nested: bool = False,
) -> dict[str, Any]:
    new_file, served, extras = _new_release_file(pair, config)
    _check_sizes((new_file,), options)
    snapshots: dict[str, tuple[Any, list[str]]] = {}
    snapshot = _cached_snapshot(snapshots, pair, pair.new, new_file, config)
    cache = analysis_cache(deadline)
    diffs = [
        diff_new_package(
            snapshot, pair.ecosystem, deadline=deadline, context_lines=options.context_lines
        )
    ]
    others = _other_wheel_diffs(
        pair, extras, snapshots, config, options, deadline, reviewed=[new_file], cache=cache
    )
    diffs.extend(others.diffs)
    block, warn, info = _merged(diffs)
    lock_block, lock_notes, lock_incomplete = _lockfile_check(pair, served)
    result = _result(pair, "new_package", [*block, *lock_block], warn, info, WARN_KINDS)
    result["first_release"] = True
    result["artifacts"] = {"basis": new_file.basis, "new": new_file.describe()}
    also = [
        {"basis": new.basis, "new": new.describe()} for _old, new in extras if new.url in snapshots
    ]
    also.extend(_same_code_entries(others))
    if also:
        result["artifacts"]["also"] = also
    result["_fetched"] = len(snapshots)
    notes = [note for _snapshot, extra in snapshots.values() for note in extra]
    _finish(
        result,
        pair,
        new_file,
        diffs,
        [*notes, *lock_notes],
        others.unseen,
        lock_incomplete,
        others.uncommon,
    )
    if not nested:
        dependencies = declared_dependencies(snapshot, pair.ecosystem)
        _review_new_dependencies(result, pair, dependencies, options, config, deadline)
    return result


def _review_new_dependencies(
    result: dict[str, Any],
    pair: _Pair,
    dependencies: dict[str, str],
    options: _Options,
    config: fetch.ArtifactScanConfig,
    deadline: float,
) -> None:
    """First-release review of dependencies the release adds that are brand-new or young.

    One level only, at most ``MAX_DEPENDENCY_LOOKUPS_PER_PAIR`` registry lookups per pair and
    ``max_dependency_reviews`` reviews per call, within the deadline. Internal names and
    privately resolved entries are never looked up publicly; git, URL and local specs are
    left to new_git_or_url_dependency. A lookup or review that fails is a limitation of the
    pair; the pair itself stays reviewed."""
    budget = options.budget
    reviews: list[dict[str, Any]] = []
    notes: list[str] = []
    lookups = 0
    for name in sorted(dependencies):
        spec = dependencies[name]
        if pair.ecosystem == "npm" and npm_satisfies("0.0.0", spec) is None:
            continue
        probe = _Pair(pair.ecosystem, name, None, "0", pair.registry)
        try:
            _check_policy(probe, options)
        except _Skip:
            continue
        if (
            budget is None
            or budget.remaining <= 0
            or lookups >= MAX_DEPENDENCY_LOOKUPS_PER_PAIR
            or time.monotonic() >= deadline
        ):
            reviews.append(_dependency_entry(name, None, "over_limit"))
            continue
        lookups += 1
        try:
            releases = registry_releases(pair.ecosystem, name, pair.registry, config)
            version = resolve(pair.ecosystem, spec, releases)
            why = None
            if version is not None:
                why = youth(pair.ecosystem, version, releases)
        except (
            ReleaseUnavailable,
            ReleaseMetadataError,
            OSError,
            ValueError,
            http.client.HTTPException,
            fetch._UntrustedArtifactURL,
            fetch.TransferTimeout,
        ) as exc:
            reviews.append(_dependency_entry(name, None, "lookup_failed"))
            notes.append(f"new dependency {name} could not be looked up: {exc}"[:300])
            continue
        if version is None:
            reviews.append(_dependency_entry(name, None, "unresolved"))
            continue
        if why is None:
            reviews.append(_dependency_entry(name, version, "established"))
            continue
        budget.remaining -= 1
        dependency = _Pair(pair.ecosystem, name, None, version, pair.registry)
        try:
            reviewed = _review_new_package(dependency, options, config, deadline, nested=True)
        except (_Skip, fetch.TransferTimeout, AnalysisTimeout) as exc:
            reviews.append(_dependency_entry(name, version, "review_failed", why))
            notes.append(f"new dependency {name} {version} was not reviewed: {exc}"[:300])
            continue
        entry = _dependency_entry(name, version, "reviewed", why)
        entry["block"] = len(reviewed["block"])
        entry["warn"] = len(reviewed["warn"])
        entry["complete"] = reviewed.get("complete", True)
        reviews.append(entry)
        if not entry["complete"]:
            notes.append(
                f"the first-release review of new dependency {name} {version} is incomplete"
            )
        for level in ("block", "warn", "info"):
            for delta in reviewed[level]:
                result[level].append(
                    {
                        **delta,
                        "path": f"{name}@{version}: {delta['path']}",
                        "detail": f"new dependency {name} {version} ({why}): {delta['detail']}",
                    }
                )
            result[level].sort(key=_delta_order)
    if reviews:
        result["dependency_reviews"] = reviews
    if notes:
        result["limitations"] = sorted({*result.get("limitations", []), *notes})


def _dependency_entry(
    name: str, version: str | None, status: str, why: str | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {"name": name, "version": version, "status": status}
    if why is not None:
        entry["why"] = why
    return entry


def _review_added(
    pair: _Pair, options: _Options, work_root: Path, cleanup: bool, deadline: float
) -> dict[str, Any]:
    """A package new to the project (``added: true``, no ``old``): compared with the
    release before it on the registry, so an install hook it has always had is not new.
    Only a package with no earlier release is reviewed as a first release."""
    config = _scan_config(options, work_root, deadline)

    def lookup(name: str, version: str, registry: str | None, config: Any) -> Any:
        return registry_releases(pair.ecosystem, name, registry, config)

    try:
        releases = _side(lookup, pair, pair.new, config)
        previous = previous_release(pair.ecosystem, pair.new, releases)
    except fetch._UntrustedArtifactURL as exc:
        raise _Skip("untrusted_registry", str(exc)) from None
    except ReleaseUnavailable as exc:
        raise _Skip("release_unavailable", str(exc)[:300]) from None
    except ReleaseMetadataError as exc:
        raise _Skip("registry_metadata_invalid", str(exc)[:300]) from None
    if previous is None:
        result = _review_pair(pair, options, work_root, cleanup, deadline)
    else:
        result = _review_pair(replace(pair, old=previous), options, work_root, cleanup, deadline)
        result["old"] = None
        result["old_resolved"] = previous
        result["basis"] = "registry_previous"
    result["added"] = True
    return result


def _review_lockfile(
    pair: _Pair, options: _Options, work_root: Path, deadline: float
) -> dict[str, Any]:
    """Same version on both sides with lockfile pins: the locked digest and URL are checked
    against the files the registry serves for that version. No artifact is downloaded; the
    code did not change, but a swapped tarball or wheel would."""
    config = _scan_config(options, work_root, deadline)
    try:
        if pair.ecosystem == "npm":
            release = _side(npm_release, pair, pair.new, config)
            served = _Served(frozenset(_digests(release.hash)), frozenset({release.url}))
        else:
            served = _pypi_served(_side(pypi_release_entries, pair, pair.new, config))
    except fetch._UntrustedArtifactURL as exc:
        raise _Skip("untrusted_registry", str(exc)) from None
    block, notes, incomplete = _lockfile_check(pair, served)
    result = _result(pair, "lockfile", block, [], [], WARN_KINDS)
    result["artifacts"] = {
        "basis": "same version: lockfile digest and URL checked against the registry"
    }
    if notes or incomplete:
        result["limitations"] = sorted({*notes, *incomplete})
    result["complete"] = not incomplete
    return result


def _pypi_served(entries: list[dict[str, Any]]) -> _Served:
    return _Served(
        frozenset(("sha256", entry["sha256"]) for entry in entries),
        frozenset(entry["url"] for entry in entries),
    )


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
    pair: _Pair, served: _Served
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """(block, notes, incomplete reasons) for the lockfile's pins of this version.

    A lockfile digest the registry does not serve means other bytes. A resolved URL the
    registry does not serve is only safe when a lockfile digest ties it to a served file;
    without one the locked artifact was not reviewed.
    """
    notes: list[str] = []
    block: list[dict[str, Any]] = []
    incomplete: list[str] = []
    verified = False
    if pair.integrity:
        pinned = _digests(pair.integrity)
        algorithms = {algorithm for algorithm, _value in served.digests}
        comparable = {item for item in pinned if item[0] in algorithms}
        if not comparable:
            notes.append("lockfile integrity uses no digest algorithm the registry lists")
        elif not comparable & served.digests:
            block.append(
                {
                    "kind": "lockfile_artifact_mismatch",
                    "path": "(lockfile)",
                    "line": None,
                    "snippet": pair.integrity[:200],
                    "detail": "the lockfile digest does not match any file the registry serves "
                    "for this version: the locked artifact is not the one reviewed",
                }
            )
        else:
            verified = True
    if pair.resolved and _url_key(pair.resolved) not in {_url_key(url) for url in served.urls}:
        if verified:
            notes.append(
                "lockfile resolved URL is not one the registry lists; the lockfile digest "
                "matches a file the registry serves"
            )
        elif not block:
            incomplete.append(
                "lockfile resolved URL is not a file the registry serves for this version and "
                "no lockfile digest ties it to one: the locked artifact was not reviewed"
            )
    return block, notes, incomplete


def _url_key(url: str) -> tuple[str, str]:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return ("", url)
    host = (parts.hostname or "").lower()
    if host == "registry.yarnpkg.com":
        host = "registry.npmjs.org"
    return host, unquote(parts.path)


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


def _too_large(release: ReleaseFile, options: _Options) -> bool:
    return release.size is not None and release.size > options.max_artifact_bytes


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
) -> tuple[ReleaseFile, _Served, list[tuple[ReleaseFile | None, ReleaseFile]]]:
    try:
        if pair.ecosystem == "npm":
            release = _side(npm_release, pair, pair.new, config)
            served = _Served(frozenset(_digests(release.hash)), frozenset({release.url}))
            return release, served, []
        entries = _side(pypi_release_entries, pair, pair.new, config)
    except fetch._UntrustedArtifactURL as exc:
        raise _Skip("untrusted_registry", str(exc)) from None
    served = _pypi_served(entries)
    choice = pip_choice(entries)
    if choice is None:
        selection = select_pypi_pair(entries, entries)
        if selection is None:
            raise _Skip("no_comparable_artifacts", "the release has no wheel or sdist to inspect")
        choice = (selection[1], selection[2])
    extras: list[tuple[ReleaseFile | None, ReleaseFile]] = [
        (None, release_file(entry, OTHER_WHEEL_BASIS))
        for entry in other_wheels(entries, [choice[0]])
    ]
    return release_file(choice[0], choice[1]), served, extras


def _delta_order(item: dict[str, Any]) -> tuple:
    return (item["kind"], item["path"], item["line"] or 0, item["snippet"])


def _release_files(
    pair: _Pair, config: fetch.ArtifactScanConfig
) -> tuple[list[tuple[ReleaseFile, ReleaseFile]], _ReleaseContext]:
    """Files to compare (what pip installs here first) and the release context: the
    digests the registry serves, the other wheels with their old counterparts, and
    whether the old release shipped compiled wheels."""
    old_version = pair.old or ""
    try:
        if pair.ecosystem == "npm":
            old_file = _side(npm_release, pair, old_version, config)
            new_file = _side(npm_release, pair, pair.new, config)
            served = _Served(frozenset(_digests(new_file.hash)), frozenset({new_file.url}))
            return [(old_file, new_file)], _ReleaseContext(served)
        old_entries = _side(pypi_release_entries, pair, old_version, config)
        new_entries = _side(pypi_release_entries, pair, pair.new, config)
    except fetch._UntrustedArtifactURL as exc:
        raise _Skip("untrusted_registry", str(exc)) from None
    served = _pypi_served(new_entries)
    pairs = comparable_pairs(old_entries, new_entries)
    if not pairs:
        raise _Skip(
            "no_comparable_artifacts",
            "no wheel installs on this machine and the releases share no wheel or sdist",
        )
    comparisons = [
        (release_file(old, basis), release_file(new, basis)) for old, new, basis in pairs
    ]
    extras: list[tuple[ReleaseFile | None, ReleaseFile]] = []
    for entry in other_wheels(new_entries, [new for _old, new, _basis in pairs]):
        old_entry = counterpart(old_entries, entry)
        old_release = None
        if old_entry is not None:
            old_release = release_file(old_entry, OTHER_WHEEL_BASIS)
        extras.append((old_release, release_file(entry, OTHER_WHEEL_BASIS)))
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
    pure_names = {entry["filename"] for entry in pure_wheels(old_entries)}
    native_release = any(
        entry["kind"] == "wheel" and entry["filename"] not in pure_names for entry in old_entries
    )
    return comparisons, _ReleaseContext(served, extras, native_release)


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
        if (
            pair.registry
            and _CREDENTIALS_RE.match(str(exc))
            and registry_matches(pair.registry, config.private_indexes)
        ):
            raise _Skip(
                "private_registry",
                f"{side}: the private registry needs credentials ({exc})"[:300],
            ) from None
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
        warn.append(
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
        warn.append(
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
    reviews = options.get("max_dependency_reviews")
    if reviews is not None:
        if isinstance(reviews, int) and not isinstance(reviews, bool) and 0 <= reviews <= 100:
            values["max_dependency_reviews"] = reviews
        else:
            receipt.invalid_options.append("max_dependency_reviews")
    release = options.get("max_release_mb")
    if release is not None:
        if (
            isinstance(release, (int, float))
            and not isinstance(release, bool)
            and 0 < release <= 10240
        ):
            values["max_release_bytes"] = int(release * 1024 * 1024)
        else:
            receipt.invalid_options.append("max_release_mb")
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
    for key, limit in (
        ("context_lines", code_context.MAX_CONTEXT_LINES),
        ("identity_diff_bytes", code_context.MAX_IDENTITY_DIFF_BYTES),
    ):
        value = options.get(key)
        if value is None:
            continue
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= limit:
            values[key] = value
        else:
            receipt.invalid_options.append(key)
    if "context_lines" in options or "identity_diff_bytes" in options:
        receipt.context_lines = values.get("context_lines", 0)
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
