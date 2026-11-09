from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packaging.utils import canonicalize_name

from ca9.core.models import Evidence, Finding, Package, RiskSignal, SourceEvidence, package_key
from ca9.package_policy import PackagePolicy
from ca9.version_order import osv_ranges_include, same_version

FEED_SCHEMA = "ca9.feed.v1"
FEED_STATUS_SCHEMA = "ca9.feed.status.v1"
REQUIRED_DATASETS = ("npm-malware", "pypi-malware", "npm-releases", "pypi-releases")
RANGE_DATASETS = ("npm-malware-ranges", "pypi-malware-ranges")
SUSPICIOUS_DATASETS = ("npm-suspicious", "pypi-suspicious")
OPTIONAL_DATASETS = (*RANGE_DATASETS, *SUSPICIOUS_DATASETS)
SUSPICIOUS_VERDICTS = frozenset({"block", "warn"})
FEED_ATTESTATION_REPO = "duriantaco/ca9"
FEED_SIGNER_WORKFLOW = "duriantaco/ca9/.github/workflows/feed.yml"
FEED_SIGNER_REF = "refs/heads/main"
ATTESTATION_TIMEOUT_SECONDS = 120
MAX_RELEASE_AGE_LOOKUPS = 1000
RELEASE_AGE_WORKERS = 8
CURRENT_POINTER = "current.json"
SNAPSHOT_FILE = "snapshot.json"
# Default hosted feed used by `ca9 feed update` when no source is given.
# Published hourly by .github/workflows/feed.yml to the `feed` branch.
# Override with the CA9_FEED_URL environment variable or `--from`.
DEFAULT_FEED_URL = "https://raw.githubusercontent.com/duriantaco/ca9/feed/latest.json"
# Install-time limits. Feeds are not signed yet, so these bound what a hostile or
# broken source can do: oversized downloads, rollback to an older snapshot, a
# far-future created_at, or an expiry that keeps stale data "current" forever.
MAX_FEED_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_FEED_LIFETIME = timedelta(days=30)
MAX_FEED_CLOCK_SKEW = timedelta(hours=24)
_DOWNLOAD_CHUNK_BYTES = 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30.0
REFRESH_STATE_FILE = "refresh.json"
REFRESH_RECHECK = timedelta(hours=1)
REFRESH_STAGING_PREFIX = ".refresh-"
# In-process caches keyed by file identity (path, device, inode, size, mtime), so a
# rewritten dataset is re-verified and re-parsed while repeat lookups stay cheap.
_CACHE_LOCK = threading.Lock()
_VERIFIED_FILES: OrderedDict[tuple[Any, ...], str] = OrderedDict()
_LOADED_DATASETS: OrderedDict[tuple[Any, ...], _LoadedDataset] = OrderedDict()
_VERIFIED_FILES_MAX = 64
_LOADED_DATASETS_MAX = 8


class FeedError(ValueError):
    pass


class FeedMissingError(FeedError):
    pass


class FeedTamperError(FeedError):
    pass


@dataclass(frozen=True)
class FeedSnapshot:
    cache_dir: Path
    snapshot_dir: Path
    snapshot_id: str
    schema: str
    created_at: str
    expires_at: str
    content_hashes: dict[str, dict[str, Any]]
    source: str | None = None
    updated_at: str | None = None
    osv_built_at: str | None = None

    def effective_expires_at(self) -> datetime:
        """``expires_at``, capped at ``created_at + MAX_FEED_LIFETIME``."""
        return _capped_expiry(_parse_time(self.created_at), _parse_time(self.expires_at))

    def is_expired(self, *, now: datetime | None = None) -> bool:
        active_now = now or datetime.now(timezone.utc)
        return self.effective_expires_at() <= active_now

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "schema": self.schema,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "source": self.source,
            "updated_at": self.updated_at,
            "osv_built_at": self.osv_built_at,
            "datasets": {
                name: {
                    "path": entry["path"],
                    "sha256": entry["sha256"],
                    "bytes": entry.get("bytes"),
                }
                for name, entry in sorted(self.content_hashes.items())
            },
        }


@dataclass(frozen=True)
class FeedStatus:
    cache_dir: Path
    state: str
    action: str
    reason: str
    snapshot: FeedSnapshot | None = None

    @property
    def exit_code(self) -> int:
        return 1 if self.action == "block" else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": FEED_STATUS_SCHEMA,
            "cache_dir": str(self.cache_dir),
            "state": self.state,
            "action": self.action,
            "reason": self.reason,
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
        }


def default_cache_root() -> Path:
    return Path(os.environ.get("CA9_CACHE_DIR", Path.home() / ".cache" / "ca9")).expanduser()


def default_feed_cache_dir() -> Path:
    return default_cache_root() / "feed"


def update_feed_from_source(
    source: str | Path,
    *,
    cache_dir: Path | None = None,
    allow_downgrade: bool = False,
    now: datetime | None = None,
    require_attestation: bool = False,
    attestation_verifier: Callable[[Path], None] | None = None,
    deadline: float | None = None,
) -> FeedSnapshot:
    """Install a feed snapshot from a URL, bundle file, or snapshot directory.

    With ``require_attestation`` the exact bundle bytes are first checked with
    ``gh attestation verify`` (or ``attestation_verifier``), and nothing is
    installed unless that succeeds. Only single-file bundles can be attested.
    ``deadline`` (a ``time.monotonic()`` value) aborts an https download that has
    not finished by then.
    """
    feed_dir = cache_dir or default_feed_cache_dir()
    source_ref = str(source)
    active_now = now or datetime.now(timezone.utc)
    if require_attestation:
        metadata, dataset_bytes = _load_attested_source(
            source_ref, attestation_verifier or verify_feed_attestation, deadline
        )
    else:
        metadata, dataset_bytes = _load_source(source_ref, deadline)
    _validate_required_datasets(dataset_bytes)
    created_at = _parse_time(_metadata_time(metadata, "created_at"))
    if created_at > active_now + MAX_FEED_CLOCK_SKEW:
        raise FeedError(
            f"{source_ref}: feed created_at {metadata['created_at']} is more than "
            f"{_format_duration(MAX_FEED_CLOCK_SKEW)} in the future; "
            "check the feed source and the system clock"
        )
    if not allow_downgrade:
        _reject_rollback(feed_dir, created_at, metadata["created_at"], source_ref)
    expires_at = _parse_time(_metadata_time(metadata, "expires_at"))
    if _capped_expiry(created_at, expires_at) < expires_at:
        # Never honor a lifetime longer than MAX_FEED_LIFETIME, so a feed cannot stay
        # "current" for years and suppress the stale-feed warnings.
        metadata = {**metadata, "expires_at": _iso(_capped_expiry(created_at, expires_at))}

    feed_dir.mkdir(parents=True, exist_ok=True)
    snapshots_dir = feed_dir / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)

    normalized: dict[str, bytes] = {}
    content_hashes: dict[str, dict[str, Any]] = {}
    for name in _present_datasets(dataset_bytes):
        data = _normalize_json_bytes(dataset_bytes[name], dataset=name)
        if name in RANGE_DATASETS:
            _validate_range_dataset(name, data)
        elif name in SUSPICIOUS_DATASETS:
            _validate_suspicious_dataset(name, data)
        filename = f"{name}.json"
        normalized[name] = data
        content_hashes[name] = {
            "path": filename,
            "sha256": _sha256_bytes(data),
            "bytes": len(data),
        }

    snapshot_meta = {
        "schema": FEED_SCHEMA,
        "created_at": _metadata_time(metadata, "created_at"),
        "expires_at": _metadata_time(metadata, "expires_at"),
        "content_hashes": content_hashes,
    }
    snapshot_id = _snapshot_id(snapshot_meta)
    snapshot_meta["snapshot_id"] = snapshot_id
    if metadata.get("osv_built_at"):
        snapshot_meta["osv_built_at"] = metadata["osv_built_at"]

    tmp_dir = Path(tempfile.mkdtemp(prefix=".update-", dir=str(feed_dir)))
    target_dir = snapshots_dir / snapshot_id
    try:
        for name, data in normalized.items():
            (tmp_dir / content_hashes[name]["path"]).write_bytes(data)
        _atomic_write_json(tmp_dir / SNAPSHOT_FILE, snapshot_meta)
        if target_dir.exists():
            shutil.rmtree(tmp_dir)
        else:
            os.replace(tmp_dir, target_dir)
        _atomic_write_json(
            feed_dir / CURRENT_POINTER,
            {
                "snapshot_id": snapshot_id,
                "source": source_ref,
                "updated_at": _utc_now_iso(),
            },
        )
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    return load_current_snapshot(cache_dir=feed_dir)


def _reject_rollback(
    feed_dir: Path,
    created_at: datetime,
    created_at_text: str,
    source_ref: str,
) -> None:
    try:
        installed = load_current_snapshot(cache_dir=feed_dir, validate_hashes=False)
        installed_created_at = _parse_time(installed.created_at)
    except FeedError:
        # Nothing usable is installed (or it is damaged): installing repairs it.
        return
    if created_at < installed_created_at:
        raise FeedError(
            f"{source_ref}: refusing to install feed snapshot created at {created_at_text}; "
            f"it is older than the installed snapshot created at {installed.created_at} "
            "(possible rollback). Re-run with --allow-downgrade to install it anyway."
        )


def load_current_snapshot(
    *,
    cache_dir: Path | None = None,
    validate_hashes: bool = True,
) -> FeedSnapshot:
    feed_dir = cache_dir or default_feed_cache_dir()
    pointer_path = feed_dir / CURRENT_POINTER
    if not pointer_path.exists():
        raise FeedMissingError(f"no ca9 feed is installed in {feed_dir}")
    try:
        pointer = json.loads(pointer_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FeedTamperError(f"{pointer_path}: cannot read feed pointer: {exc}") from exc

    snapshot_id = str(pointer.get("snapshot_id") or "")
    if not snapshot_id:
        raise FeedTamperError(f"{pointer_path}: missing snapshot_id")
    snapshot_dir = feed_dir / "snapshots" / snapshot_id
    snapshot_path = snapshot_dir / SNAPSHOT_FILE
    if not snapshot_path.exists():
        raise FeedTamperError(f"{snapshot_path}: feed snapshot is missing")

    try:
        raw = json.loads(snapshot_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FeedTamperError(f"{snapshot_path}: cannot read feed snapshot: {exc}") from exc

    snapshot = _snapshot_from_raw(feed_dir, snapshot_dir, pointer, raw)
    if validate_hashes:
        _verify_snapshot_hashes(snapshot)
    return snapshot


def feed_status(
    *,
    policy: PackagePolicy | None = None,
    cache_dir: Path | None = None,
    now: datetime | None = None,
) -> FeedStatus:
    active_policy = policy or PackagePolicy()
    feed_dir = cache_dir or default_feed_cache_dir()
    try:
        snapshot = load_current_snapshot(cache_dir=feed_dir)
    except FeedMissingError as exc:
        action = _offline_action(active_policy)
        return FeedStatus(
            cache_dir=feed_dir,
            state="missing",
            action=action,
            reason=str(exc),
        )
    except FeedTamperError as exc:
        return FeedStatus(
            cache_dir=feed_dir,
            state="tampered",
            action="block",
            reason=str(exc),
        )

    if snapshot.is_expired(now=now):
        action = _offline_action(active_policy)
        return FeedStatus(
            cache_dir=feed_dir,
            state="stale",
            action=action,
            reason=f"feed snapshot expired at {_iso(snapshot.effective_expires_at())}",
            snapshot=snapshot,
        )

    return FeedStatus(
        cache_dir=feed_dir,
        state="ready",
        action="pass",
        reason="feed snapshot is current and verified",
        snapshot=snapshot,
    )


def format_feed_status(status: FeedStatus) -> str:
    lines = [
        f"ca9 feed status: {status.state}",
        f"Action: {status.action}",
        f"Cache: {status.cache_dir}",
        f"Reason: {status.reason}",
    ]
    if status.snapshot:
        lines.extend(
            [
                f"Snapshot: {status.snapshot.snapshot_id}",
                f"Created: {status.snapshot.created_at}",
                f"Expires: {status.snapshot.expires_at}",
            ]
        )
        if status.snapshot.osv_built_at:
            lines.append(f"OSV data built: {status.snapshot.osv_built_at}")
        lines.append("Datasets:")
        for name, entry in sorted(status.snapshot.content_hashes.items()):
            lines.append(f"  - {name}: {entry['sha256']}")
    return "\n".join(lines)


def refresh_feed(
    *,
    max_age_hours: float = 6,
    timeout_seconds: float = 60,
    cache_dir: Path | None = None,
    source: str | Path | None = None,
    require_attestation: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Update the installed feed when it is older than ``max_age_hours``.

    A snapshot created less than ``max_age_hours`` ago is left alone without any
    network access (``fresh``). Otherwise the source (``source``, else
    ``CA9_FEED_URL``, else ``DEFAULT_FEED_URL``) is installed through
    ``update_feed_from_source`` with the same checks as ``ca9 feed update``
    (https only, size cap, schema, dataset hashes, rollback refusal and, with
    ``require_attestation``, ``gh attestation verify``). The download is staged in
    a temporary directory and only promoted if it finished within
    ``timeout_seconds``, so a timeout never leaves a partial install. After an
    attempt, further attempts wait an hour (or ``max_age_hours`` if shorter):
    ``recently_checked``. Returns ``status`` (fresh|recently_checked|updated|
    current|failed|timeout), ``reason``, ``source``, ``created_at`` and
    ``snapshot_id`` of the snapshot installed afterwards, and
    ``previous_created_at``. No project code or configuration is read.
    """
    feed_dir = cache_dir or default_feed_cache_dir()
    active_now = now or datetime.now(timezone.utc)
    source_ref = str(source or os.environ.get("CA9_FEED_URL") or DEFAULT_FEED_URL)
    installed = None
    with suppress(FeedError):
        installed = load_current_snapshot(cache_dir=feed_dir)

    def status(state: str, reason: str, snapshot: FeedSnapshot | None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": state,
            "reason": reason,
            "source": source_ref,
            "created_at": None,
            "snapshot_id": None,
            "previous_created_at": None,
        }
        if snapshot is not None:
            result["created_at"] = snapshot.created_at
            result["snapshot_id"] = snapshot.snapshot_id
        if installed is not None:
            result["previous_created_at"] = installed.created_at
        return result

    max_age = timedelta(hours=max_age_hours)
    if installed is not None:
        age = active_now - _parse_time(installed.created_at)
        if age < max_age:
            return status("fresh", f"installed feed is {_format_duration(age)} old", installed)
    last_attempt = _last_refresh_attempt(feed_dir)
    if last_attempt is not None and timedelta(0) <= active_now - last_attempt < min(
        max_age, REFRESH_RECHECK
    ):
        return status(
            "recently_checked",
            f"a refresh was attempted at {_iso(last_attempt)}; not retrying yet",
            installed,
        )
    _record_refresh_attempt(feed_dir, active_now)
    staged, error = _stage_feed(source_ref, feed_dir, timeout_seconds, require_attestation)
    if staged is None:
        if error is None:
            return status(
                "timeout", f"the feed did not download within {timeout_seconds:g}s", installed
            )
        return status("failed", str(error), installed)
    try:
        if installed is not None and _parse_time(staged.created_at) <= _parse_time(
            installed.created_at
        ):
            return status(
                "current",
                f"the source snapshot ({staged.created_at}) is not newer than the installed one",
                installed,
            )
        try:
            snapshot = update_feed_from_source(staged.snapshot_dir, cache_dir=feed_dir)
        except FeedError as exc:
            return status("failed", str(exc), installed)
        return status(
            "updated", f"installed the snapshot created at {snapshot.created_at}", snapshot
        )
    finally:
        shutil.rmtree(staged.cache_dir, ignore_errors=True)


def _stage_feed(
    source: str, feed_dir: Path, timeout_seconds: float, require_attestation: bool
) -> tuple[FeedSnapshot | None, Exception | None]:
    """Install ``source`` into a private staging directory within ``timeout_seconds``.

    Returns the staged snapshot, or ``(None, error)``, or ``(None, None)`` on timeout;
    a download still running after the timeout removes its own staging directory.
    """
    feed_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_staging(feed_dir)
    staging = Path(tempfile.mkdtemp(prefix=REFRESH_STAGING_PREFIX, dir=str(feed_dir)))
    deadline = time.monotonic() + max(timeout_seconds, 0)
    lock = threading.Lock()
    state: dict[str, Any] = {"done": False, "abandoned": False}

    def work() -> None:
        try:
            state["snapshot"] = update_feed_from_source(
                source,
                cache_dir=staging,
                require_attestation=require_attestation,
                deadline=deadline,
            )
        except Exception as exc:
            state["error"] = exc
        finally:
            with lock:
                state["done"] = True
                if state["abandoned"]:
                    shutil.rmtree(staging, ignore_errors=True)

    worker = threading.Thread(target=work, name="ca9-feed-refresh", daemon=True)
    worker.start()
    worker.join(max(timeout_seconds, 0))
    with lock:
        if not state["done"]:
            state["abandoned"] = True
            return None, None
    if "snapshot" not in state:
        shutil.rmtree(staging, ignore_errors=True)
        return None, state.get("error") or FeedError("feed refresh failed")
    return state["snapshot"], None


def _remove_stale_staging(feed_dir: Path) -> None:
    cutoff = time.time() - REFRESH_RECHECK.total_seconds()
    for path in feed_dir.glob(f"{REFRESH_STAGING_PREFIX}*"):
        with suppress(OSError):
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)


def _last_refresh_attempt(feed_dir: Path) -> datetime | None:
    try:
        raw = json.loads((feed_dir / REFRESH_STATE_FILE).read_text())
        return _parse_time(str(raw["attempted_at"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _record_refresh_attempt(feed_dir: Path, moment: datetime) -> None:
    with suppress(OSError):
        _atomic_write_json(feed_dir / REFRESH_STATE_FILE, {"attempted_at": _iso(moment)})


def lookup_malware(
    ecosystem: str,
    name: str,
    version: str | None = None,
    *,
    cache_dir: Path | None = None,
    snapshot: FeedSnapshot | None = None,
) -> tuple[dict[str, Any], ...]:
    """Feed entries that mark ``name`` (at ``version``) as malicious.

    Without a version, every entry for the name is returned and callers keep
    only the whole-package ones (no ``version`` key). With a version, exact and
    whole-package entries match, and so do range entries from the optional
    ``<ecosystem>-malware-ranges`` dataset when ``version`` falls inside one of
    their OSV ranges (npm semver or PEP 440 ordering). A matched range entry is
    returned with ``version`` set to the matched version and its ``ranges``.
    """
    active_snapshot = snapshot or load_current_snapshot(cache_dir=cache_dir)
    loaded = _load_dataset(active_snapshot, _dataset_name(ecosystem, "malware"))
    normalized_name = _normalize_package_name(ecosystem, name)
    matches: list[dict[str, Any]] = []
    for entry in loaded.by_name.get(normalized_name, ()):
        entry_version = entry.get("version")
        if (
            version
            and entry_version
            and str(entry_version) != version
            and not same_version(ecosystem, str(entry_version), version)
        ):
            continue
        matches.append(dict(entry))
    if version:
        seen_ids = {str(entry.get("id") or "") for entry in matches}
        for entry in _range_matches(active_snapshot, ecosystem, normalized_name, version):
            entry_id = str(entry.get("id") or "")
            if entry_id and entry_id in seen_ids:
                continue
            seen_ids.add(entry_id)
            matches.append(entry)
    return tuple(matches)


def _range_matches(
    snapshot: FeedSnapshot,
    ecosystem: str,
    normalized_name: str,
    version: str,
) -> list[dict[str, Any]]:
    dataset = _dataset_name(ecosystem, "malware-ranges")
    if dataset not in snapshot.content_hashes:
        return []
    loaded = _load_dataset(snapshot, dataset)
    matched: list[dict[str, Any]] = []
    for entry in loaded.by_name.get(normalized_name, ()):
        ranges = entry.get("ranges")
        if not isinstance(ranges, list):
            continue
        if osv_ranges_include(ecosystem, ranges, version):
            match = dict(entry)
            match["version"] = version
            match["ranges"] = [dict(item) for item in ranges if isinstance(item, dict)]
            matched.append(match)
    return matched


def find_malware_matches(
    packages: Iterable[Package],
    *,
    cache_dir: Path | None = None,
) -> list[Finding]:
    """Malware findings for ``packages`` from the installed feed snapshot.

    Covers exact versions, whole-package entries, and the range datasets. A
    package without a version only matches whole-package entries. Raises
    ``FeedMissingError`` when no feed is installed and ``FeedTamperError`` when it
    fails verification; a stale snapshot is still matched (check
    ``feed_status`` for freshness). ``cache_dir`` is the feed directory.
    """
    snapshot = load_current_snapshot(cache_dir=cache_dir)
    return _malware_findings_for(packages, snapshot)


def _malware_findings_for(packages: Iterable[Package], snapshot: FeedSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for package in packages:
        if package.ecosystem.lower() not in {"pypi", "npm"}:
            continue
        matches = lookup_malware(
            package.ecosystem,
            package.name,
            package.version,
            snapshot=snapshot,
        )
        if package.version is None:
            matches = tuple(entry for entry in matches if not entry.get("version"))
        for entry in matches:
            findings.append(_malware_feed_finding(package, snapshot, entry))
    return findings


def lookup_suspicious(
    ecosystem: str,
    name: str,
    version: str,
    *,
    cache_dir: Path | None = None,
    snapshot: FeedSnapshot | None = None,
) -> tuple[dict[str, Any], ...]:
    """Sentinel entries that flag ``name`` at exactly ``version``.

    The optional ``<ecosystem>-suspicious`` datasets list exact versions of popular
    packages whose new release ca9's sentinel review flagged before any public
    malware report. Raises ``FeedError`` when the installed feed has no such dataset
    (it predates them), so an empty result always means the version was checked.
    """
    active_snapshot = snapshot or load_current_snapshot(cache_dir=cache_dir)
    dataset = _dataset_name(ecosystem, "suspicious")
    if dataset not in active_snapshot.content_hashes:
        raise FeedError(
            f"the installed feed has no {dataset} dataset; run `ca9 feed update` to get it"
        )
    loaded = _load_dataset(active_snapshot, dataset)
    normalized_name = _normalize_package_name(ecosystem, name)
    return tuple(
        dict(entry)
        for entry in loaded.by_name.get(normalized_name, ())
        if same_version(ecosystem, str(entry.get("version") or ""), version)
    )


def find_suspicious_matches(
    packages: Iterable[Package],
    *,
    cache_dir: Path | None = None,
) -> list[Finding]:
    """Findings for package versions the sentinel flagged in the installed feed.

    Only exact versions match; packages without a version are skipped, and a
    package listed twice is reported once (callers map it back to each entry).
    Raises ``FeedMissingError``/``FeedTamperError`` like ``find_malware_matches``
    and ``FeedError`` when an ecosystem asked about has no suspicious dataset. A
    stale snapshot is still matched. ``cache_dir`` is the feed directory.
    """
    snapshot = load_current_snapshot(cache_dir=cache_dir)
    findings: list[Finding] = []
    seen: set[str] = set()
    for package in packages:
        if package.ecosystem.lower() not in {"pypi", "npm"} or not package.version:
            continue
        if package.key in seen:
            continue
        seen.add(package.key)
        for entry in lookup_suspicious(
            package.ecosystem, package.name, package.version, snapshot=snapshot
        ):
            findings.append(_suspicious_finding(package, snapshot, entry))
    return findings


def lookup_release_time(
    ecosystem: str,
    name: str,
    version: str,
    *,
    cache_dir: Path | None = None,
    snapshot: FeedSnapshot | None = None,
) -> str | None:
    active_snapshot = snapshot or load_current_snapshot(cache_dir=cache_dir)
    loaded = _load_dataset(active_snapshot, _dataset_name(ecosystem, "releases"))
    dataset = loaded.payload
    normalized_name = _normalize_package_name(ecosystem, name)
    packages = dataset.get("packages") if isinstance(dataset, dict) else None
    if isinstance(packages, dict):
        versions = packages.get(normalized_name) or packages.get(name)
        if isinstance(versions, dict):
            released_at = versions.get(version)
            return str(released_at) if released_at else None
    for entry in loaded.by_name.get(normalized_name, ()):
        if str(entry.get("version") or "") == version:
            released_at = entry.get("released_at") or entry.get("published_at")
            return str(released_at) if released_at else None
    return None


def lookup_release_window_start(snapshot: FeedSnapshot, ecosystem: str) -> str | None:
    """Return the releases dataset's ``covers_since`` promise, if present.

    A dataset that declares ``covers_since`` guarantees it contains every release
    published at or after that timestamp, so a version absent from the dataset was
    released before it.
    """
    dataset = _read_dataset(snapshot, _dataset_name(ecosystem, "releases"))
    if isinstance(dataset, dict):
        value = dataset.get("covers_since")
        if value:
            return str(value)
    return None


def release_window_covers(
    snapshot: FeedSnapshot,
    ecosystem: str,
    *,
    now: datetime,
    minimum_hours: int,
) -> bool:
    """True when a version missing from the feed is provably older than the minimum.

    If the dataset covers everything since ``covers_since`` and that point is at
    least ``minimum_hours`` in the past, any version absent from the dataset was
    released earlier and therefore satisfies the minimum-age policy.
    """
    window_start = lookup_release_window_start(snapshot, ecosystem)
    if not window_start:
        return False
    start = _parse_time(window_start)
    return (now - start).total_seconds() / 3600 >= minimum_hours


def package_age_findings(
    packages: tuple[Package, ...],
    policy: PackagePolicy,
    *,
    cache_dir: Path | None = None,
    now: datetime | None = None,
    network: bool = True,
    fetch: Callable[[str], Any] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Findings for versions younger than the policy's minimum package age.

    Release times come from the feed's releases dataset when it has them, then
    from registry metadata through ``ca9.release_age`` (cached under the cache
    root next to the feed directory). An empty releases dataset without
    ``covers_since`` says nothing about a version, so it never settles the
    question on its own. ``network=False`` skips registry lookups.
    """
    if not policy.package_age.enabled:
        return [], []

    active_now = now or datetime.now(timezone.utc)
    status = feed_status(policy=policy, cache_dir=cache_dir, now=active_now)
    warnings: list[str] = []
    if status.state == "missing":
        if status.action == "block":
            return [_feed_unavailable_finding(status)], []
        warnings.append(f"package-age policy could not use feed data: {status.reason}")
    if status.state == "tampered":
        return [_feed_unavailable_finding(status)], []
    if status.state == "stale":
        if status.action == "block":
            return [_feed_unavailable_finding(status)], []
        warnings.append(f"package-age policy used stale feed data: {status.reason}")

    snapshot = status.snapshot
    minimum_hours = policy.package_age.minimum_hours
    findings: list[Finding] = []
    pending: list[Package] = []
    for package in packages:
        if package.ecosystem.lower() not in {"pypi", "npm"} or not package.version:
            continue
        if _is_age_excluded(package, policy.package_age.exclusions):
            continue
        released_at = None
        if snapshot is not None:
            released_at = lookup_release_time(
                package.ecosystem,
                package.name,
                package.version,
                snapshot=snapshot,
            )
        if released_at:
            age_hours = (active_now - _parse_time(released_at)).total_seconds() / 3600
            if age_hours < minimum_hours:
                findings.append(
                    _new_package_version_finding(
                        package,
                        snapshot,
                        released_at=released_at,
                        age_hours=age_hours,
                        minimum_hours=minimum_hours,
                    )
                )
            continue
        if snapshot is not None and release_window_covers(
            snapshot,
            package.ecosystem,
            now=active_now,
            minimum_hours=minimum_hours,
        ):
            continue
        pending.append(package)

    results = registry_release_ages(
        pending,
        minimum_hours=minimum_hours,
        cache_root=release_cache_root(cache_dir),
        network=network,
        fetch=fetch,
        now=active_now,
        trusted_registries=policy.registries.allow,
    )
    for package, result in zip(pending, results, strict=True):
        if result["status"] == "old_enough":
            continue
        if result["status"] == "too_new" and result.get("published_at"):
            findings.append(
                _new_package_version_finding(
                    package,
                    snapshot,
                    released_at=str(result["published_at"]),
                    age_hours=float(result.get("age_hours") or 0.0),
                    minimum_hours=minimum_hours,
                    suggested_version=result.get("suggested_version"),
                    release_source=str(result.get("source") or ""),
                )
            )
            continue
        findings.append(
            _unknown_release_time_finding(
                package,
                snapshot,
                minimum_hours=minimum_hours,
                action=_offline_action(policy),
            )
        )
    return findings, warnings


def release_cache_root(feed_dir: Path | None) -> Path | None:
    """Cache root for release times: the parent of an explicit feed directory."""
    if feed_dir is None:
        return None
    return Path(feed_dir).parent


def registry_release_ages(
    packages: list[Package],
    *,
    minimum_hours: float,
    cache_root: Path | None = None,
    network: bool = True,
    fetch: Callable[[str], Any] | None = None,
    now: datetime | None = None,
    max_lookups: int = MAX_RELEASE_AGE_LOOKUPS,
    trusted_registries: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """``check_release_age`` for each package, in order, with bounded parallelism.

    Without ``network`` only cached publish times are used. Packages past
    ``max_lookups`` come back ``unknown``. An npm package's own registry is only
    queried when its host is in ``trusted_registries``; otherwise the public npm
    registry answers, so a lockfile cannot point lookups at an arbitrary host.
    """
    from ca9.release_age import cached_publish_time, check_release_age

    active_now = now or datetime.now(timezone.utc)

    def offline_fetch(url: str) -> Any:
        raise OSError(f"network lookups are disabled: {url}")

    getter = fetch
    if not network:
        getter = offline_fetch

    def lookup(package: Package) -> dict[str, Any]:
        return check_release_age(
            package.ecosystem,
            package.name,
            str(package.version),
            min_hours=minimum_hours,
            cache_dir=cache_root,
            fetch=getter,
            registry=_npm_release_registry(package, trusted_registries),
            now=active_now,
        )

    limited = packages[:max_lookups]
    results: list[dict[str, Any]] = []
    if limited:
        workers = min(RELEASE_AGE_WORKERS, len(limited))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lookup, limited))
    for package in packages[max_lookups:]:
        known = cached_publish_time(
            package.ecosystem,
            package.name,
            str(package.version),
            registry=_npm_release_registry(package, trusted_registries),
            cache_dir=cache_root,
        )
        if known:
            results.append(
                check_release_age(
                    package.ecosystem,
                    package.name,
                    str(package.version),
                    min_hours=minimum_hours,
                    cache_dir=cache_root,
                    fetch=offline_fetch,
                    registry=_npm_release_registry(package, trusted_registries),
                    now=active_now,
                )
            )
            continue
        results.append(
            {
                "status": "unknown",
                "published_at": None,
                "age_hours": None,
                "suggested_version": None,
                "source": "lookup_limit",
                "reason": "the release-age lookup limit was reached",
            }
        )
    return results


def _npm_release_registry(package: Package, trusted: tuple[str, ...]) -> str | None:
    if package.ecosystem.lower() != "npm":
        return None
    registry = package.source_registry
    if not isinstance(registry, str) or not registry.startswith("https://"):
        return None
    host = (urlparse(registry).hostname or "").lower()
    for entry in trusted:
        candidate = entry.strip().lower()
        if "://" in candidate:
            candidate = urlparse(candidate).hostname or ""
        else:
            candidate = candidate.split("/", 1)[0].rsplit(":", 1)[0]
        if host and candidate == host:
            return registry
    return None


def package_malware_findings(
    packages: tuple[Package, ...],
    policy: PackagePolicy,
    *,
    cache_dir: Path | None = None,
    now: datetime | None = None,
) -> tuple[list[Finding], list[str]]:
    if not policy.malware.enabled:
        return [], []

    active_now = now or datetime.now(timezone.utc)
    status = feed_status(policy=policy, cache_dir=cache_dir, now=active_now)
    warnings: list[str] = []
    if status.state in {"missing", "stale"} and policy.malware.fail_closed:
        return [
            _feed_unavailable_finding(
                status,
                action="block",
                policy_id="ca9.malware_feed_unavailable",
            )
        ], []
    if status.state == "missing":
        return [], [
            f"malware feed is missing ({status.reason}); local malware checks were skipped. "
            "Run `ca9 feed update` to install the feed."
        ]
    if status.state == "tampered":
        return [_feed_unavailable_finding(status)], []
    if status.state == "stale" and status.snapshot is not None:
        # A stale snapshot still knows every package it knew yesterday: match against
        # it, but say clearly that newer malware may be missing.
        warnings.append(_stale_malware_feed_warning(status.snapshot, active_now))

    snapshot = status.snapshot
    if snapshot is None:
        return [], warnings

    return _malware_findings_for(packages, snapshot), warnings


def _stale_malware_feed_warning(snapshot: FeedSnapshot, now: datetime) -> str:
    expired_at = snapshot.effective_expires_at()
    created_at = _parse_time(snapshot.created_at)
    return (
        f"malware feed is stale: snapshot {snapshot.snapshot_id} expired at {_iso(expired_at)} "
        f"({_format_duration(now - expired_at)} ago; data is {_format_duration(now - created_at)} "
        "old). Packages were matched against this stale snapshot and newer malware may be "
        "missed. Run `ca9 feed update` to refresh it."
    )


def _load_source(
    source: str, deadline: float | None = None
) -> tuple[dict[str, Any], dict[str, bytes]]:
    parsed = urlparse(source)
    if parsed.scheme == "http":
        raise FeedError(
            f"{source}: refusing to download a feed over insecure http://; "
            "use an https:// URL or a local path"
        )
    if parsed.scheme == "https":
        try:
            raw = _download_feed(source, deadline)
            return _load_inline_bundle(json.loads(raw.decode("utf-8")), source)
        except urllib.error.HTTPError as exc:
            raise FeedError(f"{source}: feed download failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise FeedError(f"{source}: cannot download feed: {exc.reason}") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FeedError(f"{source}: invalid feed JSON: {exc}") from exc

    path = Path(source).expanduser()
    if path.is_dir():
        return _load_directory_source(path)
    if path.is_file():
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise FeedError(f"{path}: cannot read feed source: {exc}") from exc
        if _has_file_backed_datasets(raw):
            return _load_file_backed_source(path.parent, raw)
        return _load_inline_bundle(raw, str(path))
    raise FeedError(f"feed source does not exist: {source}")


def _download_feed(url: str, deadline: float | None = None) -> bytes:
    """Download a feed bundle over https, aborting past the size cap or ``deadline``."""
    limit = MAX_FEED_DOWNLOAD_BYTES
    too_large = f"{url}: feed download exceeds the {_format_bytes(limit)} size limit"
    timeout = DOWNLOAD_TIMEOUT_SECONDS
    if deadline is not None:
        _check_download_deadline(url, deadline)
        timeout = max(0.1, min(timeout, deadline - time.monotonic()))
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - https only
        final_url = response.geturl() if hasattr(response, "geturl") else url
        if urlparse(str(final_url or url)).scheme != "https":
            raise FeedError(f"{url}: feed download was redirected to non-https {final_url}")
        headers = getattr(response, "headers", None)
        declared = headers.get("Content-Length") if headers is not None else None
        if isinstance(declared, str) and declared.strip().isdigit() and int(declared) > limit:
            raise FeedError(too_large)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(_DOWNLOAD_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise FeedError(too_large)
            chunks.append(chunk)
            if deadline is not None:
                _check_download_deadline(url, deadline)
    return b"".join(chunks)


def _check_download_deadline(url: str, deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise FeedError(f"{url}: feed download did not finish within the time limit")


def _load_directory_source(path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    snapshot_path = path / SNAPSHOT_FILE
    if not snapshot_path.exists():
        raise FeedError(f"{path}: missing {SNAPSHOT_FILE}")
    try:
        raw = json.loads(snapshot_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FeedError(f"{snapshot_path}: cannot read feed snapshot: {exc}") from exc
    return _load_file_backed_source(path, raw)


def _load_file_backed_source(
    root: Path,
    raw: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    metadata = _source_metadata(raw)
    entries = _source_content_hashes(raw)
    dataset_bytes: dict[str, bytes] = {}
    for name in (*REQUIRED_DATASETS, *OPTIONAL_DATASETS):
        entry = entries.get(name)
        if name in OPTIONAL_DATASETS and entry is None:
            continue
        if not isinstance(entry, dict):
            raise FeedError(f"feed snapshot missing dataset {name}")
        rel_path = entry.get("path")
        expected_hash = entry.get("sha256")
        if not isinstance(rel_path, str) or not rel_path:
            raise FeedError(f"feed dataset {name} is missing a path")
        dataset_path = root / rel_path
        try:
            data = dataset_path.read_bytes()
        except OSError as exc:
            raise FeedError(f"{dataset_path}: cannot read feed dataset: {exc}") from exc
        if expected_hash and _sha256_bytes(data) != expected_hash:
            raise FeedTamperError(f"{dataset_path}: sha256 does not match snapshot metadata")
        dataset_bytes[name] = data
    return metadata, dataset_bytes


def _load_inline_bundle(
    raw: dict[str, Any],
    source: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if not isinstance(raw, dict):
        raise FeedError(f"{source}: feed bundle must be a JSON object")
    metadata = _source_metadata(raw)
    datasets = raw.get("datasets")
    if not isinstance(datasets, dict):
        raise FeedError(f"{source}: inline feed bundle must contain datasets")
    dataset_bytes: dict[str, bytes] = {}
    for name in REQUIRED_DATASETS:
        payload = datasets.get(name)
        if payload is None:
            raise FeedError(f"{source}: missing dataset {name}")
        dataset_bytes[name] = _json_bytes(payload)
    for name in OPTIONAL_DATASETS:
        payload = datasets.get(name)
        if payload is not None:
            dataset_bytes[name] = _json_bytes(payload)
    return metadata, dataset_bytes


def _load_attested_source(
    source: str,
    verifier: Callable[[Path], None],
    deadline: float | None = None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Read a single-file bundle once, verify those exact bytes, then parse them."""
    parsed = urlparse(source)
    if parsed.scheme == "http":
        raise FeedError(
            f"{source}: refusing to download a feed over insecure http://; "
            "use an https:// URL or a local path"
        )
    if parsed.scheme == "https":
        try:
            raw = _download_feed(source, deadline)
        except urllib.error.HTTPError as exc:
            raise FeedError(f"{source}: feed download failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise FeedError(f"{source}: cannot download feed: {exc.reason}") from exc
    else:
        path = Path(source).expanduser()
        if not path.is_file():
            raise FeedError(
                f"{source}: attestation can only be verified for a single-file feed bundle"
            )
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise FeedError(f"{path}: cannot read feed source: {exc}") from exc
    with tempfile.TemporaryDirectory(prefix="ca9-feed-verify-") as workdir:
        bundle_path = Path(workdir) / "latest.json"
        bundle_path.write_bytes(raw)
        verifier(bundle_path)
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedError(f"{source}: invalid feed JSON: {exc}") from exc
    if isinstance(bundle, dict) and _has_file_backed_datasets(bundle):
        raise FeedError(f"{source}: attestation can only be verified for a single-file feed bundle")
    return _load_inline_bundle(bundle, source)


def verify_feed_attestation(
    path: Path,
    *,
    repo: str = FEED_ATTESTATION_REPO,
    signer_workflow: str = FEED_SIGNER_WORKFLOW,
    signer_ref: str = FEED_SIGNER_REF,
    gh: str | None = None,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Check ``path`` with ``gh attestation verify``; raise FeedError unless it passes.

    The signing certificate must name exactly the feed publishing workflow at
    ``signer_ref`` (``https://github.com/<signer_workflow>@<signer_ref>``), the
    source ref must be ``signer_ref``, and the runner must be GitHub-hosted. A
    bundle attested by another workflow, or by ``feed.yml`` dispatched from a
    different branch, fails.
    """
    executable = gh or shutil.which("gh")
    if not executable:
        raise FeedError(
            "feed attestation is required but the GitHub CLI (gh) is not installed; "
            "install gh or rerun without --require-attestation"
        )
    command = [
        executable,
        "attestation",
        "verify",
        str(path),
        "--repo",
        repo,
        "--cert-identity",
        f"https://github.com/{signer_workflow}@{signer_ref}",
        "--source-ref",
        signer_ref,
        "--deny-self-hosted-runners",
    ]
    try:
        completed = run(
            command,
            capture_output=True,
            text=True,
            timeout=ATTESTATION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FeedError(f"feed attestation check could not run: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        reason = f"gh exited with status {completed.returncode}"
        if detail:
            reason = detail[-1]
        raise FeedError(f"feed attestation verification failed: {reason}")


def _source_metadata(raw: dict[str, Any], *, strict: bool = True) -> dict[str, Any]:
    """Schema and times of a bundle or snapshot.

    ``osv_built_at`` (when the OSV-derived datasets were built; an hourly bundle can
    carry older OSV data forward) is kept when it is a timestamp no later than
    ``created_at``. A source with any other value is refused (``strict``); an
    installed snapshot with one just reports none.
    """
    schema = raw.get("schema")
    if schema not in {FEED_SCHEMA, 1, "1"}:
        raise FeedError(f"feed schema must be {FEED_SCHEMA}")
    created_at = raw.get("created_at")
    expires_at = raw.get("expires_at")
    if not isinstance(created_at, str) or not created_at:
        raise FeedError("feed metadata must include created_at")
    if not isinstance(expires_at, str) or not expires_at:
        raise FeedError("feed metadata must include expires_at")
    _parse_time(created_at)
    _parse_time(expires_at)
    metadata = {"schema": FEED_SCHEMA, "created_at": created_at, "expires_at": expires_at}
    osv_built_at = raw.get("osv_built_at")
    if osv_built_at is None:
        return metadata
    built = None
    if isinstance(osv_built_at, str):
        with suppress(FeedError):
            built = _parse_time(osv_built_at)
    if built is not None and built <= _parse_time(created_at):
        metadata["osv_built_at"] = osv_built_at
    elif strict:
        raise FeedError("feed osv_built_at must be a timestamp no later than created_at")
    return metadata


def _source_content_hashes(raw: dict[str, Any]) -> dict[str, Any]:
    content_hashes = raw.get("content_hashes")
    if isinstance(content_hashes, dict):
        return content_hashes
    datasets = raw.get("datasets")
    if isinstance(datasets, dict):
        return datasets
    raise FeedError("feed snapshot must include content_hashes")


def _has_file_backed_datasets(raw: dict[str, Any]) -> bool:
    if not isinstance(raw, dict):
        return False
    if isinstance(raw.get("content_hashes"), dict):
        return True
    datasets = raw.get("datasets")
    if not isinstance(datasets, dict):
        return False
    return all(isinstance(value, dict) and "path" in value for value in datasets.values())


def _snapshot_from_raw(
    feed_dir: Path,
    snapshot_dir: Path,
    pointer: dict[str, Any],
    raw: dict[str, Any],
) -> FeedSnapshot:
    metadata = _source_metadata(raw, strict=False)
    content_hashes = raw.get("content_hashes")
    if not isinstance(content_hashes, dict):
        raise FeedTamperError(f"{snapshot_dir / SNAPSHOT_FILE}: missing content_hashes")
    missing = [name for name in REQUIRED_DATASETS if name not in content_hashes]
    if missing:
        raise FeedTamperError(
            f"{snapshot_dir / SNAPSHOT_FILE}: missing dataset hash for {', '.join(missing)}"
        )
    pointer_snapshot_id = str(pointer.get("snapshot_id") or "")
    raw_snapshot_id = str(raw.get("snapshot_id") or "")
    if not pointer_snapshot_id or not raw_snapshot_id:
        raise FeedTamperError(f"{snapshot_dir / SNAPSHOT_FILE}: missing snapshot_id")
    expected_snapshot_id = _snapshot_id(
        {
            "schema": metadata["schema"],
            "created_at": metadata["created_at"],
            "expires_at": metadata["expires_at"],
            "content_hashes": content_hashes,
        }
    )
    if pointer_snapshot_id != raw_snapshot_id or raw_snapshot_id != expected_snapshot_id:
        raise FeedTamperError(
            f"{snapshot_dir / SNAPSHOT_FILE}: snapshot_id does not match metadata"
        )
    return FeedSnapshot(
        cache_dir=feed_dir,
        snapshot_dir=snapshot_dir,
        snapshot_id=raw_snapshot_id,
        schema=metadata["schema"],
        created_at=metadata["created_at"],
        expires_at=metadata["expires_at"],
        content_hashes={str(name): dict(entry) for name, entry in content_hashes.items()},
        source=str(pointer.get("source") or "") or None,
        updated_at=str(pointer.get("updated_at") or "") or None,
        osv_built_at=metadata.get("osv_built_at"),
    )


@dataclass(frozen=True)
class _LoadedDataset:
    payload: Any
    # Normalized package name -> entries, for list-shaped datasets.
    by_name: dict[str, tuple[dict[str, Any], ...]]


def _verify_snapshot_hashes(snapshot: FeedSnapshot) -> None:
    for name, entry in snapshot.content_hashes.items():
        rel_path = entry.get("path")
        expected_hash = entry.get("sha256")
        if not isinstance(rel_path, str) or not rel_path:
            raise FeedTamperError(f"feed dataset {name} has no path")
        if not isinstance(expected_hash, str) or not expected_hash:
            raise FeedTamperError(f"feed dataset {name} has no sha256")
        dataset_path = snapshot.snapshot_dir / rel_path
        try:
            identity = _file_identity(dataset_path, os.stat(dataset_path))
        except OSError as exc:
            raise FeedTamperError(f"{dataset_path}: cannot read feed dataset: {exc}") from exc
        if _cache_get(_VERIFIED_FILES, identity) == expected_hash:
            continue
        _read_verified_bytes(dataset_path, expected_hash)


def _read_verified_bytes(path: Path, expected_hash: str | None) -> tuple[bytes, tuple[Any, ...]]:
    """Read a dataset file and check its sha256, hashing each file version only once."""
    try:
        with path.open("rb") as handle:
            identity = _file_identity(path, os.fstat(handle.fileno()))
            data = handle.read()
    except OSError as exc:
        raise FeedTamperError(f"{path}: cannot read feed dataset: {exc}") from exc
    if expected_hash and _cache_get(_VERIFIED_FILES, identity) != expected_hash:
        if _sha256_bytes(data) != expected_hash:
            raise FeedTamperError(f"{path}: sha256 does not match snapshot metadata")
        _cache_put(_VERIFIED_FILES, identity, expected_hash, _VERIFIED_FILES_MAX)
    return data, identity


def _load_dataset(snapshot: FeedSnapshot, dataset: str) -> _LoadedDataset:
    """Return a parsed, indexed dataset, reusing it until the file on disk changes."""
    entry = snapshot.content_hashes.get(dataset)
    if not entry:
        raise FeedError(f"feed dataset {dataset} is not installed")
    path = snapshot.snapshot_dir / str(entry["path"])
    expected_hash = str(entry.get("sha256") or "") or None
    try:
        identity = _file_identity(path, os.stat(path))
    except OSError as exc:
        raise FeedTamperError(f"{path}: cannot read feed dataset: {exc}") from exc
    cached = _cache_get(_LOADED_DATASETS, (*identity, expected_hash, dataset))
    if cached is not None:
        return cached
    data, identity = _read_verified_bytes(path, expected_hash)
    payload = _parse_dataset(path, data)
    loaded = _LoadedDataset(payload=payload, by_name=_index_dataset(dataset, payload))
    _cache_put(_LOADED_DATASETS, (*identity, expected_hash, dataset), loaded, _LOADED_DATASETS_MAX)
    return loaded


def _read_dataset(snapshot: FeedSnapshot, dataset: str) -> dict[str, Any]:
    return _load_dataset(snapshot, dataset).payload


def _parse_dataset(path: Path, data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedTamperError(f"{path}: cannot read feed dataset: {exc}") from exc


def _index_dataset(dataset: str, payload: Any) -> dict[str, tuple[dict[str, Any], ...]]:
    ecosystem = dataset.split("-", 1)[0]
    packages = payload.get("packages") if isinstance(payload, dict) else payload
    if not isinstance(packages, list):
        return {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    # Entries are shared with the cached payload; lookups return copies.
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = _normalize_package_name(ecosystem, str(entry.get("name") or ""))
        grouped.setdefault(name, []).append(entry)
    return {name: tuple(entries) for name, entries in grouped.items()}


def _file_identity(path: Path, stat_result: os.stat_result) -> tuple[Any, ...]:
    return (
        str(path),
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_size,
        stat_result.st_mtime_ns,
    )


def _cache_get(cache: OrderedDict, key: tuple[Any, ...]) -> Any:
    with _CACHE_LOCK:
        value = cache.get(key)
        if value is not None:
            cache.move_to_end(key)
        return value


def _cache_put(cache: OrderedDict, key: tuple[Any, ...], value: Any, limit: int) -> None:
    with _CACHE_LOCK:
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > limit:
            cache.popitem(last=False)


def _clear_feed_caches() -> None:
    with _CACHE_LOCK:
        _VERIFIED_FILES.clear()
        _LOADED_DATASETS.clear()


def _dataset_entries(dataset: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    packages = dataset.get("packages") if isinstance(dataset, dict) else None
    if isinstance(packages, list):
        return tuple(dict(entry) for entry in packages if isinstance(entry, dict))
    if isinstance(dataset, list):
        return tuple(dict(entry) for entry in dataset if isinstance(entry, dict))
    return ()


def _dataset_name(ecosystem: str, kind: str) -> str:
    normalized = ecosystem.lower()
    if normalized not in {"npm", "pypi"}:
        raise FeedError(f"unsupported feed ecosystem: {ecosystem}")
    return f"{normalized}-{kind}"


def _validate_required_datasets(dataset_bytes: dict[str, bytes]) -> None:
    missing = [name for name in REQUIRED_DATASETS if name not in dataset_bytes]
    if missing:
        raise FeedError(f"feed is missing required dataset(s): {', '.join(missing)}")


def _present_datasets(dataset_bytes: dict[str, bytes]) -> tuple[str, ...]:
    optional = tuple(name for name in OPTIONAL_DATASETS if name in dataset_bytes)
    return (*REQUIRED_DATASETS, *optional)


def _validate_range_dataset(name: str, data: bytes) -> None:
    """Reject a range dataset whose entries could not be matched safely.

    Range datasets are optional: clients that predate them only read
    ``REQUIRED_DATASETS`` and ignore these, so shipping one never breaks them.
    """
    payload = json.loads(data.decode("utf-8"))
    packages = None
    if isinstance(payload, dict):
        packages = payload.get("packages")
    if not isinstance(packages, list):
        raise FeedError(f"{name}: range dataset must contain a packages list")
    for index, entry in enumerate(packages):
        if not isinstance(entry, dict) or not str(entry.get("name") or "").strip():
            raise FeedError(f"{name}: entry {index} must have a package name")
        ranges = entry.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            raise FeedError(f"{name}: entry {index} must have at least one range")


def _validate_suspicious_dataset(name: str, data: bytes) -> None:
    """Reject a suspicious-release dataset whose entries could not be matched safely.

    Each entry needs ``name``, an exact ``version``, a ``verdict`` of block or warn
    and a non-empty ``kinds`` list. Clients that predate these datasets ignore them.
    """
    payload = json.loads(data.decode("utf-8"))
    packages = None
    if isinstance(payload, dict):
        packages = payload.get("packages")
    if not isinstance(packages, list):
        raise FeedError(f"{name}: suspicious dataset must contain a packages list")
    for index, entry in enumerate(packages):
        if not isinstance(entry, dict):
            raise FeedError(f"{name}: entry {index} must be an object")
        for key in ("name", "version"):
            value = entry.get(key)
            if not isinstance(value, str) or not value.strip():
                raise FeedError(f"{name}: entry {index} must have a {key}")
        if entry.get("verdict") not in SUSPICIOUS_VERDICTS:
            raise FeedError(f"{name}: entry {index} verdict must be block or warn")
        kinds = entry.get("kinds")
        if not isinstance(kinds, list) or not kinds:
            raise FeedError(f"{name}: entry {index} must list the kinds it was flagged for")
        if not all(isinstance(kind, str) and kind for kind in kinds):
            raise FeedError(f"{name}: entry {index} kinds must be strings")


def _normalize_json_bytes(data: bytes, *, dataset: str) -> bytes:
    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise FeedError(f"{dataset}: invalid JSON: {exc}") from exc
    return _json_bytes(payload)


def _json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, sort_keys=True, indent=2)
            f.write("\n")
        os.replace(tmp_name, path)
    except Exception:
        with suppress(OSError):
            os.unlink(tmp_name)
        raise


def _snapshot_id(snapshot_meta: dict[str, Any]) -> str:
    payload = json.dumps(snapshot_meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _metadata_time(metadata: dict[str, Any], key: str) -> str:
    value = metadata[key]
    _parse_time(value)
    return value


def _parse_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise FeedError(f"invalid feed timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now_iso() -> str:
    return _iso(datetime.now(timezone.utc))


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _capped_expiry(created_at: datetime, expires_at: datetime) -> datetime:
    return min(expires_at, created_at + MAX_FEED_LIFETIME)


def _format_duration(delta: timedelta) -> str:
    hours = max(delta.total_seconds(), 0) / 3600
    if hours < 48:
        return f"{hours:.0f} hours" if hours >= 1 else "less than an hour"
    return f"{hours / 24:.0f} days"


def _format_bytes(size: int) -> str:
    return f"{size / (1024 * 1024):.0f} MiB"


def _offline_action(policy: PackagePolicy) -> str:
    return "warn" if policy.mode.offline == "warn" else "block"


def _normalize_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() == "npm":
        return name.strip().lower()
    return str(canonicalize_name(name))


def _is_age_excluded(package: Package, exclusions: tuple[str, ...]) -> bool:
    target = _normalize_package_name(package.ecosystem, package.name)
    key = package.key.lower()
    for pattern in exclusions:
        normalized = pattern.strip().lower()
        if not normalized:
            continue
        if fnmatch(target, normalized) or fnmatch(key, normalized):
            return True
    return False


def _release_source_evidence(snapshot: FeedSnapshot | None, release_source: str) -> SourceEvidence:
    if release_source and release_source != "feed":
        return SourceEvidence(
            source="registry metadata",
            reader=f"ca9 release age ({release_source})",
        )
    snapshot_path = None
    if snapshot is not None:
        snapshot_path = str(snapshot.snapshot_dir / SNAPSHOT_FILE)
    return SourceEvidence(
        source="ca9 package feed",
        path=snapshot_path,
        reader="ca9 feed release dataset",
    )


def _snapshot_id_of(snapshot: FeedSnapshot | None) -> str | None:
    if snapshot is None:
        return None
    return snapshot.snapshot_id


def _new_package_version_finding(
    package: Package,
    snapshot: FeedSnapshot | None,
    *,
    released_at: str,
    age_hours: float,
    minimum_hours: int,
    suggested_version: str | None = None,
    release_source: str = "feed",
) -> Finding:
    source = _release_source_evidence(snapshot, release_source)
    evidence_metadata: dict[str, Any] = {
        "released_at": released_at,
        "age_hours": round(age_hours, 2),
        "minimum_hours": minimum_hours,
        "snapshot_id": _snapshot_id_of(snapshot),
        "release_source": release_source,
    }
    if suggested_version:
        evidence_metadata["suggested_version"] = suggested_version
    evidence = Evidence(
        kind="release_age",
        description=f"{package.name} {package.version} was released at {released_at}",
        source=source,
        metadata=evidence_metadata,
    )
    signal = RiskSignal(
        signal_type="new_package_version",
        package_key=package.key,
        severity="high" if package.dependency_kind in {"direct", "project"} else "medium",
        confidence="high",
        evidence=(evidence,),
        metadata={
            "package": package.name,
            "version": package.version,
            "released_at": released_at,
            "age_hours": round(age_hours, 2),
        },
    )
    reason = f"package version age is {age_hours:.1f}h, below policy minimum of {minimum_hours}h"
    metadata: dict[str, Any] = {
        "action": "block",
        "reason": reason,
        "package": package.name,
        "version": package.version,
        "released_at": released_at,
        "age_hours": round(age_hours, 2),
        "minimum_hours": minimum_hours,
        "policy_id": "ca9.package_age",
    }
    if suggested_version:
        metadata["suggested_version"] = suggested_version
        metadata["reason"] = f"{reason}; {suggested_version} is older than the window"
    return Finding(
        title=f"New package version for {package.name}",
        signal_type="new_package_version",
        package_key=package.key,
        severity=signal.severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata=metadata,
    )


def _unknown_release_time_finding(
    package: Package,
    snapshot: FeedSnapshot | None,
    *,
    minimum_hours: int,
    action: str,
) -> Finding:
    snapshot_path = None
    if snapshot is not None:
        snapshot_path = str(snapshot.snapshot_dir / SNAPSHOT_FILE)
    source = SourceEvidence(
        source="ca9 package feed",
        path=snapshot_path,
        reader="ca9 feed release dataset",
    )
    target = f"{package.name} {package.version}" if package.version else package.name
    evidence = Evidence(
        kind="release_age_unknown",
        description=(
            f"release time for {target} is not available in the local feed or registry metadata"
        ),
        source=source,
        metadata={
            "minimum_hours": minimum_hours,
            "snapshot_id": _snapshot_id_of(snapshot),
        },
    )
    signal = RiskSignal(
        signal_type="package_age_unknown",
        package_key=package.key,
        severity="medium",
        confidence="high",
        evidence=(evidence,),
        metadata={
            "package": package.name,
            "version": package.version,
            "minimum_hours": minimum_hours,
        },
    )
    return Finding(
        title=f"Package release time is unknown for {package.name}",
        signal_type="package_age_unknown",
        package_key=package.key,
        severity="medium",
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": action,
            "mode_applied": True,
            "reason": (
                f"release time for {target} is not available in the local feed or registry "
                "metadata; ca9 cannot verify the minimum package age"
            ),
            "package": package.name,
            "version": package.version,
            "minimum_hours": minimum_hours,
            "policy_id": "ca9.package_age_unknown",
        },
    )


def _malware_feed_finding(
    package: Package,
    snapshot: FeedSnapshot,
    entry: dict[str, Any],
) -> Finding:
    malware_id = str(entry.get("id") or "local-feed")
    summary = str(entry.get("summary") or malware_id)
    source = SourceEvidence(
        source="ca9 package feed",
        path=str(snapshot.snapshot_dir / SNAPSHOT_FILE),
        reader="ca9 feed malware dataset",
    )
    evidence = Evidence(
        kind="malware_feed",
        description=summary,
        source=source,
        metadata={
            "malware_id": malware_id,
            "feed_version": entry.get("version"),
            "snapshot_id": snapshot.snapshot_id,
        },
    )
    signal = RiskSignal(
        signal_type="malware",
        package_key=package.key,
        severity="critical",
        confidence="high",
        advisory_key=malware_id,
        evidence=(evidence,),
        metadata={
            "package": package.name,
            "version": package.version,
            "feed_version": entry.get("version"),
        },
    )
    return Finding(
        title=f"Malicious package feed match for {package.name}",
        signal_type="malware",
        package_key=package.key,
        severity="critical",
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": "block",
            "reason": summary,
            "package": package.name,
            "version": package.version,
            "malware_id": malware_id,
            "feed_version": entry.get("version"),
            "policy_id": "ca9.malware",
        },
    )


def _suspicious_finding(
    package: Package,
    snapshot: FeedSnapshot,
    entry: dict[str, Any],
) -> Finding:
    verdict = str(entry.get("verdict") or "warn")
    kinds = [str(kind) for kind in entry.get("kinds") or []]
    previous = entry.get("previous")
    target = f"{package.name} {package.version}"
    severity = "medium"
    if verdict == "block":
        severity = "high"
    compared = "a new package with no earlier release"
    if previous:
        compared = f"{previous}, the release before it"
    reason = (
        f"ca9's sentinel flagged {target} before any public malware report: it adds "
        f"{', '.join(kinds)} that {compared} did not have (static review of the published files)"
    )
    source = SourceEvidence(
        source="ca9 package feed",
        path=str(snapshot.snapshot_dir / SNAPSHOT_FILE),
        reader="ca9 feed suspicious dataset",
    )
    evidence = Evidence(
        kind="suspicious_release",
        description=f"ca9 sentinel flagged {target}: {', '.join(kinds)}",
        source=source,
        metadata={
            "kinds": kinds,
            "verdict": verdict,
            "previous": previous,
            "evidence": [str(item) for item in entry.get("evidence") or []],
            "reviewed_at": entry.get("reviewed_at"),
            "published_at": entry.get("published_at"),
            "snapshot_id": snapshot.snapshot_id,
        },
    )
    signal = RiskSignal(
        signal_type="suspicious_release",
        package_key=package.key,
        severity=severity,
        confidence="medium",
        evidence=(evidence,),
        metadata={"package": package.name, "version": package.version, "kinds": kinds},
    )
    return Finding(
        title=f"Suspicious new release {target}",
        signal_type="suspicious_release",
        package_key=package.key,
        severity=severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": verdict,
            "reason": reason,
            "package": package.name,
            "version": package.version,
            "policy_id": "ca9.suspicious_release",
        },
    )


def _feed_unavailable_finding(
    status: FeedStatus,
    *,
    action: str | None = None,
    policy_id: str = "ca9.feed_unavailable",
) -> Finding:
    applied_action = action or status.action
    source = SourceEvidence(
        source="ca9 package feed",
        path=str(status.snapshot.snapshot_dir / SNAPSHOT_FILE) if status.snapshot else None,
        reader="ca9 feed status",
    )
    evidence = Evidence(
        kind="feed_status",
        description=status.reason,
        source=source,
        metadata={
            "state": status.state,
            "action": status.action,
            "snapshot_id": status.snapshot.snapshot_id if status.snapshot else None,
        },
    )
    key = package_key("ca9", "package-feed", "current")
    signal = RiskSignal(
        signal_type="feed_unavailable",
        package_key=key,
        severity="high",
        confidence="high",
        evidence=(evidence,),
        metadata={"state": status.state},
    )
    return Finding(
        title="Package feed is unavailable",
        signal_type="feed_unavailable",
        package_key=key,
        severity="high",
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": applied_action,
            "mode_applied": True,
            "reason": status.reason,
            "feed_state": status.state,
            "policy_id": policy_id,
        },
    )
