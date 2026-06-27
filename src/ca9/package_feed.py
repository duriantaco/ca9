from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ca9.core.models import Evidence, Finding, Package, RiskSignal, SourceEvidence, package_key
from ca9.package_policy import PackagePolicy

FEED_SCHEMA = "ca9.feed.v1"
FEED_STATUS_SCHEMA = "ca9.feed.status.v1"
REQUIRED_DATASETS = ("npm-malware", "pypi-malware", "npm-releases", "pypi-releases")
CURRENT_POINTER = "current.json"
SNAPSHOT_FILE = "snapshot.json"
# Default hosted feed used by `ca9 feed update` when no source is given.
# Published daily by .github/workflows/feed.yml to the `feed` branch.
# Override with the CA9_FEED_URL environment variable or `--from`.
DEFAULT_FEED_URL = "https://raw.githubusercontent.com/duriantaco/ca9/feed/latest.json"


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

    def is_expired(self, *, now: datetime | None = None) -> bool:
        active_now = now or datetime.now(timezone.utc)
        return _parse_time(self.expires_at) <= active_now

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "schema": self.schema,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "source": self.source,
            "updated_at": self.updated_at,
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
) -> FeedSnapshot:
    feed_dir = cache_dir or default_feed_cache_dir()
    source_ref = str(source)
    metadata, dataset_bytes = _load_source(source_ref)
    _validate_required_datasets(dataset_bytes)

    feed_dir.mkdir(parents=True, exist_ok=True)
    snapshots_dir = feed_dir / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)

    normalized: dict[str, bytes] = {}
    content_hashes: dict[str, dict[str, Any]] = {}
    for name in REQUIRED_DATASETS:
        data = _normalize_json_bytes(dataset_bytes[name], dataset=name)
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
            reason=f"feed snapshot expired at {snapshot.expires_at}",
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
                "Datasets:",
            ]
        )
        for name, entry in sorted(status.snapshot.content_hashes.items()):
            lines.append(f"  - {name}: {entry['sha256']}")
    return "\n".join(lines)


def lookup_malware(
    ecosystem: str,
    name: str,
    version: str | None = None,
    *,
    cache_dir: Path | None = None,
    snapshot: FeedSnapshot | None = None,
) -> tuple[dict[str, Any], ...]:
    active_snapshot = snapshot or load_current_snapshot(cache_dir=cache_dir)
    dataset = _read_dataset(active_snapshot, _dataset_name(ecosystem, "malware"))
    entries = _dataset_entries(dataset)
    normalized_name = _normalize_package_name(ecosystem, name)
    matches: list[dict[str, Any]] = []
    for entry in entries:
        entry_name = _normalize_package_name(ecosystem, str(entry.get("name") or ""))
        entry_version = entry.get("version")
        if entry_name != normalized_name:
            continue
        if version and entry_version and str(entry_version) != version:
            continue
        matches.append(dict(entry))
    return tuple(matches)


def lookup_release_time(
    ecosystem: str,
    name: str,
    version: str,
    *,
    cache_dir: Path | None = None,
    snapshot: FeedSnapshot | None = None,
) -> str | None:
    active_snapshot = snapshot or load_current_snapshot(cache_dir=cache_dir)
    dataset = _read_dataset(active_snapshot, _dataset_name(ecosystem, "releases"))
    normalized_name = _normalize_package_name(ecosystem, name)
    packages = dataset.get("packages") if isinstance(dataset, dict) else None
    if isinstance(packages, dict):
        versions = packages.get(normalized_name) or packages.get(name)
        if isinstance(versions, dict):
            released_at = versions.get(version)
            return str(released_at) if released_at else None
    for entry in _dataset_entries(dataset):
        entry_name = _normalize_package_name(ecosystem, str(entry.get("name") or ""))
        if entry_name == normalized_name and str(entry.get("version") or "") == version:
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
) -> tuple[list[Finding], list[str]]:
    if not policy.package_age.enabled:
        return [], []

    active_now = now or datetime.now(timezone.utc)
    status = feed_status(policy=policy, cache_dir=cache_dir, now=active_now)
    warnings: list[str] = []
    if status.state == "missing":
        if status.action == "block":
            return [_feed_unavailable_finding(status)], []
        return [], [f"package-age policy could not use feed data: {status.reason}"]
    if status.state == "tampered":
        return [_feed_unavailable_finding(status)], []
    if status.state == "stale":
        if status.action == "block":
            return [_feed_unavailable_finding(status)], []
        warnings.append(f"package-age policy used stale feed data: {status.reason}")

    snapshot = status.snapshot
    if snapshot is None:
        return [], warnings

    findings: list[Finding] = []
    for package in packages:
        if package.ecosystem.lower() not in {"pypi", "npm"} or not package.version:
            continue
        if _is_age_excluded(package, policy.package_age.exclusions):
            continue
        released_at = lookup_release_time(
            package.ecosystem,
            package.name,
            package.version,
            snapshot=snapshot,
        )
        if not released_at:
            if release_window_covers(
                snapshot,
                package.ecosystem,
                now=active_now,
                minimum_hours=policy.package_age.minimum_hours,
            ):
                continue
            findings.append(
                _unknown_release_time_finding(
                    package,
                    snapshot,
                    minimum_hours=policy.package_age.minimum_hours,
                    action=_offline_action(policy),
                )
            )
            continue
        released = _parse_time(released_at)
        age_hours = (active_now - released).total_seconds() / 3600
        if age_hours >= policy.package_age.minimum_hours:
            continue
        findings.append(
            _new_package_version_finding(
                package,
                snapshot,
                released_at=released_at,
                age_hours=age_hours,
                minimum_hours=policy.package_age.minimum_hours,
            )
        )
    return findings, warnings


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
    if status.state in {"missing", "stale"}:
        if policy.malware.fail_closed:
            return [
                _feed_unavailable_finding(
                    status,
                    action="block",
                    policy_id="ca9.malware_feed_unavailable",
                )
            ], []
        return [], warnings
    if status.state == "tampered":
        return [_feed_unavailable_finding(status)], []

    snapshot = status.snapshot
    if snapshot is None:
        return [], warnings

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
    return findings, warnings


def _load_source(source: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        try:
            with urllib.request.urlopen(source, timeout=30) as response:
                raw = response.read()
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
    for name in REQUIRED_DATASETS:
        entry = entries.get(name)
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
    return metadata, dataset_bytes


def _source_metadata(raw: dict[str, Any]) -> dict[str, Any]:
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
    return {"schema": FEED_SCHEMA, "created_at": created_at, "expires_at": expires_at}


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
    metadata = _source_metadata(raw)
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
    )


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
            data = dataset_path.read_bytes()
        except OSError as exc:
            raise FeedTamperError(f"{dataset_path}: cannot read feed dataset: {exc}") from exc
        if _sha256_bytes(data) != expected_hash:
            raise FeedTamperError(f"{dataset_path}: sha256 does not match snapshot metadata")


def _read_dataset(snapshot: FeedSnapshot, dataset: str) -> dict[str, Any]:
    entry = snapshot.content_hashes.get(dataset)
    if not entry:
        raise FeedError(f"feed dataset {dataset} is not installed")
    path = snapshot.snapshot_dir / str(entry["path"])
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FeedTamperError(f"{path}: cannot read feed dataset: {exc}") from exc


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
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _offline_action(policy: PackagePolicy) -> str:
    return "warn" if policy.mode.offline == "warn" else "block"


def _normalize_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() == "npm":
        return name.strip().lower()
    from packaging.utils import canonicalize_name

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


def _new_package_version_finding(
    package: Package,
    snapshot: FeedSnapshot,
    *,
    released_at: str,
    age_hours: float,
    minimum_hours: int,
) -> Finding:
    source = SourceEvidence(
        source="ca9 package feed",
        path=str(snapshot.snapshot_dir / SNAPSHOT_FILE),
        reader="ca9 feed release dataset",
    )
    evidence = Evidence(
        kind="release_age",
        description=f"{package.name} {package.version} was released at {released_at}",
        source=source,
        metadata={
            "released_at": released_at,
            "age_hours": round(age_hours, 2),
            "minimum_hours": minimum_hours,
            "snapshot_id": snapshot.snapshot_id,
        },
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
    return Finding(
        title=f"New package version for {package.name}",
        signal_type="new_package_version",
        package_key=package.key,
        severity=signal.severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": "block",
            "reason": (
                f"package version age is {age_hours:.1f}h, below policy minimum of {minimum_hours}h"
            ),
            "package": package.name,
            "version": package.version,
            "released_at": released_at,
            "age_hours": round(age_hours, 2),
            "minimum_hours": minimum_hours,
            "policy_id": "ca9.package_age",
        },
    )


def _unknown_release_time_finding(
    package: Package,
    snapshot: FeedSnapshot,
    *,
    minimum_hours: int,
    action: str,
) -> Finding:
    source = SourceEvidence(
        source="ca9 package feed",
        path=str(snapshot.snapshot_dir / SNAPSHOT_FILE),
        reader="ca9 feed release dataset",
    )
    target = f"{package.name} {package.version}" if package.version else package.name
    evidence = Evidence(
        kind="release_age_unknown",
        description=f"release time for {target} is not available in the local feed",
        source=source,
        metadata={
            "minimum_hours": minimum_hours,
            "snapshot_id": snapshot.snapshot_id,
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
                f"release time for {target} is not available in the local feed; "
                "ca9 cannot verify the minimum package age"
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
