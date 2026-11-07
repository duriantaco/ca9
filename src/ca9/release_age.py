"""Release age of a package version from registry metadata.

``check_release_age`` answers "how long ago was this version published?" from
the npm packument ``time`` map or PyPI's JSON API. On PyPI a release can gain
files long after its first upload, so its time is the newest upload among its
non-yanked files: a wheel added today to a 2020 release makes it new again.
npm publish times never change, so they are kept in a small persistent cache
under ``<cache root>/release-times/``; PyPI times are cached too but re-checked
after ``PYPI_RECHECK_SECONDS``. Failed lookups are never cached, and any
network or parse failure yields ``status == "unknown"`` with a ``reason``
rather than an exception.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from ca9.version_order import is_prerelease, same_version, version_key

RELEASE_TIMES_SCHEMA = "ca9.release_times.v2"
PYPI_RECHECK_SECONDS = 600
DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_JSON_BASE = "https://pypi.org/pypi"
RELEASE_TIMES_DIRNAME = "release-times"
FETCH_TIMEOUT_SECONDS = 20
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_CACHE_FILE_BYTES = 4 * 1024 * 1024
MAX_CACHE_FILES = 4096
_EVICT_EVERY_WRITES = 64
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

FetchJSON = Callable[[str], Any]

_MEMO_LOCK = threading.Lock()
_MEMO: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
_MEMO_MAX = 256
_WRITE_LOCK = threading.Lock()
_WRITES_SINCE_EVICT = [0]


class ReleaseLookupError(Exception):
    """Registry metadata could not be fetched or understood."""


def check_release_age(
    ecosystem: str,
    name: str,
    version: str,
    *,
    min_hours: float,
    cache_dir: Path | str | None = None,
    fetch: FetchJSON | None = None,
    registry: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return the release age of ``name@version`` against a ``min_hours`` cooldown.

    Result keys: ``status`` ("old_enough" | "too_new" | "unknown"),
    ``published_at`` (ISO 8601 or None), ``age_hours`` (float or None),
    ``suggested_version``, ``source`` ("cache" | "npm" | "pypi" | ...) and
    ``reason`` (why the status is "unknown", otherwise None).

    ``min_hours`` must be a finite, non-negative number; anything else is
    reported as "unknown" instead of being read as no cooldown.

    ``suggested_version`` is the newest stable version published before the
    cooldown window that the registry still serves (not a prerelease, not
    yanked, unpublished or deprecated). Versions below the requested one are
    preferred, so a fresh backport on an old release line is not answered with a
    new major version; the newest older-than-window version overall is used
    only when nothing below qualifies.

    ``fetch`` takes a URL and returns the parsed JSON document (raising on any
    failure); it replaces the built-in HTTPS client, mainly for tests.
    """
    eco = (ecosystem or "").lower()
    active_now = now or datetime.now(timezone.utc)
    if eco not in {"npm", "pypi"} or not name or not version:
        return _result(
            "unknown",
            source="unsupported",
            reason="unsupported ecosystem or missing package name or version",
        )
    threshold = _valid_hours(min_hours)
    cutoff = None
    if threshold is not None:
        with suppress(OverflowError):
            cutoff = active_now - timedelta(hours=threshold)
    if cutoff is None:
        return _result(
            "unknown",
            source="policy",
            reason=f"min_hours must be a finite, non-negative number of hours, got {min_hours!r}",
        )
    origin = _registry_origin(eco, registry)
    store = _ReleaseStore(_cache_root(cache_dir), eco, name, origin)
    getter = fetch or _default_fetch

    record = store.load()
    source = "cache"
    published = _record_time(eco, record, version, now=active_now)
    if published is None:
        try:
            record = _refresh(eco, name, version, origin, getter, store, record, now=active_now)
        except ReleaseLookupError:
            return _result(
                "unknown",
                source=eco,
                reason="registry metadata could not be fetched or parsed",
            )
        source = eco
        published = _record_time(eco, record, version, now=active_now)
    if published is None:
        return _result(
            "unknown",
            source=source,
            suggested_version=_suggest(eco, record, version, cutoff),
            reason="the version is not listed in registry metadata",
        )

    published_at = _parse_time(published)
    if published_at is None:
        return _result(
            "unknown",
            source=source,
            reason="the registry publish time could not be parsed",
        )
    age_hours = round((active_now - published_at).total_seconds() / 3600, 2)
    if published_at <= cutoff:
        return _result(
            "old_enough",
            source=source,
            published_at=_iso(published_at),
            age_hours=age_hours,
        )
    if not record.get("complete") or _fetched_before(record, cutoff):
        with suppress(ReleaseLookupError):
            record = _refresh_complete(eco, name, origin, getter, store, record, now=active_now)
    return _result(
        "too_new",
        source=source,
        published_at=_iso(published_at),
        age_hours=age_hours,
        suggested_version=_suggest(eco, record, version, cutoff),
    )


def _valid_hours(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    hours = float(value)
    if not math.isfinite(hours) or hours < 0:
        return None
    return hours


def cached_publish_time(
    ecosystem: str,
    name: str,
    version: str,
    *,
    registry: str | None = None,
    cache_dir: Path | str | None = None,
) -> str | None:
    """Publish time ca9 already learned for ``name@version``, without network access."""
    eco = (ecosystem or "").lower()
    if eco not in {"npm", "pypi"}:
        return None
    store = _ReleaseStore(_cache_root(cache_dir), eco, name, _registry_origin(eco, registry))
    return _record_time(eco, store.load(), version, now=datetime.now(timezone.utc))


def prime_release_times(
    ecosystem: str,
    name: str,
    *,
    cache_dir: Path | str | None = None,
    fetch: FetchJSON | None = None,
    registry: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Fetch and cache the full version listing for ``name``; False when that fails.

    Useful before checking many versions of one package (a PyPI project page),
    so each later ``check_release_age`` call with the same ``now`` is answered
    from the cache.
    """
    eco = (ecosystem or "").lower()
    if eco not in {"npm", "pypi"} or not name:
        return False
    origin = _registry_origin(eco, registry)
    store = _ReleaseStore(_cache_root(cache_dir), eco, name, origin)
    try:
        _refresh_complete(
            eco,
            name,
            origin,
            fetch or _default_fetch,
            store,
            store.load(),
            now=now or datetime.now(timezone.utc),
        )
    except ReleaseLookupError:
        return False
    return True


def remember_npm_packument(
    name: str,
    packument: dict[str, Any],
    *,
    registry: str | None = None,
    cache_dir: Path | str | None = None,
    now: datetime | None = None,
) -> None:
    """Store the publish times from a full npm packument that was fetched elsewhere."""
    if not isinstance(packument, dict):
        return
    origin = _registry_origin("npm", registry)
    store = _ReleaseStore(_cache_root(cache_dir), "npm", name, origin)
    try:
        record = _npm_record(name, origin, packument, now=now)
    except ReleaseLookupError:
        return
    if record["versions"]:
        store.save(_merge(store.load(), record))


def default_release_cache_root() -> Path:
    return Path(os.environ.get("CA9_CACHE_DIR", Path.home() / ".cache" / "ca9")).expanduser()


def _result(
    status: str,
    *,
    source: str,
    published_at: str | None = None,
    age_hours: float | None = None,
    suggested_version: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "published_at": published_at,
        "age_hours": age_hours,
        "suggested_version": suggested_version,
        "source": source,
        "reason": reason,
    }


def _refresh(
    eco: str,
    name: str,
    version: str,
    origin: str,
    getter: FetchJSON,
    store: _ReleaseStore,
    record: dict[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    if eco == "pypi":
        try:
            single = _pypi_version_record(name, version, getter, now=now)
        except ReleaseLookupError:
            single = None
        if single is not None and single["versions"]:
            merged = _merge(record, single)
            store.save(merged)
            return merged
    return _refresh_complete(eco, name, origin, getter, store, record, now=now)


def _refresh_complete(
    eco: str,
    name: str,
    origin: str,
    getter: FetchJSON,
    store: _ReleaseStore,
    record: dict[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    if eco == "npm":
        document = _fetch_json(getter, f"{origin}/{urllib.parse.quote(name, safe='@')}")
        fresh = _npm_record(name, origin, document, now=now)
    else:
        document = _fetch_json(getter, _pypi_url(name))
        fresh = _pypi_project_record(name, document, now=now)
    merged = _merge(record, fresh)
    if fresh["versions"]:
        store.save(merged)
    return merged


def _fetch_json(getter: FetchJSON, url: str) -> dict[str, Any]:
    try:
        document = getter(url)
    except Exception as exc:
        raise ReleaseLookupError(f"{url}: {exc}") from None
    if isinstance(document, (bytes, bytearray)):
        try:
            document = json.loads(bytes(document).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseLookupError(f"{url}: invalid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise ReleaseLookupError(f"{url}: registry metadata is not a JSON object")
    return document


def _npm_record(
    name: str,
    origin: str,
    packument: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    times = packument.get("time")
    versions = packument.get("versions")
    if not isinstance(times, dict) or not isinstance(versions, dict):
        raise ReleaseLookupError(f"{name}: npm packument has no version time map")
    published: dict[str, str] = {}
    unsuitable: list[str] = []
    for version, value in times.items():
        if version in {"created", "modified"} or not isinstance(value, str):
            continue
        if _parse_time(value) is None:
            continue
        published[str(version)] = value
        manifest = versions.get(version)
        if not isinstance(manifest, dict) or manifest.get("deprecated"):
            unsuitable.append(str(version))
    return _record("npm", name, origin, published, unsuitable, complete=True, now=now)


def _pypi_url(name: str, version: str | None = None) -> str:
    project = urllib.parse.quote(str(canonicalize_name(name)), safe="")
    if version is None:
        return f"{PYPI_JSON_BASE}/{project}/json"
    return f"{PYPI_JSON_BASE}/{project}/{urllib.parse.quote(version, safe='')}/json"


def _pypi_version_record(
    name: str,
    version: str,
    getter: FetchJSON,
    *,
    now: datetime,
) -> dict[str, Any] | None:
    document = _fetch_json(getter, _pypi_url(name, version))
    info = document.get("info")
    listed = version
    if isinstance(info, dict) and info.get("version"):
        listed = str(info["version"])
    files = document.get("urls")
    if not isinstance(files, list):
        return None
    latest, yanked = _latest_upload(files)
    if latest is None:
        return None
    unsuitable: list[str] = []
    if yanked:
        unsuitable.append(listed)
    return _record(
        "pypi", name, PYPI_JSON_BASE, {listed: latest}, unsuitable, complete=False, now=now
    )


def _pypi_project_record(
    name: str,
    document: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    releases = document.get("releases")
    if not isinstance(releases, dict):
        raise ReleaseLookupError(f"{name}: PyPI JSON has no releases map")
    published: dict[str, str] = {}
    unsuitable: list[str] = []
    for version, files in releases.items():
        if not isinstance(files, list):
            continue
        latest, yanked = _latest_upload(files)
        if latest is None:
            continue
        published[str(version)] = latest
        if yanked:
            unsuitable.append(str(version))
    return _record("pypi", name, PYPI_JSON_BASE, published, unsuitable, complete=True, now=now)


def _latest_upload(files: list[Any]) -> tuple[str | None, bool]:
    """Newest upload among a release's non-yanked files, and whether all are yanked.

    A file added to an old release is code nobody has seen yet, so it sets the
    release's age. Yanked files are left out unless every file is yanked.
    """
    live: list[datetime] = []
    yanked: list[datetime] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        uploaded = _parse_time(
            str(item.get("upload_time_iso_8601") or item.get("upload_time") or "")
        )
        if uploaded is None:
            continue
        if item.get("yanked") is True:
            yanked.append(uploaded)
        else:
            live.append(uploaded)
    if live:
        return _iso(max(live)), False
    if yanked:
        return _iso(max(yanked)), True
    return None, False


def _record(
    eco: str,
    name: str,
    origin: str,
    published: dict[str, str],
    unsuitable: list[str],
    *,
    complete: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    fetched_at = _iso(now or datetime.now(timezone.utc))
    checked: dict[str, str] = {}
    if eco == "pypi":
        checked = {version: fetched_at for version in published}
    return {
        "schema": RELEASE_TIMES_SCHEMA,
        "ecosystem": eco,
        "name": name,
        "registry": origin,
        "fetched_at": fetched_at,
        "complete": complete,
        "versions": dict(sorted(published.items())),
        "checked": dict(sorted(checked.items())),
        "unsuitable": sorted(set(unsuitable)),
    }


def _merge(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Merge records: freshly fetched times and listing state win over cached ones."""
    if not old or not isinstance(old.get("versions"), dict):
        return new
    versions = {**old["versions"], **(new.get("versions") or {})}
    checked = {**(old.get("checked") or {}), **(new.get("checked") or {})}
    if new.get("complete"):
        unsuitable = set(new.get("unsuitable") or [])
        complete = True
        fetched_at = new.get("fetched_at")
    else:
        refreshed = set(new.get("versions") or {})
        unsuitable = {item for item in old.get("unsuitable") or [] if item not in refreshed}
        unsuitable.update(new.get("unsuitable") or [])
        complete = bool(old.get("complete"))
        fetched_at = old.get("fetched_at") or new.get("fetched_at")
    return {
        **new,
        "complete": complete,
        "fetched_at": fetched_at,
        "versions": dict(sorted(versions.items())),
        "checked": dict(sorted(checked.items())),
        "unsuitable": sorted(unsuitable),
    }


def _record_time(eco: str, record: dict[str, Any], version: str, *, now: datetime) -> str | None:
    """Known time for ``version``; a PyPI time only while it was checked recently."""
    if not isinstance(record, dict) or not version:
        return None
    versions = record.get("versions")
    if not isinstance(versions, dict):
        return None
    listed = None
    if isinstance(versions.get(version), str):
        listed = version
    else:
        for candidate, value in versions.items():
            if isinstance(value, str) and same_version(eco, str(candidate), version):
                listed = str(candidate)
                break
    if listed is None:
        return None
    if eco == "pypi" and not _recently_checked(record, listed, now):
        return None
    return versions[listed]


def _recently_checked(record: dict[str, Any], version: str, now: datetime) -> bool:
    checked = record.get("checked")
    if not isinstance(checked, dict) or not isinstance(checked.get(version), str):
        return False
    when = _parse_time(checked[version])
    if when is None:
        return False
    elapsed = (now - when).total_seconds()
    return 0 <= elapsed <= PYPI_RECHECK_SECONDS


def _suggest(
    eco: str,
    record: dict[str, Any],
    requested: str,
    cutoff: datetime,
) -> str | None:
    if not isinstance(record, dict):
        return None
    versions = record.get("versions")
    if not isinstance(versions, dict):
        return None
    unsuitable = set(record.get("unsuitable") or [])
    requested_key = version_key(eco, requested)
    below: tuple[Any, str] | None = None
    overall: tuple[Any, str] | None = None
    for candidate, value in versions.items():
        if candidate in unsuitable or is_prerelease(eco, candidate):
            continue
        if not isinstance(value, str):
            continue
        published_at = _parse_time(value)
        if published_at is None or published_at > cutoff:
            continue
        key = version_key(eco, candidate)
        if key is None or same_version(eco, candidate, requested):
            continue
        if overall is None or key > overall[0]:
            overall = (key, candidate)
        if requested_key is not None and key < requested_key:
            if below is None or key > below[0]:
                below = (key, candidate)
    if below is not None:
        return below[1]
    if overall is not None:
        return overall[1]
    return None


def _fetched_before(record: dict[str, Any], cutoff: datetime) -> bool:
    fetched = _parse_time(str(record.get("fetched_at") or ""))
    return fetched is None or fetched < cutoff


def _registry_origin(eco: str, registry: str | None) -> str:
    if eco == "pypi":
        return PYPI_JSON_BASE
    return (registry or DEFAULT_NPM_REGISTRY).strip().rstrip("/") or DEFAULT_NPM_REGISTRY


def _cache_root(cache_dir: Path | str | None) -> Path:
    if cache_dir is None:
        return default_release_cache_root() / RELEASE_TIMES_DIRNAME
    return Path(cache_dir).expanduser() / RELEASE_TIMES_DIRNAME


class _ReleaseStore:
    """One JSON file of publish times per (ecosystem, registry, package)."""

    def __init__(self, root: Path, eco: str, name: str, origin: str) -> None:
        self.root = root
        self.directory = root / eco
        if eco == "pypi":
            identity = str(canonicalize_name(name))
        else:
            identity = name.strip()
        digest = hashlib.sha256(f"{origin}\n{identity}".encode()).hexdigest()
        self.path = self.directory / f"{digest[:40]}.json"
        self.eco = eco
        self.identity = identity
        self.origin = origin

    def load(self) -> dict[str, Any]:
        if not self._directories_safe(create=False):
            return {}
        try:
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return {}
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CACHE_FILE_BYTES:
                return {}
            memo_key = (str(self.path), info.st_ino, info.st_size, info.st_mtime_ns)
            with _MEMO_LOCK:
                cached = _MEMO.get(memo_key)
                if cached is not None:
                    _MEMO.move_to_end(memo_key)
                    return cached
            raw = _read_all(descriptor, MAX_CACHE_FILE_BYTES)
        except OSError:
            return {}
        finally:
            os.close(descriptor)
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        if not self._valid(record):
            return {}
        with _MEMO_LOCK:
            _MEMO[memo_key] = record
            _MEMO.move_to_end(memo_key)
            while len(_MEMO) > _MEMO_MAX:
                _MEMO.popitem(last=False)
        return record

    def save(self, record: dict[str, Any]) -> None:
        if not record.get("versions"):
            return
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(payload) > MAX_CACHE_FILE_BYTES:
            return
        with suppress(OSError):
            if not self._directories_safe(create=True):
                return
            descriptor, temp_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.directory)
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                os.replace(temp_name, self.path)
            except OSError:
                with suppress(OSError):
                    os.unlink(temp_name)
                return
            self._maybe_evict()

    def _valid(self, record: Any) -> bool:
        return (
            isinstance(record, dict)
            and record.get("schema") == RELEASE_TIMES_SCHEMA
            and record.get("ecosystem") == self.eco
            and record.get("registry") == self.origin
            and isinstance(record.get("versions"), dict)
            and isinstance(record.get("unsuitable", []), list)
            and all(isinstance(item, str) for item in record.get("unsuitable", []))
            and isinstance(record.get("checked", {}), dict)
            and _same_identity(self.eco, str(record.get("name") or ""), self.identity)
        )

    def _directories_safe(self, *, create: bool) -> bool:
        for directory in (self.root, self.directory):
            try:
                info = os.lstat(directory)
            except FileNotFoundError:
                if not create:
                    return False
                try:
                    os.makedirs(directory, mode=0o700, exist_ok=True)
                    info = os.lstat(directory)
                except OSError:
                    return False
            except OSError:
                return False
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                return False
        return True

    def _maybe_evict(self) -> None:
        with _WRITE_LOCK:
            _WRITES_SINCE_EVICT[0] += 1
            if _WRITES_SINCE_EVICT[0] % _EVICT_EVERY_WRITES != 1:
                return
        _evict_oldest(self.root)


def _read_all(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise OSError("release-time cache file is too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _evict_oldest(root: Path) -> None:
    entries: list[tuple[int, str]] = []
    with suppress(OSError):
        for eco_dir in os.scandir(root):
            if not eco_dir.is_dir(follow_symlinks=False):
                continue
            for item in os.scandir(eco_dir.path):
                if item.name.endswith(".json") and item.is_file(follow_symlinks=False):
                    with suppress(OSError):
                        entries.append((item.stat(follow_symlinks=False).st_mtime_ns, item.path))
    excess = len(entries) - MAX_CACHE_FILES
    if excess <= 0:
        return
    entries.sort()
    for _, path in entries[: excess + MAX_CACHE_FILES // 10]:
        with suppress(OSError):
            os.unlink(path)


def _same_identity(eco: str, left: str, right: str) -> bool:
    if eco == "pypi":
        return str(canonicalize_name(left)) == str(canonicalize_name(right))
    return left.strip() == right.strip()


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source = urllib.parse.urlsplit(req.full_url)
        target = urllib.parse.urlsplit(newurl)
        if (
            not target.hostname
            or target.username
            or target.password
            or (source.hostname or "").lower() != target.hostname.lower()
            or (source.scheme == "https" and target.scheme != "https")
        ):
            raise urllib.error.URLError("refusing registry redirect to another host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_fetch(url: str) -> Any:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and not (parsed.scheme == "http" and host in _LOOPBACK_HOSTS):
        raise ReleaseLookupError(f"refusing non-https registry metadata URL {url}")
    if parsed.username or parsed.password:
        raise ReleaseLookupError("refusing registry metadata URL with credentials")
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "ca9-release-age"}
    )
    opener = urllib.request.build_opener(_SameHostRedirects)
    with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_METADATA_BYTES:
                raise ReleaseLookupError(f"{url}: registry metadata exceeds the size limit")
            chunks.append(chunk)
    return json.loads(b"".join(chunks).decode("utf-8"))


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
