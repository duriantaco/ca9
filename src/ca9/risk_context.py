"""Bounded EPSS/KEV context, independent of reachability and policy scoring.

Only fixed HTTPS providers are queried. Cached observations retain their own
provider date and retrieval time; a failed refresh never refreshes old evidence.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import http.client
import json
import math
import os
import queue
import re
import secrets
import ssl
import stat
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlencode

from ca9 import __version__

MAX_CVES = 16
MAX_AGE = dt.timedelta(days=7)
REFRESH_AGE = dt.timedelta(hours=24)
MAX_CACHE_BYTES = 8 * 1024 * 1024
MAX_CACHE_RECORDS = 5000
_CVE = re.compile(r"CVE-(?:1999|20\d{2})-\d{4,19}\Z", re.ASCII)
_CACHE_FILE = "risk-context-v1.json"
_EPSS_HOST = "api.first.org"
_KEV_HOST = "www.cisa.gov"
_KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TRANSPORT_SLOTS = threading.BoundedSemaphore(2)


def canonical_cves(values: Iterable[object]) -> list[str]:
    """At most sixteen canonical identifiers, in deterministic order."""
    if isinstance(values, (str, bytes)):
        return []
    found = set()
    for index, value in enumerate(values):
        if index >= 256:
            break
        if isinstance(value, str) and len(value) <= 48:
            value = value.strip().upper()
            if _CVE.fullmatch(value):
                found.add(value)
    return sorted(found)[:MAX_CVES]


def _date(value: object, today: dt.date, *, future: bool = False) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return None
    try:
        parsed = dt.date.fromisoformat(value)
        return value if future or parsed <= today else None
    except ValueError:
        return None


def _instant(value: object, now: dt.datetime) -> dt.datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo and parsed <= now else None
    except ValueError:
        return None


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        number = float(value)
        return number if math.isfinite(number) and 0 <= number <= 1 else None
    except (ValueError, OverflowError):
        return None


def _unknown(cve: str) -> dict:
    return {
        "cve_id": cve,
        "epss": {
            "status": "unknown",
            "score": None,
            "percentile": None,
            "score_date": None,
            "retrieved_at": None,
        },
        "kev": {
            "status": "unknown",
            "in_catalog": None,
            "date_added": None,
            "due_date": None,
            "catalog_date": None,
            "retrieved_at": None,
        },
    }


def _cache_directory(path: Path, *, create: bool) -> int:
    """Open every directory component without following symlinks."""
    if os.name != "posix" or not all(
        hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    ):
        raise OSError("Safe descriptor-relative cache access is unavailable")
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            if create:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_fd
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise OSError("Cache directory must be owned by this user and not writable by others")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_cache(directory: Path) -> dict:
    try:
        directory_fd = _cache_directory(directory, create=False)
        try:
            file_fd = os.open(
                _CACHE_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
            )
            with os.fdopen(file_fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CACHE_BYTES:
                    return {}
                raw = stream.read(MAX_CACHE_BYTES + 1)
                data = json.loads(raw) if len(raw) <= MAX_CACHE_BYTES else None
                return (
                    data
                    if (
                        isinstance(data, dict)
                        and type(data.get("schema_version")) is int
                        and data["schema_version"] == 1
                    )
                    else {}
                )
        finally:
            os.close(directory_fd)
    except (OSError, ValueError, TypeError, RecursionError):
        return {}


def _write_cache(directory: Path, data: dict) -> None:
    temporary = f".{_CACHE_FILE}.{secrets.token_hex(12)}"
    directory_fd = None
    try:
        raw = json.dumps(data, allow_nan=False, separators=(",", ":")).encode()
        if len(raw) > MAX_CACHE_BYTES:
            return
        directory_fd = _cache_directory(directory, create=True)
        file_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(file_fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, _CACHE_FILE, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    except (OSError, ValueError, TypeError):
        pass
    finally:
        if directory_fd is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=directory_fd)
            os.close(directory_fd)


def _fetch_json(host: str, path: str, limit: int, deadline: float) -> dict | None:
    """Bound caller wait even if the platform's DNS resolver does not return.

    At most two daemon transports may remain in progress. A timed-out resolver
    never authorizes another request after it returns past the deadline.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _TRANSPORT_SLOTS.acquire(blocking=False):
        return None
    result = queue.Queue(maxsize=1)

    def run():
        try:
            result.put(_fetch_json_sync(host, path, limit, deadline))
        finally:
            _TRANSPORT_SLOTS.release()

    worker = threading.Thread(target=run, name="ca9-threat-context", daemon=True)
    try:
        worker.start()
    except RuntimeError:
        _TRANSPORT_SLOTS.release()
        return None
    try:
        return result.get(timeout=max(0.001, deadline - time.monotonic()))
    except queue.Empty:
        return None


def _fetch_json_sync(host: str, path: str, limit: int, deadline: float) -> dict | None:
    """No redirects, proxies, decompression or unbounded response reads."""
    connection = None
    response = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        connection = http.client.HTTPSConnection(
            host,
            timeout=min(5.0, remaining),
            context=ssl.create_default_context(),
        )
        connection.connect()
        sock = connection.sock
        if sock is None or deadline <= time.monotonic():
            return None
        sock.settimeout(max(0.001, min(5.0, deadline - time.monotonic())))
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": f"ca9/{__version__}",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        sock.settimeout(max(0.001, min(5.0, deadline - time.monotonic())))
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Encoding", "identity").lower() != "identity"
        ):
            return None
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > limit):
            return None
        chunks = []
        size = 0
        while size <= limit and not response.isclosed():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(min(5.0, remaining))
            chunk = response.read1(min(16384, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > limit:
            return None
        if length is not None and size != int(length):
            return None
        data = json.loads(b"".join(chunks))
        return data if isinstance(data, dict) else None
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        return None
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _epss_record(value: object, now: dt.datetime) -> dict | None:
    if not isinstance(value, dict):
        return None
    score, percentile = _number(value.get("score")), _number(value.get("percentile"))
    date = _date(value.get("score_date"), now.date())
    retrieved = _instant(value.get("retrieved_at"), now)
    if (
        score is None
        or percentile is None
        or date is None
        or retrieved is None
        or date > retrieved.astimezone(dt.timezone.utc).date().isoformat()
    ):
        return None
    return {
        "score": score,
        "percentile": percentile,
        "score_date": date,
        "retrieved_at": retrieved.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
    }


def _kev_record(value: object, now: dt.datetime) -> dict | None:
    if not isinstance(value, dict) or not isinstance(value.get("entries"), dict):
        return None
    date = _date(value.get("catalog_date"), now.date())
    retrieved = _instant(value.get("retrieved_at"), now)
    entries = value["entries"]
    if (
        date is None
        or retrieved is None
        or not 0 < len(entries) <= 100000
        or date > retrieved.astimezone(dt.timezone.utc).date().isoformat()
    ):
        return None
    clean = {}
    for cve, entry in entries.items():
        if not isinstance(cve, str) or not _CVE.fullmatch(cve) or not isinstance(entry, dict):
            return None
        added = _date(entry.get("date_added"), now.date())
        due = entry.get("due_date")
        if (
            added is None
            or added > date
            or _date(due, now.date(), future=True) is None
            or due < added
        ):
            return None
        clean[cve] = {"date_added": added, "due_date": due}
    return {
        "catalog_date": date,
        "retrieved_at": retrieved.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "entries": clean,
    }


def _fresh(record: dict, now: dt.datetime, date_key: str) -> bool:
    retrieved = _instant(record.get("retrieved_at"), now)
    return bool(
        retrieved
        and now - retrieved <= MAX_AGE
        and now
        - dt.datetime.combine(dt.date.fromisoformat(record[date_key]), dt.time(), dt.timezone.utc)
        <= MAX_AGE
    )


def _needs_refresh(record: dict | None, now: dt.datetime) -> bool:
    retrieved = _instant(record.get("retrieved_at"), now) if record else None
    return not retrieved or now - retrieved >= REFRESH_AGE


def threat_context(
    cve_ids: Iterable[object],
    *,
    network: bool = True,
    project_root: str | Path | None = None,
    timeout: float = 15.0,
) -> dict:
    """Return risk_context v1 for up to sixteen CVEs, without changing findings.

    ``network=False`` is cache-only. Only validated provider records can report
    zero EPSS or a negative KEV result. Failed refreshes retain dated evidence as
    stale; cached negative KEV evidence becomes unknown after a failed refresh.
    Cache directories within ``project_root`` are ignored and never written.
    """
    cves = canonical_cves(cve_ids)
    result = {"schema_version": 1, "cves": [_unknown(cve) for cve in cves]}
    if not cves:
        return result
    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
    ):
        timeout = 0
    deadline = time.monotonic() + max(0.0, min(15.0, timeout))
    cache_dir = Path(
        os.environ.get("CA9_CACHE_DIR", str(Path.home() / ".cache" / "ca9" / "threat_intel"))
    )
    allowed_cache = True
    if project_root is not None:
        try:
            cache_dir.resolve().relative_to(Path(project_root).resolve())
            allowed_cache = False
        except ValueError:
            pass
        except OSError:
            allowed_cache = False
    cached = _read_cache(cache_dir) if allowed_cache else {}
    old_epss = cached.get("epss")
    epss = {}
    if isinstance(old_epss, dict):
        for cve, value in list(old_epss.items())[:MAX_CACHE_RECORDS]:
            if isinstance(cve, str) and _CVE.fullmatch(cve):
                record = _epss_record(value, now)
                if record is not None:
                    epss[cve] = record
    kev = _kev_record(cached.get("kev"), now)
    epss_failed = set()
    kev_failed = False
    changed = False
    missing = [cve for cve in cves if _needs_refresh(epss.get(cve), now)]
    if network is True and missing:
        data = _fetch_json(
            _EPSS_HOST,
            "/data/v1/epss?" + urlencode({"cve": ",".join(missing)}),
            256 * 1024,
            deadline,
        )
        returned = set()
        if (
            data
            and data.get("status") == "OK"
            and type(data.get("status-code")) is int
            and data["status-code"] == 200
            and type(data.get("offset")) is int
            and data["offset"] == 0
            and type(data.get("total")) is int
            and isinstance(data.get("data"), list)
            and data["total"] == len(data["data"]) <= MAX_CVES
        ):
            duplicates = set()
            seen = set()
            for item in data["data"]:
                if isinstance(item, dict) and isinstance(item.get("cve"), str):
                    if item["cve"] in seen:
                        duplicates.add(item["cve"])
                    seen.add(item["cve"])
            for item in data["data"]:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("cve"), str)
                    or item["cve"] not in missing
                    or item["cve"] in duplicates
                ):
                    continue
                record = _epss_record(
                    {
                        "score": item.get("epss"),
                        "percentile": item.get("percentile"),
                        "score_date": item.get("date"),
                        "retrieved_at": stamp,
                    },
                    now,
                )
                if record is not None:
                    epss[item["cve"]] = record
                    returned.add(item["cve"])
                    changed = True
        epss_failed.update(set(missing) - returned)
    if network is True and _needs_refresh(kev, now):
        data = _fetch_json(_KEV_HOST, _KEV_PATH, MAX_CACHE_BYTES, deadline)
        candidate = None
        if data and isinstance(data.get("vulnerabilities"), list):
            rows = data["vulnerabilities"]
            count = data.get("count")
            released = data.get("dateReleased")
            if (
                isinstance(count, int)
                and not isinstance(count, bool)
                and count == len(rows)
                and 0 < count <= 100000
                and isinstance(released, str)
                and len(released) <= 40
                and _instant(released, now) is not None
                and isinstance(data.get("catalogVersion"), str)
                and re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", data["catalogVersion"])
                and data["catalogVersion"].replace(".", "-") == released[:10]
            ):
                entries = {}
                for item in rows:
                    if not isinstance(item, dict):
                        entries = {}
                        break
                    cve = item.get("cveID")
                    if not isinstance(cve, str) or not _CVE.fullmatch(cve) or cve in entries:
                        entries = {}
                        break
                    entries[cve] = {
                        "date_added": item.get("dateAdded"),
                        "due_date": item.get("dueDate"),
                    }
                candidate = _kev_record(
                    {"entries": entries, "catalog_date": released[:10], "retrieved_at": stamp}, now
                )
        if candidate is not None:
            kev, changed = candidate, True
        else:
            kev_failed = True
    if changed and allowed_cache:
        newest = sorted(epss, key=lambda cve: epss[cve]["retrieved_at"], reverse=True)[
            :MAX_CACHE_RECORDS
        ]
        _write_cache(
            cache_dir, {"schema_version": 1, "epss": {cve: epss[cve] for cve in newest}, "kev": kev}
        )
    for item in result["cves"]:
        cve = item["cve_id"]
        record = epss.get(cve)
        if record is not None:
            item["epss"] = {
                "status": "current"
                if cve not in epss_failed and _fresh(record, now, "score_date")
                else "stale",
                **record,
            }
        if kev is not None:
            entry = kev["entries"].get(cve)
            current = not kev_failed and _fresh(kev, now, "catalog_date")
            if entry is not None or current:
                item["kev"] = {
                    "status": "current" if current else "stale",
                    "in_catalog": entry is not None,
                    "date_added": entry["date_added"] if entry else None,
                    "due_date": entry["due_date"] if entry else None,
                    "catalog_date": kev["catalog_date"],
                    "retrieved_at": kev["retrieved_at"],
                }
    return result
