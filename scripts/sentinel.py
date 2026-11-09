"""ca9 sentinel: review new releases of popular npm and PyPI packages every hour.

Each run finds versions of watched packages published since the previous run,
reviews each one against the release before it with ``ca9.api.review_upgrades``
(a static diff of the two published artifacts; no package code is installed,
imported or executed), and writes the versions that look malicious to the
optional ``npm-suspicious`` and ``pypi-suspicious`` feed datasets. Clients that
predate those datasets ignore them; ``ca9.api.suspicious_matches`` reads them.

Entry shape: ``{name, version, previous, kinds, verdict (block|warn), evidence
(at most 3 strings of at most 200 printable characters; control and bidi
characters from the package are removed), reviewed_at, published_at}``.

Watch list
    ``sentinel/watch-npm.json`` and ``sentinel/watch-pypi.json`` are checked in,
    ranked by downloads, and a run watches the first ``--top`` names (5,000 by
    default). They are checked in rather than fetched every hour so that a change
    to what is watched is reviewed like code, the hourly job depends on no
    third-party ranking service, and a run spends no requests on ranking.
    ``python scripts/sentinel.py watchlist --ecosystem npm|pypi`` rebuilds them.

    * npm: ``lib/top-download.js`` of github.com/wooorm/npm-high-impact, MIT
      licensed (copyright Titus Wormer; the license text is kept in the file's
      ``notice``). It lists every package npm counts as high impact through
      1,000,000 or more weekly downloads, most downloaded first.
    * PyPI: the packages.ecosyste.ms listing of pypi.org sorted by last-month
      downloads. Its data is licensed CC BY-SA 4.0, so the derived list file is
      CC BY-SA 4.0 too and carries the attribution. hugovk/top-pypi-packages was
      not used because its repository states no license.

Finding new versions
    Registry metadata, checked conditionally. npm: a ``HEAD`` on the packument
    returns ``Last-Modified`` (registry.npmjs.org ignores ``If-Modified-Since``
    but answers ``HEAD``; checked on 2026-11-07), and a packument unchanged since
    the watermark is not downloaded; otherwise its ``time`` map gives publish
    times. PyPI: ``HEAD /pypi/<name>/json`` returns ``X-PyPI-Last-Serial``, which
    is compared with the global serial (``HEAD /simple/``) that an earlier run
    recorded at or before the watermark; only projects changed since are
    downloaded, and the earliest ``upload_time`` of each version in ``releases``
    is its publish time. ETags would need per-package state carried between runs;
    these checks save the same downloads with one number per ecosystem. Requests
    send a ca9-sentinel User-Agent, accept gzip, run ``--workers`` at a time,
    retry 429 and 5xx with backoff, and stop reading a document past 64 MiB.

Window and state
    A run covers versions published in (watermark, now - 20 minutes]; the settle
    time exceeds the CDN cache lifetimes (npm 5 minutes, PyPI 15) so a version is
    visible before its window closes. State is kept in each dataset's
    ``sentinel`` object: the ``watermark``; ``lagging`` packages whose check failed
    or was not reached, each with its own start; ``pending`` versions found but
    not yet reviewed (budget, or a transient failure retried up to
    ``--max-attempts`` times); PyPI ``serial_marks``; and the run's ``coverage``
    (watched, checked, new versions, reviewed, incomplete, flagged, deferred and
    why). Without a readable previous bundle only the last
    ``--initial-lookback-hours`` (3) are reviewed. A watermark older than
    ``--max-lookback-hours`` (48) is clamped and the skipped gap is recorded.

What is reviewed
    Each new version against the highest earlier stable version published before
    it (yanked PyPI releases are not used as the base). Prereleases are counted
    but not reviewed unless ``--include-prereleases`` is given, since npm and pip
    do not install them by default. Versions already unpublished are counted.

Verdicts
    block: a review BLOCK kind that runs or pulls in code at install, import or
    interpreter start: new_pth_code, new_sitecustomize, new_install_hook,
    new_decode_exec, new_git_or_url_dependency, ships_agent_or_editor_hook,
    shadows_system_command.
    warn: the other BLOCK kinds, usually packaging accidents rather than payloads
    (ambiguous_package_contents, uninspectable_import_time_code,
    lockfile_artifact_mismatch), and BLOCK kinds this script does not know yet.
    warn: two combinations of WARN kinds. publisher_change with
    new_import_time_network, new_import_time_exec or obfuscation_growth: a release
    published outside the package's trusted publisher, or by an account that is not
    a maintainer, that also ships new code reaching the network or a process, the
    shape of a publish with a stolen token. obfuscation_growth with
    new_import_time_network or new_import_time_exec: an obfuscated payload that acts
    at import, the shape of the September 2025 chalk and debug wallet drainer. Each
    WARN kind alone is common in legitimate releases and never makes an entry.
    Entries in ``sentinel/allow.json`` (reviewed false positives) are never
    emitted; an optional ``kinds`` list narrows an entry to those kinds.

Bounds
    Time: ``--time-budget-minutes`` (30) covers discovery and review; discovery may
    use ``--discovery-share`` (half) of it; a review starts only with
    ``--min-review-seconds`` (30) left, runs at most ``--review-seconds`` (120),
    and at most ``--max-reviews`` (400) run. Whatever is left stays pending and the
    coverage says so. With the OSV build and the publish job this fits an hourly
    schedule. Size: entries are kept ``--retain-days`` (30), at most
    ``--max-entries`` (1,000) per ecosystem, newest first, and each dataset's
    entries are cut to ``--max-dataset-kb`` (1,024 KiB); ``pending`` and
    ``lagging`` hold at most 1,000 items. That bounds the two datasets to about
    2.5 MiB.

Usage:
    python scripts/sentinel.py run --previous prev-latest.json \\
        --bundle feed_build/latest.json --manifest feed_build/manifest.json
    python scripts/sentinel.py watchlist --ecosystem npm --top 10000
"""

from __future__ import annotations

import argparse
import http.client
import json
import math
import re
import sys
import time
import urllib.error
import urllib.request
import zlib
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

from packaging.utils import canonicalize_name

from ca9 import __version__
from ca9.version_order import is_prerelease, same_version, version_key

ECOSYSTEMS = ("npm", "pypi")
STATE_SCHEMA = "ca9.sentinel.state.v1"
ALLOW_SCHEMA = "ca9.sentinel.allow.v1"
WATCHLIST_SCHEMA = "ca9.sentinel.watchlist.v1"
USER_AGENT = f"ca9-sentinel/{__version__} (+https://github.com/duriantaco/ca9)"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_JSON = "https://pypi.org/pypi/{name}/json"
PYPI_SIMPLE = "https://pypi.org/simple/"
SENTINEL_DIR = Path(__file__).resolve().parents[1] / "sentinel"
MAX_METADATA_BYTES = 64 * 1024 * 1024
BLOCK_VERDICT_KINDS = frozenset(
    {
        "new_pth_code",
        "new_sitecustomize",
        "new_install_hook",
        "new_decode_exec",
        "new_git_or_url_dependency",
        "ships_agent_or_editor_hook",
        "shadows_system_command",
    }
)
WARN_COMBINATIONS = (
    (
        "publisher_change",
        frozenset({"new_import_time_network", "new_import_time_exec", "obfuscation_growth"}),
    ),
    ("obfuscation_growth", frozenset({"new_import_time_network", "new_import_time_exec"})),
)
RETRY_REASONS = frozenset(
    {
        "timeout",
        "registry_unreachable",
        "artifact_fetch_failed",
        "artifact_integrity_failed",
        "review_error",
    }
)
MAX_EVIDENCE = 3
MAX_EVIDENCE_CHARS = 200
MAX_SERIAL_MARKS = 100
MAX_SAMPLES = 20
MARK_MARGIN = timedelta(minutes=5)
NPM_HIGH_IMPACT = "wooorm/npm-high-impact"
ECOSYSTEMS_PYPI_LISTING = (
    "https://packages.ecosyste.ms/api/v1/registries/pypi.org/packages"
    "?sort=downloads&order=desc&per_page={per_page}&page={page}"
)


class RegistryError(Exception):
    """A registry request failed; the package is checked again on the next run."""


class PackageNotFound(Exception):
    """The registry has no such package."""


class MetadataTooLarge(Exception):
    """A registry document exceeded the size cap."""


class AllowlistError(ValueError):
    """The allowlist file is missing, unreadable or has an invalid entry."""


@dataclass(frozen=True)
class Release:
    version: str
    published: datetime
    available: bool = True
    yanked: bool = False


@dataclass(frozen=True)
class Probe:
    modified: datetime | None = None
    serial: int | None = None


class Registry(Protocol):
    def probe(self, ecosystem: str, name: str) -> Probe: ...

    def releases(self, ecosystem: str, name: str) -> list[Release]: ...

    def marker(self, ecosystem: str) -> int | None: ...


Review = Callable[[dict[str, Any], dict[str, Any]], Mapping[str, Any]]


@dataclass(frozen=True)
class SentinelConfig:
    top: int = 5000
    time_budget_seconds: float = 1800
    discovery_share: float = 0.5
    min_review_seconds: float = 30
    review_seconds: float = 120
    request_timeout: float = 20
    settle_minutes: float = 20
    initial_lookback_hours: float = 3
    max_lookback_hours: float = 48
    retain_days: float = 30
    max_entries: int = 1000
    max_dataset_bytes: int = 1024 * 1024
    max_reviews: int = 400
    max_artifact_mb: int = 50
    workers: int = 16
    review_workers: int = 4
    include_prereleases: bool = False
    max_pending: int = 1000
    max_lagging: int = 1000
    max_attempts: int = 3


@dataclass
class Candidate:
    ecosystem: str
    name: str
    version: str
    previous: str | None
    published: datetime
    attempts: int = 0

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    def to_state(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "previous": self.previous,
            "published": _iso(self.published),
            "attempts": self.attempts,
        }


@dataclass(frozen=True)
class AllowEntry:
    ecosystem: str
    name: str
    version: str
    kinds: frozenset[str] | None
    reason: str
    reviewed_by: str


class Allowlist:
    """Reviewed false positives: matching versions are never emitted."""

    def __init__(self, entries: Iterable[AllowEntry] = ()) -> None:
        self.entries = tuple(entries)

    def allows(self, ecosystem: str, name: str, version: str, kinds: Iterable[str]) -> bool:
        normalized = normalize_name(ecosystem, name)
        flagged = set(kinds)
        for item in self.entries:
            if item.ecosystem != ecosystem or item.name != normalized:
                continue
            if item.version != "*" and not same_version(ecosystem, item.version, version):
                continue
            if item.kinds is not None and not flagged <= item.kinds:
                continue
            return True
        return False


def load_allowlist(path: str | Path) -> Allowlist:
    """Read ``allow.json``; every entry needs ecosystem, name, an exact version or
    ``"*"``, a reason and the reviewer. Raises AllowlistError otherwise."""
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise AllowlistError(f"{path}: cannot read the allowlist: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != ALLOW_SCHEMA:
        raise AllowlistError(f"{path}: schema must be {ALLOW_SCHEMA}")
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise AllowlistError(f"{path}: entries must be a list")
    return Allowlist(
        _allow_entry(item, f"{path}: entry {index}") for index, item in enumerate(entries)
    )


def _allow_entry(item: object, where: str) -> AllowEntry:
    if not isinstance(item, dict):
        raise AllowlistError(f"{where} must be an object")
    ecosystem = item.get("ecosystem")
    if ecosystem not in ECOSYSTEMS:
        raise AllowlistError(f"{where}: ecosystem must be npm or pypi")
    values: dict[str, str] = {}
    for key in ("name", "version", "reason", "reviewed_by"):
        value = item.get(key)
        if not isinstance(value, str) or not value.strip():
            raise AllowlistError(f"{where} needs a non-empty {key}")
        values[key] = value.strip()
    version = values["version"]
    if version != "*" and ("*" in version or re.search(r"\s", version)):
        raise AllowlistError(f'{where}: version must be an exact version or "*"')
    kinds = item.get("kinds")
    allowed_kinds = None
    if kinds is not None:
        if not isinstance(kinds, list) or not kinds:
            raise AllowlistError(f"{where}: kinds must be a non-empty list when given")
        if not all(isinstance(kind, str) and kind.strip() for kind in kinds):
            raise AllowlistError(f"{where}: kinds must be strings")
        allowed_kinds = frozenset(kind.strip() for kind in kinds)
    return AllowEntry(
        ecosystem=str(ecosystem),
        name=normalize_name(str(ecosystem), values["name"]),
        version=version,
        kinds=allowed_kinds,
        reason=values["reason"],
        reviewed_by=values["reviewed_by"],
    )


def load_watchlist(path: str | Path, *, top: int) -> list[str]:
    """The first ``top`` distinct, normalized names of a watch-list file."""
    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, dict) or not isinstance(raw.get("packages"), list):
        raise ValueError(f"{path}: a watch list needs a packages list")
    ecosystem = raw.get("ecosystem")
    if ecosystem not in ECOSYSTEMS:
        raise ValueError(f"{path}: ecosystem must be npm or pypi")
    names: list[str] = []
    seen: set[str] = set()
    for item in raw["packages"]:
        if len(names) >= top:
            break
        if not isinstance(item, str) or not item.strip():
            continue
        normalized = normalize_name(ecosystem, item)
        if normalized not in seen:
            seen.add(normalized)
            names.append(normalized)
    return names


def read_previous_bundle(path: str | Path) -> dict[str, Any] | None:
    """The previously published bundle, or None when it cannot be read."""
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == "npm":
        return name.strip().lower()
    return str(canonicalize_name(name))


def classify(result: Mapping[str, Any] | None) -> tuple[str, list[str], list[str]] | None:
    """Verdict, kinds and evidence lines for one review result, or None (not flagged)."""
    if not isinstance(result, Mapping) or result.get("status") != "reviewed":
        return None
    block = _deltas(result.get("block"))
    warn = _deltas(result.get("warn"))
    if block:
        strong = [item for item in block if item["kind"] in BLOCK_VERDICT_KINDS]
        chosen = strong + [item for item in block if item["kind"] not in BLOCK_VERDICT_KINDS]
        verdict = "warn"
        if strong:
            verdict = "block"
    else:
        present = {item["kind"] for item in warn}
        matched: set[str] = set()
        for anchor, partners in WARN_COMBINATIONS:
            if anchor in present and present & partners:
                matched.add(anchor)
                matched.update(present & partners)
        if not matched:
            return None
        chosen = [item for item in warn if item["kind"] in matched]
        verdict = "warn"
    kinds = sorted({item["kind"] for item in chosen})
    return verdict, kinds, [_evidence_line(item) for item in chosen[:MAX_EVIDENCE]]


def _deltas(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value
        if isinstance(item, dict) and isinstance(item.get("kind"), str) and item["kind"]
    ]


def _evidence_line(delta: Mapping[str, Any]) -> str:
    location = str(delta.get("path") or "")
    line = delta.get("line")
    if location and isinstance(line, int) and not isinstance(line, bool):
        location = f"{location}:{line}"
    text = " ".join(str(delta.get("snippet") or "").split())
    if not text:
        text = " ".join(str(delta.get("detail") or "").split())
    value = f"{delta['kind']}: {text}"
    if location:
        value = f"{delta['kind']} {location}: {text}"
    value = "".join(char for char in " ".join(value.split()) if char.isprintable())
    if len(value) > MAX_EVIDENCE_CHARS:
        value = value[: MAX_EVIDENCE_CHARS - 3] + "..."
    return value


def review_with_ca9(pair: dict[str, Any], options: dict[str, Any]) -> Mapping[str, Any]:
    """Review one upgrade pair with ``ca9.api.review_upgrades`` (static, never raises)."""
    from ca9.api import review_upgrades

    outcome = review_upgrades([pair], options=options)
    results = outcome.get("results") or []
    if results and isinstance(results[0], Mapping):
        return results[0]
    receipt = outcome.get("receipt") or {}
    return {
        **pair,
        "status": "skipped",
        "reason": "review_error",
        "detail": str(receipt.get("error") or "the review returned no result"),
        "block": [],
        "warn": [],
    }


class HttpRegistry:
    """Read-only registry metadata over https with a polite User-Agent."""

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        max_bytes: int = MAX_METADATA_BYTES,
        retries: int = 2,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.retries = retries
        self.opener = opener or urllib.request.urlopen
        self.sleep = sleep

    def probe(self, ecosystem: str, name: str) -> Probe:
        if ecosystem == "npm":
            headers, _body = self.fetch(_npm_url(name), method="HEAD")
            return Probe(modified=_http_date(headers.get("Last-Modified")))
        headers, _body = self.fetch(_pypi_url(name), method="HEAD")
        return Probe(serial=_int_or_none(headers.get("X-PyPI-Last-Serial")))

    def releases(self, ecosystem: str, name: str) -> list[Release]:
        url = _pypi_url(name)
        if ecosystem == "npm":
            url = _npm_url(name)
        _headers, body = self.fetch(url)
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise RegistryError(f"{url}: invalid JSON") from exc
        if not isinstance(document, dict):
            raise RegistryError(f"{url}: metadata is not an object")
        if ecosystem == "npm":
            return _npm_releases(document, url)
        return _pypi_releases(document, url)

    def marker(self, ecosystem: str) -> int | None:
        if ecosystem != "pypi":
            return None
        headers, _body = self.fetch(PYPI_SIMPLE, method="HEAD")
        return _int_or_none(headers.get("X-PyPI-Last-Serial"))

    def fetch(self, url: str, *, method: str = "GET") -> tuple[Any, bytes]:
        request = urllib.request.Request(
            url,
            method=method,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
            },
        )
        failure = ""
        for attempt in range(self.retries + 1):
            delay = min(2.0**attempt, 10.0)
            try:
                with self.opener(request, timeout=self.timeout) as response:
                    headers = response.headers
                    body = b""
                    if method == "GET":
                        body = self._read(response, headers, url)
                    return headers, body
            except urllib.error.HTTPError as exc:
                if exc.code in {404, 410}:
                    raise PackageNotFound(url) from None
                if exc.code != 429 and exc.code < 500:
                    raise RegistryError(f"{url}: HTTP {exc.code}") from None
                failure = f"HTTP {exc.code}"
                delay = _retry_after(exc.headers, delay)
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                failure = f"{type(exc).__name__}: {exc}"
            if attempt < self.retries:
                self.sleep(delay)
        raise RegistryError(f"{url}: {failure}"[:300])

    def _read(self, response: Any, headers: Any, url: str) -> bytes:
        raw = bytearray()
        while True:
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > self.max_bytes:
                raise MetadataTooLarge(f"{url} is larger than {self.max_bytes} bytes")
        if str(headers.get("Content-Encoding") or "").lower() != "gzip":
            return bytes(raw)
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            data = decompressor.decompress(bytes(raw), self.max_bytes + 1)
        except zlib.error as exc:
            raise RegistryError(f"{url}: invalid gzip body") from exc
        if len(data) > self.max_bytes or decompressor.unconsumed_tail:
            raise MetadataTooLarge(f"{url} is larger than {self.max_bytes} bytes")
        return data


def _npm_url(name: str) -> str:
    return f"{NPM_REGISTRY}/{quote(name, safe='@')}"


def _pypi_url(name: str) -> str:
    return PYPI_JSON.format(name=quote(name, safe=""))


def _npm_releases(document: dict[str, Any], url: str) -> list[Release]:
    times = document.get("time")
    versions = document.get("versions")
    if not isinstance(times, dict):
        raise RegistryError(f"{url}: packument has no time map")
    if not isinstance(versions, dict):
        versions = {}
    releases = []
    for version, stamp in times.items():
        if version in {"created", "modified"}:
            continue
        published = _parse_time(stamp)
        if published is not None:
            releases.append(Release(str(version), published, available=version in versions))
    return sorted(releases, key=lambda item: (item.published, item.version))


def _pypi_releases(document: dict[str, Any], url: str) -> list[Release]:
    listed = document.get("releases")
    if not isinstance(listed, dict):
        raise RegistryError(f"{url}: project JSON has no releases map")
    releases = []
    for version, files in listed.items():
        entries = [item for item in files or [] if isinstance(item, dict)]
        stamps = [
            _parse_time(item.get("upload_time_iso_8601") or item.get("upload_time"))
            for item in entries
        ]
        known = [stamp for stamp in stamps if stamp is not None]
        if not known:
            continue
        yanked = all(bool(item.get("yanked")) for item in entries)
        releases.append(Release(str(version), min(known), available=True, yanked=yanked))
    return sorted(releases, key=lambda item: (item.published, item.version))


def _retry_after(headers: Any, default: float) -> float:
    value = None
    if headers is not None:
        value = headers.get("Retry-After")
    if isinstance(value, str) and value.strip().isdigit():
        return min(float(value.strip()), 30.0)
    return default


def _http_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _int_or_none(value: object) -> int | None:
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text[-1:] in {"Z", "z"}:
        text = text[:-1] + "+00:00"
    match = re.fullmatch(r"(.*T\d{2}:\d{2}:\d{2})\.(\d+)(.*)", text)
    if match is not None:
        fraction = (match.group(2) + "000000")[:6]
        text = f"{match.group(1)}.{fraction}{match.group(3)}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _whole_seconds(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(microsecond=0)


@dataclass
class _Check:
    status: str
    candidates: list[Candidate] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    detail: str = ""


class _EcosystemRun:
    def __init__(
        self,
        ecosystem: str,
        names: Sequence[str],
        previous: Mapping[str, Any] | None,
        config: SentinelConfig,
        moment: datetime,
    ) -> None:
        self.ecosystem = ecosystem
        self.names = list(names)
        self.config = config
        self.moment = moment
        self.counts: Counter = Counter()
        self.failed_reasons: Counter = Counter()
        self.samples: list[dict[str, str]] = []
        self.gap: dict[str, str] | None = None
        self.new_entries: dict[tuple[str, str], dict[str, Any]] = {}
        self.cleared: set[tuple[str, str]] = set()
        self.next_pending: list[Candidate] = []
        self.next_lagging: dict[str, datetime] = {}
        self.budget_hit = False
        dataset = _previous_dataset(previous, ecosystem)
        state = dataset.get("sentinel")
        if not isinstance(state, dict):
            state = {}
        self.previous_entries = dataset.get("packages")
        floor = moment - timedelta(hours=config.max_lookback_hours)
        watermark = _parse_time(state.get("watermark"))
        self.source = "previous"
        if previous is None:
            self.source = "fallback"
        elif watermark is None:
            self.source = "initial"
        if watermark is None:
            watermark = moment - timedelta(hours=config.initial_lookback_hours)
        if watermark < floor:
            self.gap = {"since": _iso(watermark), "until": _iso(floor)}
            self.source = "clamped"
            watermark = floor
        self.watermark = _whole_seconds(watermark)
        self.until = _whole_seconds(moment - timedelta(minutes=config.settle_minutes))
        watched = set(self.names)
        self.lagging: dict[str, datetime] = {}
        raw_lagging = state.get("lagging")
        if isinstance(raw_lagging, dict):
            for name, since in raw_lagging.items():
                parsed = _parse_time(since)
                if name in watched and parsed is not None:
                    self.lagging[name] = max(parsed, floor)
        self.pending = _pending_from_state(ecosystem, state.get("pending"), moment, config)
        self.marks = _marks_from_state(state.get("serial_marks"), floor)

    def since(self, name: str) -> datetime:
        return self.lagging.get(name, self.watermark)

    def mark_for(self, since: datetime) -> int | None:
        usable = [serial for at, serial in self.marks if at + MARK_MARGIN <= since]
        if not usable:
            return None
        return max(usable)

    def changed(self, probe: Probe, since: datetime) -> bool:
        if self.ecosystem == "npm":
            return probe.modified is None or probe.modified + timedelta(seconds=1) > since
        mark = self.mark_for(since)
        if probe.serial is None or mark is None:
            return True
        return probe.serial > mark

    def record_check(self, name: str, since: datetime, check: _Check | None) -> None:
        if check is None:
            self.counts["not_reached"] += 1
            self.next_lagging[name] = since
            self.budget_hit = True
            return
        self.counts.update(check.counts)
        if check.status in {"unchanged", "checked"}:
            self.counts["checked"] += 1
            if check.status == "unchanged":
                self.counts["unchanged"] += 1
            return
        if check.status == "not_found":
            self.counts["not_found"] += 1
            return
        self.counts["metadata_errors"] += 1
        self._sample(name, "", check.detail or check.status)
        if check.status == "error":
            self.next_lagging[name] = since

    def record_review(
        self,
        candidate: Candidate,
        result: Mapping[str, Any] | None,
        allowlist: Allowlist,
    ) -> None:
        if result is None:
            self.counts["deferred"] += 1
            self.next_pending.append(candidate)
            return
        identity = (candidate.name, candidate.version)
        if result.get("status") == "reviewed":
            self.counts["reviewed"] += 1
            if result.get("complete") is False:
                self.counts["incomplete"] += 1
                self.counts["partial"] += 1
            outcome = classify(result)
            if outcome is None:
                self.cleared.add(identity)
                return
            verdict, kinds, evidence = outcome
            if allowlist.allows(self.ecosystem, candidate.name, candidate.version, kinds):
                self.counts["allowlisted"] += 1
                self.cleared.add(identity)
                return
            self.new_entries[identity] = {
                "name": candidate.name,
                "version": candidate.version,
                "previous": candidate.previous,
                "kinds": kinds,
                "verdict": verdict,
                "evidence": evidence,
                "reviewed_at": _iso(self.moment),
                "published_at": _iso(candidate.published),
            }
            return
        reason = str(result.get("reason") or "review_error")
        self.counts["incomplete"] += 1
        self.failed_reasons[reason] += 1
        if reason in RETRY_REASONS:
            candidate.attempts += 1
            if candidate.attempts < self.config.max_attempts:
                self.next_pending.append(candidate)
                return
            self.counts["abandoned"] += 1
        self._sample(candidate.name, candidate.version, reason)

    def _sample(self, name: str, version: str, reason: str) -> None:
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append({"name": name, "version": version, "reason": reason[:200]})

    def dataset(self, allowlist: Allowlist, elapsed: float) -> dict[str, Any]:
        entries = self._entries(allowlist)
        watermark = max(self.watermark, self.until)
        lagging = dict(self.next_lagging)
        if len(lagging) > self.config.max_lagging:
            watermark = min(lagging.values())
            lagging = {}
            self.counts["lagging_overflow"] += 1
        pending = sorted(
            self.next_pending, key=lambda item: (item.published, item.name, item.version)
        )
        if len(pending) > self.config.max_pending:
            self.counts["dropped_pending"] += len(pending) - self.config.max_pending
            pending = pending[-self.config.max_pending :]
        state: dict[str, Any] = {
            "schema": STATE_SCHEMA,
            "watermark": _iso(watermark),
            "lagging": {name: _iso(since) for name, since in sorted(lagging.items())},
            "pending": [item.to_state() for item in pending],
        }
        if self.ecosystem == "pypi":
            state["serial_marks"] = [[_iso(at), serial] for at, serial in self.marks]
        state["coverage"] = self._coverage(entries, pending, lagging, elapsed)
        return {"packages": entries, "sentinel": state}

    def _entries(self, allowlist: Allowlist) -> list[dict[str, Any]]:
        keep_after = self.moment - timedelta(days=self.config.retain_days)
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        previous = self.previous_entries
        if not isinstance(previous, list):
            previous = []
        for item in previous:
            if not _valid_entry(item):
                self.counts["invalid_previous"] += 1
                continue
            reviewed_at = _parse_time(item.get("reviewed_at"))
            if reviewed_at is None or reviewed_at < keep_after:
                self.counts["expired_entries"] += 1
                continue
            name = normalize_name(self.ecosystem, item["name"])
            if allowlist.allows(self.ecosystem, name, item["version"], item["kinds"]):
                self.counts["allowlist_removed"] += 1
                continue
            merged[(name, item["version"])] = {**item, "name": name}
        for identity in self.cleared:
            merged.pop(identity, None)
        merged.update(self.new_entries)
        self.counts["flagged"] = len(self.new_entries)
        newest = sorted(merged.values(), key=lambda item: str(item["reviewed_at"]), reverse=True)
        if len(newest) > self.config.max_entries:
            self.counts["dropped_entries"] += len(newest) - self.config.max_entries
            newest = newest[: self.config.max_entries]
        sizes = [len(json.dumps(item, separators=(",", ":"))) + 1 for item in newest]
        while newest and sum(sizes) > self.config.max_dataset_bytes:
            newest.pop()
            sizes.pop()
            self.counts["dropped_entries"] += 1
        return sorted(newest, key=lambda item: (item["name"], item["version"]))

    def _coverage(
        self,
        entries: list[dict[str, Any]],
        pending: list[Candidate],
        lagging: dict[str, datetime],
        elapsed: float,
    ) -> dict[str, Any]:
        counts = self.counts
        incomplete_discovery = counts["not_reached"] + counts["metadata_errors"]
        complete = (
            incomplete_discovery == 0
            and counts["deferred"] == 0
            and counts["incomplete"] == 0
            and counts["abandoned"] == 0
            and self.gap is None
            and not pending
            and not lagging
        )
        coverage: dict[str, Any] = {
            "run_at": _iso(self.moment),
            "window": {"since": _iso(self.watermark), "until": _iso(self.until)},
            "watermark_source": self.source,
            "watched": len(self.names),
            "checked": counts["checked"],
            "unchanged": counts["unchanged"],
            "not_found": counts["not_found"],
            "metadata_errors": counts["metadata_errors"],
            "not_reached": counts["not_reached"],
            "new_versions": counts["new_versions"],
            "prereleases_skipped": counts["prereleases_skipped"],
            "unpublished": counts["unpublished"],
            "reviewed": counts["reviewed"],
            "incomplete": counts["incomplete"],
            "failed_reasons": dict(sorted(self.failed_reasons.items())),
            "deferred": counts["deferred"],
            "abandoned": counts["abandoned"],
            "flagged": counts["flagged"],
            "allowlisted": counts["allowlisted"],
            "entries": len(entries),
            "expired_entries": counts["expired_entries"],
            "dropped_entries": counts["dropped_entries"],
            "pending": len(pending),
            "lagging": len(lagging),
            "budget_hit": self.budget_hit,
            "complete": complete,
            "elapsed_seconds": round(elapsed, 1),
        }
        for key in ("allowlist_removed", "dropped_pending", "lagging_overflow", "invalid_previous"):
            if counts[key]:
                coverage[key] = counts[key]
        if self.gap is not None:
            coverage["gap"] = dict(self.gap)
        if self.samples:
            coverage["unreviewed"] = list(self.samples)
        return coverage


def _previous_dataset(previous: Mapping[str, Any] | None, ecosystem: str) -> dict[str, Any]:
    if not isinstance(previous, Mapping):
        return {}
    datasets = previous.get("datasets")
    if not isinstance(datasets, Mapping):
        return {}
    dataset = datasets.get(f"{ecosystem}-suspicious")
    if not isinstance(dataset, dict):
        return {}
    return dataset


def _pending_from_state(
    ecosystem: str, raw: object, moment: datetime, config: SentinelConfig
) -> list[Candidate]:
    if not isinstance(raw, list):
        return []
    keep_after = moment - timedelta(days=config.retain_days)
    pending = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        version = item.get("version")
        published = _parse_time(item.get("published"))
        previous = item.get("previous")
        attempts = item.get("attempts")
        if not isinstance(name, str) or not isinstance(version, str) or published is None:
            continue
        if previous is not None and not isinstance(previous, str):
            continue
        if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
            attempts = 0
        if published < keep_after:
            continue
        pending.append(
            Candidate(
                ecosystem, normalize_name(ecosystem, name), version, previous, published, attempts
            )
        )
    return pending


def _marks_from_state(raw: object, floor: datetime) -> list[tuple[datetime, int]]:
    if not isinstance(raw, list):
        return []
    marks = []
    for item in raw:
        if not isinstance(item, list) or len(item) != 2:
            continue
        at = _parse_time(item[0])
        serial = item[1]
        if at is None or not isinstance(serial, int) or isinstance(serial, bool):
            continue
        if at >= floor - timedelta(hours=2):
            marks.append((at, serial))
    return sorted(marks)[-MAX_SERIAL_MARKS:]


def _valid_entry(item: object) -> bool:
    if not isinstance(item, dict):
        return False
    for key in ("name", "version"):
        value = item.get(key)
        if not isinstance(value, str) or not value.strip():
            return False
    kinds = item.get("kinds")
    if item.get("verdict") not in {"block", "warn"} or not isinstance(kinds, list) or not kinds:
        return False
    return all(isinstance(kind, str) and kind for kind in kinds)


def _previous_version(ecosystem: str, target: Release, releases: Sequence[Release]) -> str | None:
    target_key = version_key(ecosystem, target.version)
    if target_key is None:
        return None
    earlier = []
    for other in releases:
        if other.version == target.version or not other.available or other.yanked:
            continue
        if other.published >= target.published:
            continue
        key = version_key(ecosystem, other.version)
        if key is not None and key < target_key:
            earlier.append((key, other.version))
    stable = [item for item in earlier if not is_prerelease(ecosystem, item[1])]
    pool = stable or earlier
    if not pool:
        return None
    return max(pool, key=lambda item: item[0])[1]


def _check_package(
    registry: Registry,
    run: _EcosystemRun,
    name: str,
    since: datetime,
    include_prereleases: bool,
) -> _Check:
    ecosystem = run.ecosystem
    try:
        probe = registry.probe(ecosystem, name)
        if not run.changed(probe, since):
            return _Check("unchanged")
        releases = registry.releases(ecosystem, name)
    except PackageNotFound:
        return _Check("not_found")
    except MetadataTooLarge as exc:
        return _Check("too_large", detail=str(exc)[:200])
    except Exception as exc:
        return _Check("error", detail=f"{type(exc).__name__}: {exc}"[:200])
    check = _Check("checked")
    for release in releases:
        if not since < release.published <= run.until:
            continue
        check.counts["new_versions"] += 1
        if not release.available:
            check.counts["unpublished"] += 1
            continue
        if not include_prereleases and is_prerelease(ecosystem, release.version):
            check.counts["prereleases_skipped"] += 1
            continue
        previous = _previous_version(ecosystem, release, releases)
        check.candidates.append(
            Candidate(ecosystem, name, release.version, previous, release.published)
        )
    return check


def _bounded(
    items: Sequence[Any],
    worker: Callable[[Any], Any],
    *,
    workers: int,
    may_start: Callable[[], bool],
) -> list[tuple[Any, Any, bool]]:
    """Run ``worker`` with at most ``workers`` in flight, starting each item only while
    ``may_start()`` holds. Returns ``(item, result, started)`` triples."""
    outcomes: list[tuple[Any, Any, bool]] = []
    limit = max(1, workers)
    index = 0
    with ThreadPoolExecutor(max_workers=limit) as pool:
        running: dict[Any, Any] = {}
        while index < len(items) or running:
            while index < len(items) and len(running) < limit:
                item = items[index]
                index += 1
                if may_start():
                    running[pool.submit(worker, item)] = item
                else:
                    outcomes.append((item, None, False))
            if not running:
                continue
            done, _rest = wait(running, return_when=FIRST_COMPLETED)
            for future in done:
                item = running.pop(future)
                outcomes.append((item, future.result(), True))
    return outcomes


def run_sentinel(
    watchlists: Mapping[str, Sequence[str]],
    previous: Mapping[str, Any] | None,
    *,
    registry: Registry,
    review: Review | None = None,
    allowlist: Allowlist | None = None,
    config: SentinelConfig | None = None,
    now: datetime | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, dict[str, Any]]:
    """One sentinel run. Returns the ``npm-suspicious`` and ``pypi-suspicious`` datasets.

    ``previous`` is the previously published bundle (None when it could not be read).
    ``registry`` answers ``probe``, ``releases`` and ``marker``; ``review`` takes an
    upgrade pair and ``review_upgrades`` options and returns one review result.
    """
    settings = config or SentinelConfig()
    reviewer = review or review_with_ca9
    allowed = allowlist or Allowlist()
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    started = clock()
    budget_end = started + settings.time_budget_seconds
    discovery_end = started + settings.time_budget_seconds * settings.discovery_share
    runs = {
        ecosystem: _EcosystemRun(
            ecosystem, watchlists.get(ecosystem, ()), previous, settings, moment
        )
        for ecosystem in ECOSYSTEMS
    }
    try:
        serial = registry.marker("pypi")
    except (RegistryError, PackageNotFound, MetadataTooLarge):
        serial = None
    if serial is not None and clock() - started <= MARK_MARGIN.total_seconds():
        runs["pypi"].marks = (runs["pypi"].marks + [(_whole_seconds(moment), serial)])[
            -MAX_SERIAL_MARKS:
        ]

    tasks = []
    queues = [
        [
            (ecosystem, name)
            for name in runs[ecosystem].names
            if runs[ecosystem].since(name) < runs[ecosystem].until
        ]
        for ecosystem in ECOSYSTEMS
    ]
    for position in range(max((len(queue) for queue in queues), default=0)):
        for queue in queues:
            if position < len(queue):
                tasks.append(queue[position])

    def check(task: tuple[str, str]) -> _Check:
        ecosystem, name = task
        run = runs[ecosystem]
        return _check_package(registry, run, name, run.since(name), settings.include_prereleases)

    discovered: dict[tuple[str, str, str], Candidate] = {}
    for run in runs.values():
        for candidate in run.pending:
            discovered[candidate.key] = candidate
    for task, result, _started in _bounded(
        tasks, check, workers=settings.workers, may_start=lambda: clock() < discovery_end
    ):
        ecosystem, name = task
        run = runs[ecosystem]
        run.record_check(name, run.since(name), result)
        if result is not None:
            for candidate in result.candidates:
                discovered.setdefault(candidate.key, candidate)

    queue = sorted(
        discovered.values(),
        key=lambda item: (item.published, item.ecosystem, item.name, item.version),
    )
    started_reviews = [0]

    def may_review() -> bool:
        if started_reviews[0] >= settings.max_reviews:
            return False
        if budget_end - clock() < settings.min_review_seconds:
            return False
        started_reviews[0] += 1
        return True

    def review_one(candidate: Candidate) -> Mapping[str, Any]:
        pair = {
            "ecosystem": candidate.ecosystem,
            "name": candidate.name,
            "old": candidate.previous,
            "new": candidate.version,
        }
        options = {
            "network": True,
            "max_pairs": 1,
            "max_seconds": max(1.0, min(settings.review_seconds, budget_end - clock())),
            "max_artifact_mb": settings.max_artifact_mb,
            "request_timeout": settings.request_timeout,
        }
        try:
            result = reviewer(pair, options)
        except Exception as exc:
            return {"status": "skipped", "reason": "review_error", "detail": str(exc)[:200]}
        if not isinstance(result, Mapping):
            return {"status": "skipped", "reason": "review_error", "detail": "no result"}
        return result

    for candidate, result, was_started in _bounded(
        queue, review_one, workers=settings.review_workers, may_start=may_review
    ):
        run = runs[candidate.ecosystem]
        if not was_started:
            run.budget_hit = True
        run.record_review(candidate, result, allowed)

    elapsed = clock() - started
    return {
        f"{ecosystem}-suspicious": runs[ecosystem].dataset(allowed, elapsed)
        for ecosystem in ECOSYSTEMS
    }


def merge_into_bundle(
    bundle: dict[str, Any],
    datasets: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Add the sentinel datasets and a coverage summary to a built feed bundle."""
    merged = dict(bundle)
    merged["datasets"] = {**(bundle.get("datasets") or {}), **datasets}
    build_info = bundle.get("build_info")
    if not isinstance(build_info, dict):
        build_info = {}
    merged["build_info"] = {**build_info, "sentinel": dict(summary)}
    return merged


def _summary(datasets: Mapping[str, Any], error: str | None) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for ecosystem in ECOSYSTEMS:
        state = datasets.get(f"{ecosystem}-suspicious", {}).get("sentinel")
        if isinstance(state, dict) and isinstance(state.get("coverage"), dict):
            summary[ecosystem] = state["coverage"]
    if error:
        summary = {"error": error}
    return summary


def _carried_forward(previous: Mapping[str, Any] | None) -> dict[str, Any]:
    datasets = {}
    for ecosystem in ECOSYSTEMS:
        dataset = _previous_dataset(previous, ecosystem)
        packages = dataset.get("packages")
        if not isinstance(packages, list):
            packages = []
        kept: dict[str, Any] = {"packages": [item for item in packages if _valid_entry(item)]}
        if isinstance(dataset.get("sentinel"), dict):
            kept["sentinel"] = dataset["sentinel"]
        datasets[f"{ecosystem}-suspicious"] = kept
    return datasets


def _summary_lines(summary: Mapping[str, Any]) -> list[str]:
    if "error" in summary:
        return [f"sentinel: failed ({summary['error']}); previous suspicious datasets kept"]
    keys = (
        "watched",
        "checked",
        "unchanged",
        "metadata_errors",
        "not_reached",
        "new_versions",
        "reviewed",
        "incomplete",
        "deferred",
        "flagged",
        "allowlisted",
        "entries",
        "pending",
        "lagging",
    )
    lines = []
    for ecosystem in ECOSYSTEMS:
        coverage = summary.get(ecosystem)
        if not isinstance(coverage, dict):
            continue
        details = "  ".join(f"{key}={coverage.get(key, 0)}" for key in keys)
        state = "complete"
        if not coverage.get("complete"):
            state = "INCOMPLETE"
        window = coverage.get("window") or {}
        lines.append(
            f"sentinel {ecosystem}: {details}  window={window.get('since')}..{window.get('until')}"
            f"  {state}"
        )
    return lines


def _run_command(
    args: argparse.Namespace,
    *,
    registry: Registry | None,
    review: Review | None,
    now: datetime | None,
) -> int:
    try:
        allowlist = load_allowlist(args.allowlist)
    except AllowlistError as exc:
        print(f"sentinel: invalid allowlist: {exc}", file=sys.stderr)
        return 2
    try:
        bundle = json.loads(args.bundle.read_text())
    except (OSError, ValueError) as exc:
        print(f"sentinel: cannot read the built bundle {args.bundle}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(bundle, dict):
        print(f"sentinel: {args.bundle} is not a feed bundle", file=sys.stderr)
        return 2
    previous = None
    if args.previous is not None:
        previous = read_previous_bundle(args.previous)
    config = SentinelConfig(
        top=args.top,
        time_budget_seconds=args.time_budget_minutes * 60,
        discovery_share=args.discovery_share,
        min_review_seconds=args.min_review_seconds,
        review_seconds=args.review_seconds,
        settle_minutes=args.settle_minutes,
        initial_lookback_hours=args.initial_lookback_hours,
        max_lookback_hours=args.max_lookback_hours,
        retain_days=args.retain_days,
        max_entries=args.max_entries,
        max_dataset_bytes=args.max_dataset_kb * 1024,
        max_reviews=args.max_reviews,
        max_artifact_mb=args.max_artifact_mb,
        workers=args.workers,
        review_workers=args.review_workers,
        include_prereleases=args.include_prereleases,
        max_attempts=args.max_attempts,
    )
    error = None
    try:
        watchlists = {
            ecosystem: load_watchlist(args.watchlist_dir / f"watch-{ecosystem}.json", top=args.top)
            for ecosystem in ECOSYSTEMS
        }
        datasets = run_sentinel(
            watchlists,
            previous,
            registry=registry or HttpRegistry(timeout=config.request_timeout),
            review=review,
            allowlist=allowlist,
            config=config,
            now=now,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"[:500]
        datasets = _carried_forward(previous)
        print(
            f"sentinel failed: {error}; keeping the previous suspicious datasets", file=sys.stderr
        )
    summary = _summary(datasets, error)
    merged = merge_into_bundle(bundle, datasets, summary)
    args.bundle.write_text(json.dumps(merged, sort_keys=True, separators=(",", ":")) + "\n")
    if args.manifest is not None:
        manifest: Any = {}
        if args.manifest.is_file():
            try:
                manifest = json.loads(args.manifest.read_text())
            except (OSError, ValueError):
                manifest = {}
        if not isinstance(manifest, dict):
            manifest = {}
        manifest["sentinel"] = summary
        manifest["suspicious_counts"] = {
            name: len(dataset.get("packages") or []) for name, dataset in sorted(datasets.items())
        }
        args.manifest.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    for line in _summary_lines(summary):
        print(line)
    return 0


def build_npm_watchlist(
    registry: HttpRegistry, *, top: int, ref: str | None = None
) -> dict[str, Any]:
    """Watch list from wooorm/npm-high-impact (MIT), most downloaded first."""
    sha = ref
    if not sha:
        _headers, body = registry.fetch(
            f"https://api.github.com/repos/{NPM_HIGH_IMPACT}/commits/main"
        )
        sha = str(json.loads(body)["sha"])
    raw = f"https://raw.githubusercontent.com/{NPM_HIGH_IMPACT}/{sha}"
    _headers, body = registry.fetch(f"{raw}/lib/top-download.js")
    names = re.findall(r"'([^'\\\s]+)'", body.decode("utf-8"))
    _headers, notice = registry.fetch(f"{raw}/license")
    return {
        "schema": WATCHLIST_SCHEMA,
        "ecosystem": "npm",
        "source": f"https://github.com/{NPM_HIGH_IMPACT}/blob/{sha}/lib/top-download.js",
        "license": "MIT",
        "notice": notice.decode("utf-8").strip(),
        "ranking": "npm high-impact packages (1,000,000+ weekly downloads), most downloaded first",
        "retrieved_at": _iso(datetime.now(timezone.utc)),
        "packages": _distinct("npm", names)[:top],
    }


def build_pypi_watchlist(registry: HttpRegistry, *, top: int) -> dict[str, Any]:
    """Watch list from the packages.ecosyste.ms pypi.org listing (CC BY-SA 4.0)."""
    per_page = 1000
    names: list[str] = []
    for page in range(1, math.ceil(top / per_page) + 1):
        url = ECOSYSTEMS_PYPI_LISTING.format(per_page=per_page, page=page)
        _headers, body = registry.fetch(url)
        listing = json.loads(body)
        if not isinstance(listing, list) or not listing:
            break
        names.extend(
            str(item["name"]) for item in listing if isinstance(item, dict) and item.get("name")
        )
    return {
        "schema": WATCHLIST_SCHEMA,
        "ecosystem": "pypi",
        "source": ECOSYSTEMS_PYPI_LISTING.split("&per_page")[0],
        "license": "CC-BY-SA-4.0",
        "attribution": (
            "Package ranking from ecosyste.ms (https://packages.ecosyste.ms), licensed CC BY-SA "
            "4.0 (https://creativecommons.org/licenses/by-sa/4.0/). Changed: reduced to "
            "normalized package names in download order. This file is licensed CC BY-SA 4.0."
        ),
        "ranking": "PyPI downloads over the last month as reported by ecosyste.ms, most first",
        "retrieved_at": _iso(datetime.now(timezone.utc)),
        "packages": _distinct("pypi", names)[:top],
    }


def _distinct(ecosystem: str, names: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered = []
    for name in names:
        normalized = normalize_name(ecosystem, name)
        if normalized and normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)
    return ordered


def _watchlist_command(args: argparse.Namespace) -> int:
    registry = HttpRegistry(timeout=120, max_bytes=512 * 1024 * 1024)
    if args.ecosystem == "npm":
        document = build_npm_watchlist(registry, top=args.top, ref=args.ref)
    else:
        document = build_pypi_watchlist(registry, top=args.top)
    output = args.output or SENTINEL_DIR / f"watch-{args.ecosystem}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {output}: {len(document['packages'])} {args.ecosystem} packages")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    registry: Registry | None = None,
    review: Review | None = None,
    now: datetime | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="ca9 sentinel: review new popular releases.")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Review new releases and merge the datasets.")
    run.add_argument("--bundle", type=Path, required=True, help="Built feed bundle to extend.")
    run.add_argument("--previous", type=Path, default=None, help="Previously published bundle.")
    run.add_argument("--manifest", type=Path, default=None, help="Build manifest to extend.")
    run.add_argument("--watchlist-dir", type=Path, default=SENTINEL_DIR)
    run.add_argument("--allowlist", type=Path, default=SENTINEL_DIR / "allow.json")
    run.add_argument("--top", type=int, default=SentinelConfig.top)
    run.add_argument("--time-budget-minutes", type=float, default=30)
    run.add_argument("--discovery-share", type=float, default=SentinelConfig.discovery_share)
    run.add_argument("--min-review-seconds", type=float, default=SentinelConfig.min_review_seconds)
    run.add_argument("--review-seconds", type=float, default=SentinelConfig.review_seconds)
    run.add_argument("--settle-minutes", type=float, default=SentinelConfig.settle_minutes)
    run.add_argument(
        "--initial-lookback-hours", type=float, default=SentinelConfig.initial_lookback_hours
    )
    run.add_argument("--max-lookback-hours", type=float, default=SentinelConfig.max_lookback_hours)
    run.add_argument("--retain-days", type=float, default=SentinelConfig.retain_days)
    run.add_argument("--max-entries", type=int, default=SentinelConfig.max_entries)
    run.add_argument("--max-dataset-kb", type=int, default=1024)
    run.add_argument("--max-reviews", type=int, default=SentinelConfig.max_reviews)
    run.add_argument("--max-artifact-mb", type=int, default=SentinelConfig.max_artifact_mb)
    run.add_argument("--workers", type=int, default=SentinelConfig.workers)
    run.add_argument("--review-workers", type=int, default=SentinelConfig.review_workers)
    run.add_argument("--max-attempts", type=int, default=SentinelConfig.max_attempts)
    run.add_argument("--include-prereleases", action="store_true")
    watch = commands.add_parser("watchlist", help="Rebuild a checked-in watch list.")
    watch.add_argument("--ecosystem", choices=ECOSYSTEMS, required=True)
    watch.add_argument("--top", type=int, default=10000)
    watch.add_argument("--ref", default=None, help="npm-high-impact commit to read.")
    watch.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.command == "watchlist":
        return _watchlist_command(args)
    return _run_command(args, registry=registry, review=review, now=now)


if __name__ == "__main__":
    raise SystemExit(main())
