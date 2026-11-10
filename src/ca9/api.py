"""Stable library interface for supply-chain checks (used by Skylos).

``API_VERSION`` changes only when a name, key or value set below changes
incompatibly; new optional keys may be added within a version.

Package input (plain dict): ``ecosystem`` ("npm"|"pypi"), ``name``, ``version``,
``direct``, ``dev``, ``registry``, ``registry_mode`` ("exclusive"|"merged"|None),
``source_kind`` ("registry"|"git"|"url"|"path"), ``source_url``, ``integrity``,
``file``, ``line``. Optional: ``registries`` (every index of a merged setup; when
given, the public default is not added) and ``lockfile`` (bool; otherwise inferred
from ``file``).

Finding dict: ``signal_type``, ``severity`` (CRITICAL|HIGH|MEDIUM|LOW), ``action``
(block|warn|investigate), ``ecosystem``, ``name``, ``version``, ``title``,
``reason``, ``remediation``, ``evidence`` (dict), ``file``, ``line``.

Signal types: dependency_confusion, untrusted_registry, git_dependency,
direct_url_dependency, mutable_source, missing_integrity, malware,
new_package_version, provenance_regression. Git and URL findings carry
``evidence.mutable`` plus ``pinned_commit``/``ref`` (git) or ``has_hash`` (URL).
Provenance regressions carry ``evidence.line``: "same" (this release line had
provenance), "older" (a new line after attested releases) or "newer" (an older
line that never had it, after newer lines did; can be a hand-published backport).

``feed_status(feed_dir=None)`` reports the malware feed state (ready, stale,
missing, tampered); a stale feed is still matched but leaves the receipt
incomplete. ``refresh_feed`` updates an installed feed older than a given age,
within a time limit, and never raises.

``suspicious_matches(packages, feed_dir=None)`` matches exact versions against
the feed's ``*-suspicious`` datasets: new releases of popular packages that
ca9's hourly sentinel flagged from a static review before any public malware
report. Its findings use signal type ``suspicious_release``.
"""

from __future__ import annotations

import contextlib
import importlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any

from packaging.version import InvalidVersion, Version

from ca9.analyzers.supply_chain import (
    DEFAULT_TRUSTED_INDEXES,
    SupplyChainPolicy,
    analyze_supply_chain,
    internal_pattern_for,
    registry_matches,
)
from ca9.core.models import (
    Artifact,
    Evidence,
    Finding,
    Inventory,
    Package,
    SourceEvidence,
    package_key,
)
from ca9.npm_publisher import REGISTRY_ORIGIN, check_npm_provenance
from ca9.readers.requirements import valid_hash_pins

API_VERSION = 1
DEFAULT_MAX_LOOKUPS = 200


def threat_context(cve_ids, *, network=True, project_root=None, timeout=15.0):
    """Return dated EPSS/CISA KEV risk_context v1; never change policy scores.

    This additive capability is available in ca9 0.9.0+. Each call accepts at
    most sixteen canonical CVEs. Use ``network=False`` for cache-only lookup.
    Missing or unavailable provider evidence is explicit unknown, never zero.
    """
    from ca9.risk_context import threat_context as lookup

    return lookup(cve_ids, network=network, project_root=project_root, timeout=timeout)


_ECOSYSTEMS = frozenset({"npm", "pypi"})
_REGISTRY_MODES = frozenset({"exclusive", "merged"})
_SOURCE_KINDS = {"registry": "registry", "git": "git", "url": "direct_url", "path": "path"}
_PUBLIC_REGISTRIES = {"npm": REGISTRY_ORIGIN, "pypi": "https://pypi.org/simple"}
_LOCKFILES_WITH_INTEGRITY = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "pdm.lock",
        "fyn.lock",
    }
)
_STATIC_SIGNALS = frozenset(
    {
        "dependency_confusion",
        "untrusted_registry",
        "git_dependency",
        "direct_url_dependency",
        "mutable_source",
    }
)
_SEVERITIES = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_ACTIONS = frozenset({"block", "warn", "investigate"})
_AGE_STATUSES = frozenset({"old_enough", "too_new", "unknown"})
_NPM_EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_RANGE_CHARACTERS = re.compile(r"[\s,<>=~*^|:@]")
_REMEDIATION = {
    "dependency_confusion": (
        "Install internal packages only from the private index: make it the only index "
        "(--index-url, not --extra-index-url) or scope the name to the private registry, "
        "and reserve the name on the public registry."
    ),
    "untrusted_registry": (
        "Install from a trusted registry, or add this registry to the trusted list after review."
    ),
    "git_dependency": (
        "Pin the Git dependency to a full commit SHA, or publish it to a registry you control."
    ),
    "direct_url_dependency": (
        "Pin the file with a hash (pip --hash or lockfile integrity), or install a registry "
        "release instead."
    ),
    "mutable_source": (
        "Publish the package to a registry or pin it by hash; local paths change without review."
    ),
    "missing_integrity": (
        "Regenerate the lockfile so every registry entry records an integrity hash."
    ),
    "malware": (
        "Remove the package, rotate credentials exposed to installs on affected machines, "
        "and pin a clean version."
    ),
    "new_package_version": (
        "Wait until the release is older than the cooldown, or pin the older version."
    ),
    "provenance_regression": (
        "Do not install this version until the maintainers confirm it; pin the previous "
        "version that was published with provenance."
    ),
    "suspicious_release": (
        "Do not install this version until it is confirmed safe; pin the previous release "
        "and check the package's advisories."
    ),
}


class FeedUnavailable(RuntimeError):
    """The local malware feed or its matcher is not available in this installation."""


@dataclass
class _Receipt:
    checked: int = 0
    lookups: int = 0
    cache_hits: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str, count: int = 1) -> None:
        if count > 0:
            self.skipped[reason] = self.skipped.get(reason, 0) + count

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "lookups": self.lookups,
            "cache_hits": self.cache_hits,
            "skipped": [
                {"reason": reason, "count": count} for reason, count in sorted(self.skipped.items())
            ],
            "complete": not self.skipped,
        }


@dataclass(frozen=True)
class _Options:
    internal_packages: tuple[str, ...] = ()
    private_registries: tuple[str, ...] = ()
    trusted_registries: tuple[str, ...] = ()
    min_release_age_hours: int | None = None
    check_provenance: bool = False
    network: bool = False
    max_lookups: int = DEFAULT_MAX_LOOKUPS
    cache_dir: Path | None = None
    feed_dir: Path | None = None


@dataclass(frozen=True)
class _Entry:
    raw: Mapping[str, Any]
    package: Package
    ecosystem: str
    name: str
    version: str | None
    source_kind: str
    registry: str | None
    integrity: str | None
    file: str | None
    line: int | None


def evaluate_packages(
    packages: Iterable[Mapping[str, Any]],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run ca9's package checks over plain package dicts.

    Never raises on malformed input: bad entries and options are skipped and
    counted in the receipt, whose ``complete`` is false whenever anything that was
    asked for was not checked. Malware uses the installed ca9 feed (``feed_dir``
    option, else the default feed); release age and provenance run only with
    ``network`` and stop after ``max_lookups`` registry requests. A version that is not
    exact (a range, tag, alias or alternative) is undecided: whole-package malware records
    still match it, but the receipt counts it as malware_version_not_exact (and
    release_age_version_not_exact / provenance_version_not_exact, with no lookup) and is
    not complete.
    """
    receipt = _Receipt()
    active = _parse_options(options, receipt)
    entries = _parse_entries(packages, receipt)
    receipt.checked = len(entries)

    findings: list[dict[str, Any]] = []
    policy = SupplyChainPolicy(
        trusted_indexes=active.trusted_registries or DEFAULT_TRUSTED_INDEXES,
        private_indexes=active.private_registries,
        internal_package_patterns=active.internal_packages,
    )
    for entry in entries:
        findings.extend(_static_findings(entry, policy, active, receipt))
    findings.extend(_malware_findings(entries, active, receipt))
    findings.extend(_release_age_findings(entries, active, receipt))
    findings.extend(_provenance_findings(entries, active, receipt))
    findings.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(item["severity"], 4),
            item["signal_type"],
            item["ecosystem"],
            item["name"],
            str(item["file"] or ""),
            item["line"] or 0,
        )
    )
    return {"findings": findings, "receipt": receipt.to_dict()}


def check_release_age(
    ecosystem: str,
    name: str,
    version: str,
    *,
    min_hours: int,
    cache_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Release age from registry publish times; unknown when it cannot be decided."""
    checker = _optional_function("ca9.release_age", "check_release_age")
    if checker is None:
        return _unknown_age("ca9.release_age is not available in this ca9")
    try:
        result = checker(ecosystem, name, version, min_hours=min_hours, cache_dir=cache_dir)
    except Exception as exc:
        return _unknown_age(f"release age check failed: {exc}")
    return _normalized_age(result)


def malware_matches(
    packages: Iterable[Mapping[str, Any]],
    *,
    feed_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Match packages against the installed ca9 malware feed, offline.

    Malformed entries are ignored. Raises FeedUnavailable when the feed or its
    matcher is missing, so an empty list always means "checked, no match".
    """
    receipt = _Receipt()
    entries = _parse_entries(packages, receipt)
    finder = _optional_function("ca9.package_feed", "find_malware_matches")
    if finder is None:
        raise FeedUnavailable("ca9.package_feed.find_malware_matches is not available")
    try:
        matches = finder(
            [entry.package for entry in entries],
            cache_dir=_optional_path(feed_dir),
        )
    except Exception as exc:
        raise FeedUnavailable(str(exc)) from exc
    return _malware_dicts(matches, entries)


def feed_status(*, feed_dir: str | Path | None = None) -> dict[str, Any]:
    """State of the installed malware feed: ready, stale, missing, or tampered.

    Returns ``state``, ``action`` (pass|warn|block), ``reason``, ``created_at``,
    ``expires_at`` (the effective expiry, ISO 8601) and ``osv_built_at`` (when the
    OSV-derived malware and release datasets were built; the hosted bundle is
    published hourly but rebuilds them every few hours; None for feeds that do not
    record it). Never raises.
    """
    status_function = _optional_function("ca9.package_feed", "feed_status")
    if status_function is None:
        return _feed_status_dict("missing", "warn", "ca9.package_feed.feed_status is not available")
    try:
        status = status_function(cache_dir=_optional_path(feed_dir))
    except Exception as exc:
        return _feed_status_dict("missing", "warn", f"feed status check failed: {exc}")
    state = str(getattr(status, "state", "missing"))
    if state not in {"ready", "stale", "missing", "tampered"}:
        state = "missing"
    result = _feed_status_dict(
        state, str(getattr(status, "action", "warn")), str(getattr(status, "reason", ""))
    )
    snapshot = getattr(status, "snapshot", None)
    if snapshot is not None:
        result["created_at"] = getattr(snapshot, "created_at", None)
        result["expires_at"] = getattr(snapshot, "expires_at", None)
        effective = getattr(snapshot, "effective_expires_at", None)
        if callable(effective):
            with contextlib.suppress(TypeError, ValueError, AttributeError):
                result["expires_at"] = effective().isoformat()
        result["snapshot_id"] = getattr(snapshot, "snapshot_id", None)
        result["osv_built_at"] = getattr(snapshot, "osv_built_at", None)
    return result


def _feed_status_dict(state: str, action: str, reason: str) -> dict[str, Any]:
    return {
        "state": state,
        "action": action,
        "reason": reason,
        "created_at": None,
        "expires_at": None,
        "osv_built_at": None,
    }


def suspicious_matches(
    packages: Iterable[Mapping[str, Any]],
    *,
    feed_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Match exact package versions against the sentinel's suspicious releases, offline.

    Same input and finding shape as ``malware_matches``. ``signal_type`` is
    ``suspicious_release``; ``action`` is block (HIGH) or warn (MEDIUM), from the
    sentinel's verdict. ``evidence`` carries ``kinds`` (upgrade-review kinds the
    release added), ``verdict``, ``previous`` (the release it was compared with, or
    None), ``evidence`` (short strings), ``reviewed_at``, ``published_at`` and
    ``snapshot_id``. Entries without a version and malformed entries are ignored.
    Raises FeedUnavailable when the feed or its matcher is missing, or when the
    installed feed has no suspicious dataset for an ecosystem asked about, so an
    empty list always means "checked, no match".
    """
    receipt = _Receipt()
    entries = _parse_entries(packages, receipt)
    finder = _optional_function("ca9.package_feed", "find_suspicious_matches")
    if finder is None:
        raise FeedUnavailable("ca9.package_feed.find_suspicious_matches is not available")
    try:
        matches = finder(
            [entry.package for entry in entries],
            cache_dir=_optional_path(feed_dir),
        )
    except Exception as exc:
        raise FeedUnavailable(str(exc)) from exc
    return _malware_dicts(matches, entries)


def refresh_feed(
    *,
    max_age_hours: float = 6,
    timeout_seconds: float = 60,
    feed_dir: str | Path | None = None,
    source: str | None = None,
    require_attestation: bool = False,
) -> dict[str, Any]:
    """Update the installed feed only when it is older than ``max_age_hours``.

    Uses the same source and checks as ``ca9 feed update`` (``source``, else
    ``CA9_FEED_URL``, else the hosted feed; https only, size cap, hashes, rollback
    refusal, and ``gh attestation verify`` with ``require_attestation``) and gives up
    after ``timeout_seconds`` without a partial install. After an attempt it waits an
    hour (or ``max_age_hours`` if shorter) before trying again. Returns ``status``
    (fresh|recently_checked|updated|current|failed|timeout), ``reason``, ``source``,
    ``created_at`` and ``snapshot_id`` of the installed snapshot afterwards, and
    ``previous_created_at``. Never raises and never runs or reads project code.
    """
    result = {
        "status": "failed",
        "reason": "",
        "source": source,
        "created_at": None,
        "snapshot_id": None,
        "previous_created_at": None,
    }
    numbers = (max_age_hours, timeout_seconds)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in numbers):
        return {**result, "reason": "max_age_hours and timeout_seconds must be numbers"}
    refresher = _optional_function("ca9.package_feed", "refresh_feed")
    if refresher is None:
        return {**result, "reason": "ca9.package_feed.refresh_feed is not available"}
    try:
        return refresher(
            max_age_hours=max_age_hours,
            timeout_seconds=timeout_seconds,
            cache_dir=_optional_path(feed_dir),
            source=source,
            require_attestation=require_attestation is True,
        )
    except Exception as exc:
        return {**result, "reason": f"feed refresh failed: {exc}"[:300]}


def check_provenance(
    ecosystem: str,
    name: str,
    version: str,
    *,
    cache_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Compare a release's provenance with the stable releases uploaded before it.

    npm: registry attestations (``dist.attestations``) or a trusted publisher. PyPI: PEP
    740 attestations from the Integrity API; ``regressed`` when earlier stable releases on
    the release line were attested by a Trusted Publisher and this one has no
    attestation, a publisher identity (repository, workflow...) none of them had, or
    unattested files where every earlier file was attested. Evidence lists the releases
    checked, ``previous_publishers`` and ``this_version``. Returns ``status``
    ok|regressed|unknown|not_applicable; network errors, a version the registry does not
    list and a project with no earlier stable release return unknown.
    """
    normalized = ""
    if isinstance(ecosystem, str):
        normalized = ecosystem.strip().lower()
    if normalized == "pypi":
        from ca9.pypi_provenance import check_pypi_provenance

        return check_pypi_provenance(name, version, cache_dir=_optional_path(cache_dir))
    if normalized != "npm":
        return {
            "status": "not_applicable",
            "evidence": {},
            "reason": "provenance is checked for npm and PyPI packages only",
        }
    return check_npm_provenance(name, version, cache_dir=_optional_path(cache_dir))


def _parse_options(options: Mapping[str, Any] | None, receipt: _Receipt) -> _Options:
    if options is None:
        return _Options()
    if not isinstance(options, Mapping):
        receipt.skip("invalid_option")
        return _Options()
    values: dict[str, Any] = {}
    for key in ("internal_packages", "private_registries", "trusted_registries"):
        if key in options and options[key] is not None:
            parsed = _string_tuple(options[key])
            if parsed is None:
                receipt.skip("invalid_option")
            else:
                values[key] = parsed
    hours = options.get("min_release_age_hours")
    if hours is not None:
        if isinstance(hours, int) and not isinstance(hours, bool) and hours >= 0:
            values["min_release_age_hours"] = hours or None
        else:
            receipt.skip("invalid_option")
    for key in ("check_provenance", "network"):
        value = options.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            values[key] = value
        else:
            receipt.skip("invalid_option")
    max_lookups = options.get("max_lookups")
    if max_lookups is not None:
        if isinstance(max_lookups, int) and not isinstance(max_lookups, bool) and max_lookups >= 0:
            values["max_lookups"] = max_lookups
        else:
            receipt.skip("invalid_option")
    for key in ("cache_dir", "feed_dir"):
        value = options.get(key)
        if value is None:
            continue
        if isinstance(value, (str, PurePath)) and str(value):
            values[key] = Path(value)
        else:
            receipt.skip("invalid_option")
    return _Options(**values)


def _string_tuple(value: object) -> tuple[str, ...] | None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        return None
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        items.append(item.strip())
    return tuple(items)


def _parse_entries(packages: object, receipt: _Receipt) -> list[_Entry]:
    if isinstance(packages, (str, bytes, Mapping)) or not isinstance(packages, Iterable):
        receipt.skip("malformed_input")
        return []
    entries: list[_Entry] = []
    try:
        iterator = iter(packages)
    except Exception:
        receipt.skip("malformed_input")
        return entries
    while True:
        try:
            raw = next(iterator)
        except StopIteration:
            break
        except Exception:
            receipt.skip("malformed_input")
            break
        try:
            entry, reason = _entry(raw)
        except Exception:
            entry, reason = None, "malformed_package"
        if entry is None:
            receipt.skip(reason)
        else:
            entries.append(entry)
    return entries


def _entry(raw: object) -> tuple[_Entry | None, str]:
    if not isinstance(raw, Mapping):
        return None, "malformed_package"
    ecosystem = raw.get("ecosystem")
    name = raw.get("name")
    version = raw.get("version")
    if not isinstance(ecosystem, str) or not isinstance(name, str) or not name.strip():
        return None, "malformed_package"
    ecosystem = ecosystem.strip().lower()
    if ecosystem not in _ECOSYSTEMS:
        return None, "unsupported_ecosystem"
    if version is not None and (not isinstance(version, str) or not version.strip()):
        return None, "malformed_package"
    registry = _optional_string(raw.get("registry"))
    source_url = _optional_string(raw.get("source_url"))
    integrity = _optional_string(raw.get("integrity"))
    file = _optional_string(raw.get("file"))
    line = raw.get("line")
    if not isinstance(line, int) or isinstance(line, bool):
        line = None
    mode = raw.get("registry_mode")
    if mode is not None and (not isinstance(mode, str) or mode not in _REGISTRY_MODES):
        return None, "malformed_package"
    source_kind = raw.get("source_kind") or "registry"
    if not isinstance(source_kind, str) or source_kind not in _SOURCE_KINDS:
        return None, "malformed_package"
    extra_registries: tuple[str, ...] = ()
    if raw.get("registries") is not None:
        parsed = _string_tuple(raw.get("registries"))
        if parsed is None:
            return None, "malformed_package"
        extra_registries = parsed

    clean_name = name.strip()
    clean_version = None
    if isinstance(version, str):
        clean_version = version.strip()
    dependency_kind = "transitive"
    if raw.get("direct") is True:
        dependency_kind = "direct"
    internal_kind = _SOURCE_KINDS[source_kind]
    metadata: dict[str, Any] = {"source_kind": internal_kind}
    source_registry = registry
    if mode == "merged":
        candidates = [item for item in (registry, *extra_registries) if item]
        if raw.get("registries") is None:
            candidates.append(_PUBLIC_REGISTRIES[ecosystem])
        metadata["registry_mode"] = "merged"
        metadata["candidate_registries"] = list(dict.fromkeys(candidates))
        source_registry = None
    elif mode == "exclusive":
        metadata["registry_mode"] = "exclusive"
    artifacts: tuple[Artifact, ...] = ()
    evidence = SourceEvidence(source=file or "skylos inventory", reader="ca9.api")
    if source_url:
        metadata["source_url"] = source_url
    if internal_kind == "git" and source_url:
        artifacts = (Artifact(kind="git-source", url=source_url, evidence=(evidence,)),)
    elif internal_kind == "direct_url":
        has_hash = _usable_integrity(integrity)
        metadata["has_hash"] = has_hash
        if source_url and has_hash:
            artifacts = (
                Artifact(kind="direct-url", url=source_url, hash=integrity, evidence=(evidence,)),
            )
    package = Package(
        name=clean_name,
        version=clean_version,
        ecosystem=ecosystem,
        dependency_kind=dependency_kind,
        source_registry=source_registry,
        artifacts=artifacts,
        evidence=(evidence,),
        metadata=metadata,
    )
    return (
        _Entry(
            raw=raw,
            package=package,
            ecosystem=ecosystem,
            name=clean_name,
            version=clean_version,
            source_kind=source_kind,
            registry=registry,
            integrity=integrity,
            file=file,
            line=line,
        ),
        "",
    )


def _static_findings(
    entry: _Entry,
    policy: SupplyChainPolicy,
    options: _Options,
    receipt: _Receipt,
) -> list[dict[str, Any]]:
    try:
        findings = analyze_supply_chain(
            Inventory(repo_path=".", packages=(entry.package,)), policy=policy
        )
    except (TypeError, ValueError, AttributeError, KeyError):
        receipt.skip("malformed_package")
        return []
    results: list[dict[str, Any]] = []
    for finding in findings:
        if finding.signal_type not in _STATIC_SIGNALS:
            continue
        if finding.signal_type == "untrusted_registry" and not options.trusted_registries:
            continue
        converted = _finding_dict(finding, entry)
        if converted is not None:
            results.append(converted)
    if _missing_integrity(entry):
        results.append(
            _finding_dict(
                Finding(
                    title=f"Lockfile entry without integrity for {entry.name}",
                    signal_type="missing_integrity",
                    package_key=entry.package.key,
                    severity="medium",
                    evidence=(
                        Evidence(
                            kind="artifact_integrity",
                            description=f"{entry.file} records no integrity for {entry.name}",
                            source=SourceEvidence(
                                source=entry.file or "lockfile", reader="ca9.api"
                            ),
                            metadata={"file": entry.file, "registry": entry.registry},
                        ),
                    ),
                    metadata={
                        "action": "warn",
                        "reason": (
                            "the lockfile does not pin this registry package by hash, so a "
                            "changed or substituted tarball installs without notice"
                        ),
                    },
                ),
                entry,
            )
        )
    return results


def _missing_integrity(entry: _Entry) -> bool:
    if entry.source_kind != "registry" or entry.integrity:
        return False
    declared = entry.raw.get("lockfile")
    if isinstance(declared, bool):
        return declared
    if not entry.file:
        return False
    return PurePath(entry.file.replace("\\", "/")).name.lower() in _LOCKFILES_WITH_INTEGRITY


def _malware_findings(
    entries: list[_Entry],
    options: _Options,
    receipt: _Receipt,
) -> list[dict[str, Any]]:
    if not entries:
        return []
    finder = _optional_function("ca9.package_feed", "find_malware_matches")
    if finder is None:
        receipt.skip("malware_feed_unsupported", len(entries))
        return []
    try:
        matches = finder([entry.package for entry in entries], cache_dir=options.feed_dir)
    except Exception:
        receipt.skip("malware_feed_unavailable", len(entries))
        return []
    if feed_status(feed_dir=options.feed_dir)["state"] == "stale":
        receipt.skip("malware_feed_stale", len(entries))
    receipt.skip("malware_version_not_exact", sum(not _exact_version(entry) for entry in entries))
    return _malware_dicts(matches, entries)


def _exact_version(entry: _Entry) -> bool:
    """False for ranges, tags, aliases and alternatives (``^5.6.1``, ``latest``,
    ``npm:x@1.0.0``, ``1 || 2``, ``>=2``): only whole-package records can be matched for
    them, so the check is undecided rather than clean. No version at all is unpinned."""
    version = entry.version
    if version is None:
        return True
    if entry.ecosystem == "npm":
        return bool(_NPM_EXACT_VERSION.fullmatch(version))
    if _RANGE_CHARACTERS.search(version):
        return False
    try:
        Version(version)
    except InvalidVersion:
        return False
    return True


def _malware_dicts(matches: object, entries: list[_Entry]) -> list[dict[str, Any]]:
    by_key: dict[str, list[_Entry]] = {}
    by_name: dict[str, list[_Entry]] = {}
    for entry in entries:
        by_key.setdefault(entry.package.key, []).append(entry)
        by_name.setdefault(package_key(entry.ecosystem, entry.name), []).append(entry)
    results: list[dict[str, Any]] = []
    if not isinstance(matches, Iterable):
        return results
    seen: set[str] = set()
    for finding in matches:
        if not isinstance(finding, Finding) or finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        targets = by_key.get(finding.package_key) or by_name.get(finding.package_key) or ()
        for entry in targets:
            converted = _finding_dict(finding, entry)
            if converted is not None:
                results.append(converted)
    return results


def _release_age_findings(
    entries: list[_Entry],
    options: _Options,
    receipt: _Receipt,
) -> list[dict[str, Any]]:
    if not options.min_release_age_hours:
        return []
    eligible = [entry for entry in entries if entry.source_kind == "registry"]
    unpinned = [entry for entry in eligible if not entry.version]
    receipt.skip("release_age_no_version", len(unpinned))
    eligible = [entry for entry in eligible if entry.version]
    loose = [entry for entry in eligible if not _exact_version(entry)]
    receipt.skip("release_age_version_not_exact", len(loose))
    eligible = [entry for entry in eligible if _exact_version(entry)]
    private = [entry for entry in eligible if _private_name(entry, options)]
    receipt.skip("release_age_private_registry", len(private))
    eligible = [entry for entry in eligible if not _private_name(entry, options)]
    if not eligible:
        return []
    if not options.network:
        receipt.skip("network_disabled", len(eligible))
        return []
    checker = _optional_function("ca9.release_age", "check_release_age")
    if checker is None:
        receipt.skip("release_age_unsupported", len(eligible))
        return []
    results: dict[tuple[str, str, str], dict[str, Any] | None] = {}
    findings: list[dict[str, Any]] = []
    for entry in eligible:
        identity = (entry.ecosystem, entry.package.normalized_name, entry.version or "")
        if identity not in results:
            if receipt.lookups >= options.max_lookups:
                results[identity] = None
            else:
                results[identity] = _call_release_age(checker, entry, options, receipt)
        result = results[identity]
        if result is None:
            receipt.skip("max_lookups")
            continue
        if result["status"] == "unknown":
            receipt.skip("release_age_unknown")
            continue
        if result["status"] != "too_new":
            continue
        findings.append(_release_age_dict(entry, result, options.min_release_age_hours))
    return findings


def _call_release_age(
    checker: Callable[..., Any],
    entry: _Entry,
    options: _Options,
    receipt: _Receipt,
) -> dict[str, Any]:
    try:
        raw = checker(
            entry.ecosystem,
            entry.name,
            entry.version,
            min_hours=options.min_release_age_hours,
            cache_dir=options.cache_dir,
        )
    except Exception as exc:
        receipt.lookups += 1
        return _unknown_age(f"release age check failed: {exc}")
    result = _normalized_age(raw)
    if "cache" in str(result.get("source") or "").lower():
        receipt.cache_hits += 1
    else:
        receipt.lookups += 1
    return result


def _release_age_dict(entry: _Entry, result: dict[str, Any], min_hours: int) -> dict[str, Any]:
    suggested = result.get("suggested_version")
    remediation = _REMEDIATION["new_package_version"]
    if isinstance(suggested, str) and suggested:
        remediation = (
            f"Wait until the release is older than {min_hours}h, or pin {entry.name} {suggested}."
        )
    age = result.get("age_hours")
    age_text = "less than the cooldown"
    if isinstance(age, (int, float)) and not isinstance(age, bool):
        age_text = f"{age:.1f}h old"
    return {
        "signal_type": "new_package_version",
        "severity": "HIGH",
        "action": "block",
        "ecosystem": entry.ecosystem,
        "name": entry.name,
        "version": entry.version,
        "title": f"{entry.name} {entry.version} is newer than the {min_hours}h cooldown",
        "reason": (
            f"{entry.name} {entry.version} was published {age_text}; fresh releases are "
            "where hijacked and malicious versions are caught before they spread"
        ),
        "remediation": remediation,
        "evidence": {**result, "min_release_age_hours": min_hours},
        "file": entry.file,
        "line": entry.line,
    }


def _provenance_findings(
    entries: list[_Entry],
    options: _Options,
    receipt: _Receipt,
) -> list[dict[str, Any]]:
    if not options.check_provenance:
        return []
    npm_entries = [
        entry for entry in entries if entry.ecosystem == "npm" and entry.source_kind == "registry"
    ]
    public: list[_Entry] = []
    for entry in npm_entries:
        private_registry = bool(
            entry.registry and entry.registry.rstrip("/").lower() != REGISTRY_ORIGIN
        )
        if private_registry or _private_name(entry, options):
            receipt.skip("provenance_private_registry")
        elif not entry.version:
            receipt.skip("provenance_no_version")
        elif not _exact_version(entry):
            receipt.skip("provenance_version_not_exact")
        else:
            public.append(entry)
    if not public:
        return []
    if not options.network:
        receipt.skip("network_disabled", len(public))
        return []
    documents: dict[str, dict[str, Any] | None] = {}
    results: dict[tuple[str, str], dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for entry in public:
        identity = (entry.package.normalized_name, entry.version or "")
        if identity not in results:
            fetched_before = identity[0] in documents
            allow_fetch = fetched_before or receipt.lookups < options.max_lookups
            result = check_npm_provenance(
                entry.name,
                entry.version or "",
                cache_dir=options.cache_dir,
                documents=documents,
                allow_fetch=allow_fetch,
            )
            if result.get("source") == "cache" or fetched_before:
                receipt.cache_hits += 1
            elif result.get("reason") != "lookup budget exhausted":
                receipt.lookups += 1
            results[identity] = result
        result = results[identity]
        if result.get("reason") == "lookup budget exhausted":
            receipt.skip("max_lookups")
            continue
        if result["status"] == "unknown":
            receipt.skip("provenance_unknown")
            continue
        if result["status"] != "regressed":
            continue
        findings.append(
            {
                "signal_type": "provenance_regression",
                "severity": "HIGH",
                "action": "block",
                "ecosystem": entry.ecosystem,
                "name": entry.name,
                "version": entry.version,
                "title": f"npm provenance regression for {entry.name}",
                "reason": str(result.get("reason") or "release lost provenance"),
                "remediation": _REMEDIATION["provenance_regression"],
                "evidence": dict(result.get("evidence") or {}),
                "file": entry.file,
                "line": entry.line,
            }
        )
    return findings


def _private_name(entry: _Entry, options: _Options) -> bool:
    """Names that must not be sent to a public registry: internal or privately hosted."""
    if internal_pattern_for(entry.name, options.internal_packages) is not None:
        return True
    mode = entry.raw.get("registry_mode")
    return bool(
        entry.registry
        and mode != "merged"
        and registry_matches(entry.registry, options.private_registries)
    )


def _finding_dict(finding: Finding, entry: _Entry) -> dict[str, Any] | None:
    action = str(finding.metadata.get("action") or "warn")
    if action == "pass":
        return None
    if action not in _ACTIONS:
        action = "warn"
    evidence: dict[str, Any] = {}
    if finding.evidence:
        evidence = dict(finding.evidence[0].metadata)
        evidence["description"] = finding.evidence[0].description
    for key in ("advisory_id", "aliases", "malicious"):
        if key in finding.metadata and key not in evidence:
            evidence[key] = finding.metadata[key]
    return {
        "signal_type": finding.signal_type,
        "severity": _SEVERITIES.get(finding.severity, "MEDIUM"),
        "action": action,
        "ecosystem": entry.ecosystem,
        "name": entry.name,
        "version": entry.version,
        "title": finding.title,
        "reason": str(finding.metadata.get("reason") or finding.title),
        "remediation": _remediation(finding, evidence),
        "evidence": evidence,
        "file": entry.file,
        "line": entry.line,
    }


def _remediation(finding: Finding, evidence: dict[str, Any]) -> str:
    if finding.signal_type == "git_dependency" and evidence.get("pinned_commit"):
        return "Prefer a registry release with integrity hashes over a Git source."
    if finding.signal_type == "direct_url_dependency" and evidence.get("has_hash"):
        return "Prefer a registry release over a direct URL; keep the hash pin."
    return _REMEDIATION.get(finding.signal_type, "Review this package before installing it.")


def _usable_integrity(value: str | None) -> bool:
    if not value:
        return False
    if valid_hash_pins(value.split()):
        return True
    for token in value.split():
        algorithm, separator, digest = token.partition("-")
        if separator and algorithm in {"sha256", "sha384", "sha512"} and len(digest) >= 40:
            return True
    return False


def _unknown_age(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "published_at": None,
        "age_hours": None,
        "suggested_version": None,
        "source": "unavailable",
        "reason": reason,
    }


def _normalized_age(result: object) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return _unknown_age("release age check returned no result")
    normalized = dict(result)
    if normalized.get("status") not in _AGE_STATUSES:
        normalized["status"] = "unknown"
    for key in ("published_at", "age_hours", "suggested_version", "source"):
        normalized.setdefault(key, None)
    return normalized


def _optional_function(module_name: str, attribute: str) -> Callable[..., Any] | None:
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return None
    function = getattr(module, attribute, None)
    if not callable(function):
        return None
    return function


def _optional_path(value: str | Path | None) -> Path | None:
    if value is None or not str(value):
        return None
    return Path(value)


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def agent_config(repo_root: str | Path) -> dict[str, Any]:
    """Committed agent/editor execution hooks, MCP server configs and API base-URL overrides.

    Reads ``.claude/settings(.local).json``, ``.gemini/settings.json``,
    ``.cursor/{hooks,mcp}.json``, ``.codex/{hooks.json,config.toml}``,
    ``.vscode/{tasks,mcp,settings}.json``, ``*.code-workspace``, ``.mcp.json``,
    ``.kiro/settings/mcp.json``, Kiro agent hooks ``.kiro/hooks/*.kiro.hook``,
    ``opencode.json(c)`` (``mcp``), Zed ``.zed/settings.json`` (``context_servers``) and
    Roo / Amazon Q / Windsurf ``mcp.json``, at any depth, skipping ``node_modules``, ``.git`` and virtualenvs. Symlinks that stay inside
    the repository are followed and reported under the in-repo path an agent opens (a
    committed ``.claude`` link to ``tools/cfg`` reports ``.claude/settings.json``); a config
    folder or file link that leaves the repository, dangles or cannot be read is an
    ``errors`` entry and makes the result partial. JSON with comments and trailing commas
    parses; an unparseable hook file still reports the command strings found in its text.
    Never raises.

    Returns ``{"findings": [finding dict], "inventory": {...}}``. ``signal_type`` is one
    of agent_hook_command (HIGH; CRITICAL when the command downloads remote code,
    decodes and runs a payload, or runs a script disguised as a font/image),
    editor_folder_open_task (same severities), mcp_server_unpinned (MEDIUM),
    mcp_server_hidden_path (HIGH), mcp_server_impersonation (MEDIUM),
    agent_base_url_override (HIGH). mcp_server_unpinned also covers launches that fetch
    unpinned extra packages or use another registry or index (evidence ``extra_packages``,
    ``indexes``; registry variables in the server ``env`` count) and remote servers reached
    over cleartext http or at a bare non-loopback IP (evidence ``url``, ``cleartext``,
    ``bare_ip``). Claude ``enabledPlugins`` entries are agent_hook_command findings with
    ``plugin`` and ``marketplace`` (from ``extraKnownMarketplaces``) in the evidence. ``name`` is the hook event, task label, server
    name or variable; ``ecosystem``/``version`` are set for MCP findings. Hook
    evidence carries the exact ``command`` plus ``display_command``, ``executable``,
    ``script``, ``fetches_remote``, ``decodes_and_executes``, ``disguised_script`` and
    ``hidden_by_padding``. No command is trusted by name.

    ``inventory``: ``schema`` "ca9.agent_hooks.v1", ``hooks`` [{file, kind, event,
    command, line}] (kind: claude_hook, claude_setting, gemini_hook, gemini_setting,
    cursor_hook, codex_hook, kiro_hook, vscode_task; optional matcher, label, via,
    handler_type), ``mcp_servers`` [{file, name, command, ecosystem, package,
    version, pinned, line}] (optional argv, transport, fetches, launcher, url), plus
    optional ``env_overrides``, ``files``, ``errors``, ``status``
    ("complete"|"partial"), ``truncated`` and ``links`` ([{path, target}] for followed
    symlinks, both repository-relative).
    """
    from ca9.agent_config import scan_repository

    try:
        return scan_repository(repo_root)
    except Exception as exc:
        return {
            "findings": [],
            "inventory": {
                "schema": "ca9.agent_hooks.v1",
                "hooks": [],
                "mcp_servers": [],
                "env_overrides": [],
                "files": [],
                "errors": [{"file": ".", "reason": f"agent config scan failed: {exc}"}],
                "status": "partial",
                "truncated": False,
            },
        }


def parse_mcp_server(
    command: object, args: object = None, *, version: object = None
) -> dict[str, Any] | None:
    """Package behind an MCP server launch, and whether it is pinned.

    Understands npx / npm exec / pnpm dlx / yarn dlx / bunx / bun x / uvx / uv tool
    run / pipx run / python -m / node and other interpreters / deno / docker and
    podman run, through ``cmd /c``, ``sh -c`` and ``env`` wrappers. Returns
    ``ecosystem`` (npm|pypi|docker|url|local), ``package``, ``version`` (or None),
    ``pinned`` (exact version, full git commit, or image digest) and
    ``pinned_command``: the same argv with ``version`` inserted when the caller
    passes an exact ``version=`` (an image digest ``sha256:...`` for docker), else
    None. Optional keys: ``launcher``, ``fetches`` (False for local files and
    ``python -m``, which run what is already installed), ``spec``, ``source``
    (registry|git|url|local|installed|image), ``extra_packages`` ([{package, version,
    pinned, source}] from further ``-p``/``--package``, ``--with``,
    ``--with-requirements``/``--with-editable`` or ``--preinstall``) and ``indexes``
    (registries or indexes other than the public npm registry and PyPI, from
    ``--registry``, ``--index``, ``--index-url``, ``--extra-index-url``, ``--find-links``
    or pipx ``--pip-args``). An unpinned extra package or another index makes ``pinned``
    false and ``pinned_command`` None. Launcher options count only before the package
    (npx, dlx, bunx, uvx and pipx hand later arguments to the server), except for npm exec,
    which reads them anywhere before ``--``. None for unusable input; never raises.
    """
    from ca9.agent_config import parse_launch

    try:
        return parse_launch(command, args, version=version)
    except Exception:
        return None


def hardening_settings(repo_root: str | Path) -> dict[str, Any]:
    """Snapshot of the install-hardening settings committed at the repository root.

    ``cooldown``: ``npm_days`` (.npmrc ``min-release-age``, days, npm >= 11.10),
    ``pnpm_minutes`` (``minimumReleaseAge``, minutes; pnpm-workspace.yaml, else pnpm 10
    .npmrc ``minimum-release-age`` or package.json ``pnpm``), ``yarn`` (.yarnrc.yml
    ``npmMinimalAgeGate`` as written), ``bun_seconds`` (bunfig.toml
    ``install.minimumReleaseAge``, seconds), ``uv`` (``exclude-newer`` from uv.toml or
    pyproject ``[tool.uv]``, as written), ``pip`` (``uploaded-prior-to`` from
    pip.conf/pip.ini or requirements files), ``dependabot_days`` (smallest
    ``cooldown.default-days``), ``renovate`` (``minimumReleaseAge``); None when unset.
    ``scripts``: ``npm_ignore_scripts``, ``npm12_allow_scripts``,
    ``pnpm_strict_dep_builds``, ``pnpm_allow_builds`` (packages allowed to build);
    optional ``pnpm_only_built_dependencies`` (pnpm 10), ``pnpm_dangerously_allow_all_builds``,
    ``bun_trusted_dependencies``, ``bun_ignore_scripts``, ``yarn_enable_scripts``.
    ``actions``: ``pinned``/``unpinned`` counts of third-party ``uses:`` refs (full commit
    SHA or image digest = pinned; local ``./`` actions not counted), optional ``refs``
    [{file, uses, ref, pinned, line}] and ``truncated``. ``sources``: setting key to
    the file it came from. Optional: ``cooldown_minutes`` (each cooldown in minutes;
    None when unset or an absolute date), ``exclusions`` (manager -> packages that skip
    the cooldown), ``dependabot`` [{ecosystem, directory, directories, default_days}],
    ``managers`` (package.json ``packageManager``, ``devEngines`` or ``engines``),
    ``renovate_presets``, ``renovate_rules`` [{match, all, minimum_release_age}] for
    packageRules that set an age, ``ignored`` [{setting, file, reason}] for settings the
    declared tool version does not read (pnpm 11 ignores pnpm keys in .npmrc and the
    removed onlyBuiltDependencies / neverBuiltDependencies), ``scripts`` keys
    ``pnpm_never_built_dependencies`` and ``workflow_overrides`` [{file, line, setting,
    value}] (workflow or composite-action lines that turn install scripts back on, such as
    ``npm_config_ignore_scripts: false``, ``YARN_ENABLE_SCRIPTS=true``,
    ``--no-ignore-scripts``, ``--ignore-scripts false``, ``--config.ignore-scripts=false``,
    ``config set ignore-scripts false`` or ``ignore-scripts=false`` echoed into .npmrc),
    ``cooldown_overrides`` [{file, line, setting (cooldown key), option, value}] (CI lines
    that set npm ``min-release-age``, pnpm ``minimum-release-age`` or Yarn
    ``npmMinimalAgeGate`` through environment variables, flags or config writes),
    ``errors``, ``status``. Actions are read with the YAML parser when available (flow style and
    anchors included) and local composite actions referenced by ``uses: ./...`` are
    followed. Never raises.
    """
    from ca9.hardening import SCHEMA, settings

    try:
        return settings(repo_root)
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "cooldown": {},
            "scripts": {},
            "actions": {"pinned": 0, "unpinned": 0},
            "sources": {},
            "errors": [{"file": ".", "reason": f"hardening scan failed: {exc}"}],
            "status": "partial",
        }


def hardening_regressions(base: object, head: object) -> list[dict[str, Any]]:
    """Ways ``head`` weakens the install hardening of ``base``.

    ``base`` and ``head`` are ``hardening_settings`` snapshots or repository paths.
    Items: ``kind``, ``detail``, ``path`` (file in head, else base), plus ``setting``,
    ``base``, ``head`` and, for per-package items, ``package`` (and ``line`` for
    actions). Kinds: cooldown_removed, cooldown_lowered (compared in minutes across
    units; a removal that falls back to an equal or longer default such as pnpm 11's
    1440 minutes or Dependabot's 3 days is not reported; Renovate packageRules and
    Dependabot entries are matched by the packages and directories they cover),
    cooldown_exclusion_added, ignore_scripts_disabled (including new workflow
    overrides), allow_builds_added (pnpm allowBuilds / onlyBuiltDependencies /
    dangerouslyAllowAllBuilds, entries removed from neverBuiltDependencies, Bun
    trustedDependencies), allow_scripts_added (npm allowScripts),
    strict_dep_builds_disabled, action_unpinned (an action pinned to a SHA in base, owner
    and repo compared case-insensitively, used at a tag or branch in head, or any new
    tag or branch ref when every action in base was pinned), cooldown_lowered also for a
    CI override shorter than base's cooldown (with ``line``), and
    check_failed (with ``side``) for a side that is missing, not a snapshot, or was only
    partly read; a missing or unreadable side returns only check_failed items, never an
    empty list. Exceptions are the caller's to apply. Never raises.
    """
    from ca9.hardening import regressions

    try:
        return regressions(base, head)
    except Exception as exc:
        return [
            {"kind": "check_failed", "detail": f"hardening comparison failed: {exc}", "path": None}
        ]


_CI_INVENTORY_SCHEMA = "ca9.ci_inventory.v1"


def ci_inventory(repo_root: str | PurePath, *, max_jobs: int = 500) -> dict[str, Any]:
    """What each CI job can install, run, reach and publish (``ca9.ci_inventory.v1``).

    Covers GitHub Actions workflows (with local composite actions and local
    reusable workflows) and ``.gitlab-ci.yml`` with its local includes (exact paths,
    ``*``/``**`` patterns and nested includes), top-level ``before_script``/``after_script``
    and ``default:`` inheritance. Records names only: secret names, never values; download
    hosts, never URLs or credentials. ``status`` is complete, partial (some files
    unreadable, or GitLab includes that cannot be resolved in the repository: remote,
    project, template, component, variable paths or over the include cap, all listed in
    ``skipped``) or yaml_unavailable (PyYAML missing). ``truncated`` is true when ``max_jobs``
    or a per-list cap cut the output. Each job's ``indirect`` lists commands that may
    install packages out of sight (make, gmake, just, task, tox, nox, docker/podman
    build, buildx, compose or run, Docker build actions, repository scripts) as
    ``[{"command": tool or script path, "line": int}]``. Container images a job runs in or
    starts (GitHub ``container:``, ``uses: docker://``, ``docker``/``podman run``, GitLab
    ``image:`` with default and top-level inheritance) are ``other_tools`` with ``manager``
    container, docker_action or docker_run; ``pinned`` means a digest, or a Docker official
    image at a version tag. Never raises.
    """
    try:
        from ca9.ci.inventory import build_inventory

        inventory, _ = build_inventory(repo_root, max_jobs=max_jobs)
    except Exception as exc:
        return {
            "schema": _CI_INVENTORY_SCHEMA,
            "status": "partial",
            "truncated": False,
            "workflows": [],
            "skipped": [{"file": ".", "reason": f"error:{type(exc).__name__}"}],
        }
    return inventory


def audit_workflows(repo_root: str | PurePath) -> dict[str, Any]:
    """Publish-job rules: ``{"findings": [finding dict], "receipt": {...}}``.

    Signal types: unpinned_tool_in_credentialed_job, unverified_download_into_publish,
    oidc_publish_without_environment, publish_on_dispatch_or_any_branch, and
    credentials_to_remote_reusable_workflow (investigate: secrets or tokens handed to a
    workflow outside this repository). workflow_run counts as an outside event for
    publish_on_dispatch_or_any_branch (it runs on the default branch with secrets after a
    workflow anyone can start, fork pull requests included), and unpinned container
    images count as unpinned tools. Findings use the package finding shape with
    ``ecosystem`` github-actions|gitlab-ci, ``name`` the job id (or workflow file) and
    ``version`` None. The receipt lists ``unknowns`` (remote reusable workflows, remote
    GitLab includes) and ``incomplete_reasons``; ``complete`` is false whenever any part
    of the pipeline could not be read. Never raises.
    """
    try:
        from ca9.ci.audit import audit_repository

        return audit_repository(repo_root)
    except Exception as exc:
        return {
            "findings": [],
            "receipt": {
                "status": "partial",
                "complete": False,
                "skipped": [{"file": ".", "reason": f"error:{type(exc).__name__}"}],
            },
        }


def review_upgrades(
    pairs: Iterable[Mapping[str, Any]],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Diff the old and new published artifacts of each dependency upgrade.

    ``pairs``: ``[{"ecosystem": "npm"|"pypi", "name", "old", "new", "registry"?,
    "integrity"?, "resolved"?, "registry_mode"?}]``.
    Both releases are fetched from a trusted registry (digest-verified, size-capped),
    unpacked safely and compared with deterministic static rules; package code is
    never installed, imported or executed. Only behaviours the new release adds are
    reported; ones present in both versions are counted in ``unchanged_risky``.

    Returns ``{"results": [...], "receipt": {...}}``. Each result has ``ecosystem``,
    ``name``, ``old``, ``new``, ``status`` (reviewed|skipped), ``reason`` (when
    skipped), ``block`` and ``warn`` (lists of deltas). A delta is ``{"kind", "path",
    "line", "snippet", "detail"}``. Block kinds: new_pth_code, new_sitecustomize,
    new_install_hook, new_decode_exec, new_git_or_url_dependency,
    ships_agent_or_editor_hook, ambiguous_package_contents, shadows_system_command,
    uninspectable_import_time_code, lockfile_artifact_mismatch, obfuscation_growth, and
    new_import_time_exec / new_import_time_network for process or network calls that a
    Python package makes at import time and for npm wallet or fetch hijacks. Warn kinds:
    new_import_time_exec / new_import_time_network for JavaScript module capabilities
    and stdlib-only .pth imports, new_native_binary, publisher_change,
    install_script_changed, native_binary_changed, provenance_dropped.
    Optional result keys: ``detail``, ``info`` (informational deltas),
    ``unchanged_risky``, ``unchanged_risky_by_kind``, ``artifacts``, ``limitations``.

    A pair whose ``old`` is missing, None or blank is a first release (a brand-new
    package, typosquat or slopsquat): it is reviewed against an empty release, so
    everything it ships is new and every delta keeps its upgrade level (install hooks
    and nested sitecustomize block, native binaries warn). Such results have ``basis``
    "new_package" and ``first_release`` true; the receipt counts them in
    ``first_release_reviews``.

    ``added: true`` (with ``old`` missing or None) marks a package new to the project, not
    necessarily new to the registry: it is compared with the release before ``new`` on
    the registry (the highest earlier version published before it that is installable and
    not yanked, stable when one exists), and the result has ``basis`` "registry_previous",
    ``old`` None, ``old_resolved`` that version and ``added`` true. With no earlier release
    it is a first release as above. Every result for a pair that carried ``added: true``
    echoes it, skipped ones included (``reason`` network_disabled for an offline call with
    ``network: False``), so such a call shows whether this engine supports it; with an
    explicit ``old`` the pair is an ordinary upgrade that still echoes ``added``. A registry lookup that fails leaves the pair skipped and the receipt
    incomplete.

    PyPI releases are reviewed wheel by wheel: the file pip installs here first, then
    every other wheel of the release against the old release's file for the same tags or
    platform (deltas found only there name the wheel in ``detail``). A wheel whose files
    other than native binaries match a reviewed wheel, or differ without adding any
    behaviour, and whose binaries are ELF/PE/Mach-O images of modules already shipped, is
    read by byte ranges without downloading its old counterpart (``artifacts.also`` entry
    with ``same_code_as``). Wheels for mainstream platforms (CPython or pure Python on
    manylinux/musllinux x86_64 and aarch64, macOS arm64/x86_64/universal2, win_amd64) left
    out by ``max_release_mb``, ``max_artifact_mb`` or the deadline are listed in
    ``limitations`` and make the result incomplete; wheels for uncommon platforms
    (free-threaded, PyPy, 32-bit and other architectures) are not reviewed and are named in
    a limitation without making the result incomplete.

    A release that adds a dependency (any dependency of a first release) also gets that
    dependency reviewed as a first release when the version its range resolves to is the
    package's first release, or the package's first release is at most 30 days older: a
    two-stage package that only adds a dependency carries its payload there. One level,
    at most 5 registry lookups per pair and ``max_dependency_reviews`` (10) reviews per
    call; internal and privately resolved names are never looked up. Their deltas are
    added to the pair with ``path`` "<name>@<version>: <path>"; ``dependency_reviews``
    lists each lookup ({name, version, status: reviewed|established|unresolved|over_limit|
    lookup_failed|review_failed, why?, block?, warn?, complete?}), a failed lookup is a
    limitation, and the receipt counts ``dependency_reviews``.

    Options: ``network`` (default true), ``max_pairs`` (50), ``max_artifact_mb`` (100),
    ``max_release_mb`` (400, the bytes fetched per pair for the other wheels),
    ``cache_dir`` (keeps verified downloads; a temporary directory otherwise),
    ``trusted_registries``, ``private_registries``, ``internal_packages``. Names matching
    ``internal_packages`` are skipped as internal_package, and entries whose lockfile
    ``resolved`` URL is on a listed private registry as private_registry (unless the
    pair's ``registry_mode`` is "merged", a private registry that proxies the public
    one): neither is ever looked up on a public registry. A pair whose ``registry`` is a
    listed private or trusted HTTPS registry is reviewed from that registry. A pair whose
    ``old`` equals ``new`` but carries ``integrity`` or ``resolved`` is reviewed with
    ``basis`` "lockfile": its digest and URL are checked against the files the registry
    serves for that version (lockfile_artifact_mismatch blocks a swapped artifact), with
    nothing downloaded. A ``resolved`` URL the registry does not serve, with no lockfile
    digest tying it to a served file, makes any result incomplete. Never
    raises: bad input is skipped with a reason and counted in the receipt, whose
    ``complete`` is false when anything was not reviewed; same_version (no lockfile pins),
    internal_package and private_registry skips are policy, not gaps, and keep it true.

    Code for reviewers (both off by default; without them the output is unchanged; the
    artifacts are deleted after the review, so this is the only way to see the code):
    ``context_lines`` (int, 0-200) gives every ``block`` and ``warn`` delta in a text file
    of the package a ``context`` string: unified-diff hunks (an ``@@ -a,b +c,d @@`` header,
    then lines prefixed by a space, ``-`` or ``+``; no file header) of that file between
    the old and new artifact within that many lines of the delta's ``line`` (the file's
    first change when ``line`` is None); a file the new release adds, and every file of a
    first release, is shown as ``+`` lines. Deltas in binary files or files over 32 MB,
    and registry-metadata or lockfile deltas, get no ``context``. A context is at most 8 KB and the contexts of one result
    at most 64 KB together (contexts that fit an equal share stay whole, the others share
    the rest); a cut context keeps the delta's line in the middle and ends with the line
    ``... (truncated)``. ``identity_diff_bytes`` (int, 0-200000): a reviewed upgrade with
    a publisher_change or provenance_dropped delta at any level gains ``identity_diff``,
    a unified diff (``--- a/<path>``, ``+++ b/<path>``, hunks with 3 lines of context) of
    every changed text code file (.js, .mjs, .cjs, .ts, .py, .pth, .json, .sh, .toml,
    .cfg, including setup.py and package.json; binaries and lockfiles skipped), files
    with the smallest change first, at most that many bytes, and
    ``identity_diff_truncated`` (true when a file or part of one was left out). All text
    comes from the package files: control, bidi and other invisible characters are
    removed (tabs stay, other whitespace becomes a space), a CR, U+2028 or U+2029 inside
    a line is shown as ``\\r``, ``\\u2028`` or ``\\u2029`` so code after it cannot pass for
    part of a comment, and nothing else is changed. Values that are not integers in range
    are listed in ``invalid_options`` and ignored, like the other options. When either
    option is passed, the receipt has ``context_lines`` (the value applied, 0 when
    rejected or not given), so a caller can tell that this engine supports them.
    """
    from ca9.review.upgrades import review_upgrades as _review_upgrade_pairs

    try:
        return _review_upgrade_pairs(pairs, options)
    except Exception as exc:
        return {
            "results": [],
            "receipt": {
                "schema": "ca9.upgrade_review.v1",
                "pairs": 0,
                "reviewed": 0,
                "skipped": [{"reason": "review_error", "count": 1}],
                "complete": False,
                "error": f"{type(exc).__name__}: {exc}"[:300],
            },
        }
