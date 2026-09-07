from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ca9.artifacts.fetch import ArtifactScanConfig, collect_artifact_snapshots
from ca9.core.models import Inventory
from ca9.review.behavior import BehaviorFact, inspect_snapshot
from ca9.review.locks import LockChange, LockOccurrence, LockState, compare_locks, load_lock
from ca9.review.redaction import redact_text, redact_value

DEFAULT_TRUSTED_REGISTRIES = ("https://registry.npmjs.org",)
_SRI = re.compile(r"(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})\Z")
_DECLARATION_KINDS = frozenset({"lifecycle_script", "entrypoint", "dependency", "module_format"})


@dataclass(frozen=True)
class Inspection:
    status: str
    facts: tuple[BehaviorFact, ...] = ()
    issues: tuple[str, ...] = ()
    blocks: tuple[str, ...] = ()
    declarations_complete: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "issues": list(self.issues),
            "declarations_complete": self.declarations_complete,
        }


@dataclass(frozen=True)
class ReviewReport:
    base: str
    head: str
    decision: str
    complete: bool
    summary: dict[str, int]
    packages: tuple[dict[str, Any], ...]
    issues: tuple[str, ...] = ()
    trusted_registries: tuple[str, ...] = DEFAULT_TRUSTED_REGISTRIES

    @property
    def exit_code(self) -> int:
        if self.decision == "block":
            return 1
        if not self.complete:
            return 2
        return 1 if self.decision == "review" else 0

    def to_dict(self) -> dict[str, Any]:
        return redact_value(
            {
                "schema_version": "ca9.dependency-review.v1",
                "base": self.base,
                "head": self.head,
                "decision": self.decision,
                "complete": self.complete,
                "exit_code": self.exit_code,
                "scope": {
                    "ecosystem": "npm",
                    "lockfile_versions": [2, 3],
                    "selection": "changed installation occurrences only",
                    "artifact_verification": "strongest supported lockfile SRI (SHA-256/384/512)",
                    "trusted_registries": list(self.trusted_registries),
                    "analysis": "package declarations and ca9 static package-code observations",
                    "limitations": "No package execution, full JavaScript semantic comparison, "
                    "vulnerability-feed scan, or proof of safety. Unchanged occurrences are not scanned.",
                },
                "summary": dict(self.summary),
                "packages": list(self.packages),
                "issues": list(self.issues),
            }
        )


def review_lockfiles(
    base: Path,
    head: Path,
    *,
    cache_dir: Path | None = None,
    trusted_registries: tuple[str, ...] = DEFAULT_TRUSTED_REGISTRIES,
    scan_artifacts: bool = True,
) -> ReviewReport:
    """Review changed npm v2/v3 lock occurrences without running dependency code.

    A pass means no new reviewable facts within the reported scope. Unavailable
    evidence remains unknown, including when the baseline cannot be inspected.
    Registry origins are explicit trust input; lockfile URLs never expand trust.
    """
    origins = tuple(sorted({_registry_origin(value) for value in trusted_registries}))
    config = ArtifactScanConfig(
        url_validator=lambda url: _permitted_url(url, origins),
        allowed_local_roots=(),
        **({"cache_dir": cache_dir} if cache_dir is not None else {}),
    )
    base_state = load_lock(Path(base))
    head_state = load_lock(Path(head))
    changes = compare_locks(base_state, head_state)
    counts = Counter(change.status for change in changes)
    selected = {change.path for change in changes if change.status != "unchanged"}
    issues = [*(f"base: {item}" for item in _scope_issues(base_state, selected))]
    issues.extend(f"head: {item}" for item in _scope_issues(head_state, selected))
    scanner = _Scanner(config, scan_artifacts)
    packages: list[dict[str, Any]] = []
    for change in changes:
        if change.status == "unchanged":
            continue
        before = scanner.inspect(change.base)
        after = scanner.inspect(change.head)
        deltas = _metadata_deltas(change)
        deltas.extend(_behavior_deltas(before, after))
        for signal in after.blocks:
            deltas.append(
                _delta(
                    "artifact_verification",
                    signal,
                    "added",
                    None,
                    signal,
                    "block",
                    "Head artifact failed integrity or safe extraction checks.",
                )
            )
        for side, inspection in (("base", before), ("head", after)):
            if inspection.issues:
                issues.extend(f"{change.path} ({side}): {issue}" for issue in inspection.issues)
                deltas.append(
                    _delta(
                        "inspection",
                        side,
                        "uninspectable",
                        None,
                        None,
                        "info",
                        "; ".join(inspection.issues),
                    )
                )
        packages.append(
            {
                "path": change.path,
                "status": change.status,
                "base": _occurrence_dict(change.base),
                "head": _occurrence_dict(change.head),
                "base_inspection": before.to_dict(),
                "head_inspection": after.to_dict(),
                "deltas": sorted(deltas, key=lambda item: (item["kind"], item["key"])),
            }
        )
    actions = {item["action"] for package in packages for item in package["deltas"]}
    complete = not issues
    decision = (
        "block"
        if "block" in actions
        else "incomplete"
        if not complete
        else "review"
        if "review" in actions
        else "pass"
    )
    summary = {
        f"packages_{status}": counts[status]
        for status in ("added", "removed", "changed", "unchanged")
    }
    summary["packages_reviewed"] = len(packages)
    for action in ("review", "block"):
        summary[f"{action}_deltas"] = sum(
            delta["action"] == action for package in packages for delta in package["deltas"]
        )
    return ReviewReport(
        base_state.label,
        head_state.label,
        decision,
        complete,
        summary,
        tuple(packages),
        tuple(sorted(set(issues))),
        origins,
    )


def _scope_issues(state: LockState, selected: set[str]) -> tuple[str, ...]:
    # Artifact availability outside the selected update is not evidence missing
    # from this comparison. Root/schema and unresolved graph issues remain global.
    unselected_issues = {
        issue
        for path, occurrence in state.occurrences.items()
        if path not in selected
        for issue in occurrence.metadata.get("issues", [])
        if issue not in occurrence.metadata.get("validation_issues", [])
    }
    return tuple(issue for issue in state.issues if issue not in unselected_issues)


@dataclass
class _Scanner:
    config: ArtifactScanConfig
    enabled: bool
    memo: dict[tuple[Any, ...], Inspection] = field(default_factory=dict)

    def inspect(self, occurrence: LockOccurrence | None) -> Inspection:
        if occurrence is None:
            return Inspection("absent")
        if not self.enabled:
            return Inspection("incomplete", issues=("Artifact inspection was disabled.",))
        package = occurrence.package
        if not occurrence.metadata.get("inspection_supported", False):
            return Inspection(
                "incomplete",
                issues=("This occurrence cannot be inspected as a locked npm registry tarball.",),
            )
        if len(package.artifacts) != 1 or package.artifacts[0].kind != "npm-tarball":
            return Inspection("incomplete", issues=("An unambiguous npm tarball is required.",))
        artifact = package.artifacts[0]
        integrity = _strong_integrity(artifact.hash or "")
        if integrity is None:
            return Inspection(
                "incomplete",
                issues=("A valid SHA-256, SHA-384 or SHA-512 SRI digest is required.",),
            )
        if self.config.url_validator is None or not self.config.url_validator(artifact.url or ""):
            return Inspection(
                "incomplete",
                issues=(
                    "Artifact URL is outside the trusted HTTPS registry origins or contains credentials.",
                ),
            )
        # Include expected identity and alias declarations: identical bytes must still
        # be validated separately if their expected package identity differs.
        key = (
            package.name,
            package.version,
            artifact.url,
            integrity,
            repr(package.metadata.get("requested_specifiers")),
        )
        if key in self.memo:
            return self.memo[key]
        verified_package = replace(package, artifacts=(replace(artifact, hash=integrity),))
        collection = collect_artifact_snapshots(
            Inventory(repo_path=".", packages=(verified_package,)),
            self.config,
        )
        issues: list[str] = []
        blocks: list[str] = []
        for finding in collection.findings:
            if finding.metadata.get("action") == "block":
                blocks.append(finding.signal_type)
            # Acquisition exceptions may contain credential-bearing redirect URLs.
            # Expose a stable diagnostic rather than copying the exception verbatim.
            issues.append(
                {
                    "artifact_hash_mismatch": "Artifact digest does not match the lockfile SRI.",
                    "artifact_unpack_error": "Artifact could not be extracted safely within resource limits.",
                    "artifact_fetch_error": "Artifact could not be fetched under the registry and size policy.",
                }.get(finding.signal_type, "Artifact acquisition did not complete.")
            )
        if collection.warnings or collection.skipped_artifacts:
            issues.append("Artifact acquisition skipped required evidence.")
        facts: tuple[BehaviorFact, ...] = ()
        declarations_complete = False
        if len(collection.snapshots) == 1:
            profile = inspect_snapshot(collection.snapshots[0])
            facts = profile.facts
            issues.extend(profile.issues)
            declarations_complete = profile.declarations_complete
        else:
            issues.append("No verified artifact snapshot is available.")
        result = Inspection(
            "incomplete" if issues else "verified",
            facts,
            tuple(sorted(set(issues))),
            tuple(sorted(set(blocks))),
            declarations_complete=declarations_complete,
        )
        self.memo[key] = result
        return result


def _registry_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or any(ord(c) <= 32 for c in value)
        ):
            raise ValueError
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        return f"https://{host}" + (f":{port}" if port not in (None, 443) else "")
    except ValueError:
        raise ValueError(
            "Trusted registries must be HTTPS origins without credentials or paths."
        ) from None


def _permitted_url(value: str, origins: tuple[str, ...]) -> bool:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "\\" in value
            or any(ord(c) <= 32 for c in value)
        ):
            return False
        return _registry_origin(f"https://{parsed.netloc}") in origins
    except ValueError:
        return False


def _strong_integrity(value: str) -> str | None:
    candidates: list[tuple[int, str]] = []
    for token in value.split():
        match = _SRI.fullmatch(token)
        if match is None:
            # Legacy SHA-1 entries may coexist with a stronger SRI entry.
            if token.startswith("sha1-"):
                continue
            return None
        algorithm, encoded = match.groups()
        bits = int(algorithm[3:])
        try:
            digest = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(digest) != bits // 8:
            return None
        candidates.append((bits, token))
    if not candidates:
        return None
    strongest = max(bits for bits, _ in candidates)
    return " ".join(sorted({token for bits, token in candidates if bits == strongest}))


def _occurrence_dict(occurrence: LockOccurrence | None) -> dict[str, Any] | None:
    if occurrence is None:
        return None
    allowed = (
        "installed_name",
        "dependency_kind",
        "source_kind",
        "source",
        "source_registry",
        "integrity",
        "dependencies",
        "requested_specifiers",
        "has_install_script",
        "dev",
        "optional",
        "dev_optional",
        "in_bundle",
        "link",
        "platforms",
        "peer_metadata",
        "cycle_references",
    )
    return {
        "name": occurrence.package.name,
        "version": occurrence.package.version,
        "chains": [list(chain) for chain in occurrence.chains],
        **{key: occurrence.metadata[key] for key in allowed if key in occurrence.metadata},
    }


def _metadata_deltas(change: LockChange) -> list[dict[str, Any]]:
    before = _occurrence_dict(change.base) or {}
    after = _occurrence_dict(change.head) or {}
    before_metadata = change.base.metadata if change.base is not None else {}
    after_metadata = change.head.metadata if change.head is not None else {}
    before_identities = before_metadata.get("comparison_identities", {})
    after_identities = after_metadata.get("comparison_identities", {})
    same_release = bool(
        before
        and after
        and before["name"] == after["name"]
        and before["version"] == after["version"]
    )
    deltas: list[dict[str, Any]] = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        old_identity = before_identities.get(key)
        new_identity = after_identities.get(key)
        identity_changed = (
            old_identity is not None and new_identity is not None and old_identity != new_identity
        )
        status = (
            "added"
            if key not in before
            else "removed"
            if key not in after
            else ("unchanged" if old == new and not identity_changed else "changed")
        )
        action = "info"
        reason = "Lockfile metadata comparison."
        if status in ("added", "changed"):
            if key == "dependencies" and _introduced_dependencies(
                before_metadata.get("dependency_comparison_identities", old),
                after_metadata.get("dependency_comparison_identities", new),
            ):
                action = "review"
                reason = "Lockfile dependency declarations were added or changed."
            elif (
                key in {"has_install_script", "link", "in_bundle"}
                and new
                or key
                in {
                    "name",
                    "source_kind",
                    "dev",
                    "optional",
                    "dev_optional",
                    "dependency_kind",
                    "platforms",
                    "peer_metadata",
                }
                and status == "changed"
            ):
                action = "review"
            elif key in {"source", "integrity"} and same_release:
                action = "review"
                reason = "Artifact identity changed without a package version change."
            elif key == "source" and old and new and _source_origin(old) != _source_origin(new):
                action = "review"
                reason = "Package artifact origin changed."
        delta = _delta("lock_metadata", key, status, old, new, action, reason)
        if any(
            identity is not None
            and identity
            != hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            for identity, value in ((old_identity, old), (new_identity, new))
        ):
            delta["base_identity_sha256"] = old_identity
            delta["head_identity_sha256"] = new_identity
        deltas.append(delta)
    return deltas


def _introduced_dependencies(before: Any, after: Any) -> bool:
    old = {(item["group"], item["name"]): item["specifier"] for item in before or []}
    return any(old.get((item["group"], item["name"])) != item["specifier"] for item in after or [])


def _source_origin(value: Any) -> str:
    try:
        parsed = urlsplit(str(value))
        if parsed.scheme == "https":
            return _registry_origin(f"https://{parsed.netloc}")
        return f"{parsed.scheme}://{parsed.netloc}"
    except ValueError:
        return "unknown"


def _behavior_deltas(before: Inspection, after: Inspection) -> list[dict[str, Any]]:
    left = {(fact.kind, fact.key): fact for fact in before.facts}
    right = {(fact.kind, fact.key): fact for fact in after.facts}
    result = []
    for kind, key in sorted(left.keys() | right.keys()):
        old, new = left.get((kind, key)), right.get((kind, key))
        reason = "Compared verified package declarations or static observations."
        action = "info"
        if old is None:
            status = "uninspectable" if _absence_unknown(before, kind) else "added"
        elif new is None:
            status = "uninspectable" if _absence_unknown(after, kind) else "removed"
        else:
            status = "unchanged" if old.value == new.value else "changed"
        if status == "uninspectable":
            reason = "Missing evidence on one side prevents establishing this change."
        elif new is not None and status in ("added", "changed"):
            action = new.action
        result.append(
            _delta(
                kind,
                key,
                status,
                old.value if old else None,
                new.value if new else None,
                action,
                reason,
            )
        )
    return result


def _absence_unknown(inspection: Inspection, kind: str) -> bool:
    return inspection.status == "incomplete" and not (
        kind in _DECLARATION_KINDS and inspection.declarations_complete
    )


def _delta(
    kind: str, key: str, status: str, base: Any, head: Any, action: str, reason: str
) -> dict[str, Any]:
    result = {
        "kind": kind,
        "key": redact_text(key),
        "status": status,
        "base": redact_value(base),
        "head": redact_value(head),
        "action": action,
        "reason": redact_text(reason),
    }
    # Compare original values above. When displays hide sensitive differences,
    # retain their exact value identities so the change remains reviewable.
    if result["base"] != base or result["head"] != head:
        for side, value in (("base", base), ("head", head)):
            result[f"{side}_identity_sha256"] = (
                hashlib.sha256(
                    json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                if value is not None
                else None
            )
    return result
