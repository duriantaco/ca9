from __future__ import annotations

import json
import os
import re
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

from ca9.analyzers.install_scripts import (
    KNOWN_SCRIPT_PATTERNS,
    VERDICT_ALLOW_CANDIDATE,
    VERDICT_DENY,
    VERDICT_REVIEW,
    ScriptHook,
    classify_install_scripts,
    install_hooks_from_manifest,
)
from ca9.artifacts.fetch import ArtifactScanConfig, collect_artifact_snapshots
from ca9.artifacts.model import ArtifactSnapshot
from ca9.core.models import Finding, Inventory, Package
from ca9.package_policy import PackagePolicy

_VERDICT_SORT = {VERDICT_DENY: 0, VERDICT_REVIEW: 1, VERDICT_ALLOW_CANDIDATE: 2}
_MAX_COMMAND_CHARS = 160
_SUPPORTED_LOCKFILE_VERSIONS = {2, 3}
_SAFE_NPM_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*$")
_NPM_SEMVER_RE = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_VERIFIED_NATIVE_COMMANDS = frozenset(
    command
    for pattern in KNOWN_SCRIPT_PATTERNS
    if pattern.requires_verified_artifact_analysis
    for command in pattern.commands
)
_BINDING_GYP_COMMANDS = frozenset(
    {
        "node-gyp rebuild",
        "prebuild-install || node-gyp rebuild",
    }
)


class ScriptsAuditError(ValueError):
    """Raised when install-script audit input cannot be trusted."""


@dataclass(frozen=True)
class ScriptAuditEntry:
    package: Package
    hooks: tuple[ScriptHook, ...]
    verdict: str
    reasons: tuple[str, ...]
    notes: tuple[str, ...]
    scripts_source: str
    installed_tree_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        policy_name = _policy_name(self.package)
        return {
            "package": self.package.name,
            "version": self.package.version,
            "key": self.package.key,
            "dependency_kind": self.package.dependency_kind,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "notes": list(self.notes),
            "scripts_source": self.scripts_source,
            "lock_path": self.package.metadata.get("lock_path"),
            "policy_name": policy_name,
            "policy_names": [policy_name] if policy_name is not None else [],
            "installed_tree_verified": self.installed_tree_verified,
            "hooks": [hook.to_dict() for hook in self.hooks],
        }


@dataclass(frozen=True)
class ScriptsAuditReport:
    repo_path: str
    entries: tuple[ScriptAuditEntry, ...]
    warnings: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()

    @property
    def deny_count(self) -> int:
        return sum(1 for entry in self.entries if entry.verdict == VERDICT_DENY)

    @property
    def review_count(self) -> int:
        return sum(1 for entry in self.entries if entry.verdict == VERDICT_REVIEW)

    @property
    def allow_candidate_count(self) -> int:
        return sum(1 for entry in self.entries if entry.verdict == VERDICT_ALLOW_CANDIDATE)

    @property
    def exit_code(self) -> int:
        if self.blockers or self.deny_count:
            return 1
        if self.review_count:
            return 2
        return 0

    def summary(self) -> dict[str, int]:
        return {
            "packages_with_install_scripts": len(self.entries),
            "deny": self.deny_count,
            "review": self.review_count,
            "allow_candidates": self.allow_candidate_count,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ca9.scripts-audit.v1",
            "repo_path": self.repo_path,
            "summary": self.summary(),
            "packages": [entry.to_dict() for entry in self.entries],
            "warnings": list(self.warnings),
            "blockers": list(self.blockers),
        }


def build_scripts_audit_report(
    repo_path: Path,
    *,
    package_policy: PackagePolicy | None = None,
    feed_cache_dir: Path | None = None,
    artifact_config: ArtifactScanConfig | None = None,
    fetch_artifacts: bool = True,
) -> ScriptsAuditReport:
    from ca9.readers.package_lock import read_package_lock

    lock_data = _load_and_validate_package_lock(repo_path)
    inventory = read_package_lock(repo_path)
    warnings: list[str] = list(inventory.warnings)
    blockers: list[str] = []
    candidates = _script_candidates(inventory, lock_data)
    candidate_keys = {_audit_key(candidate) for candidate in candidates}
    accounted_paths = {
        package.metadata.get("lock_path")
        for package in inventory.packages
        if package.metadata.get("local_workspace") or _audit_key(package) in candidate_keys
    }
    unaccounted_paths = sorted(_eligible_lock_package_paths(lock_data) - accounted_paths)
    if unaccounted_paths:
        raise ScriptsAuditError(
            "package-lock.json script-bearing entry could not be materialized safely: "
            + ", ".join(repr(_single_line(path)) for path in unaccounted_paths)
        )

    deny_reasons_by_key: dict[str, list[str]] = {}
    review_reasons_by_key: dict[str, list[str]] = {}
    if package_policy is not None and package_policy.malware.enabled:
        _apply_malware_tier(
            candidates,
            package_policy,
            feed_cache_dir,
            deny_reasons_by_key,
            review_reasons_by_key,
            warnings,
            blockers,
        )

    artifact_candidates: list[Package] = []
    for package in candidates:
        audit_key = _audit_key(package)
        if package.metadata.get("identity_ambiguous"):
            review_reasons_by_key.setdefault(audit_key, []).append("policy-identity-ambiguous")
        lock_path = package.metadata.get("lock_path")
        if _is_external_file_target_path(lock_path):
            review_reasons_by_key.setdefault(audit_key, []).append("external-local-source")
        policy_name = _policy_name(package)
        if policy_name is None:
            review_reasons_by_key.setdefault(audit_key, []).append("policy-identity-unavailable")
        elif not _is_safe_npm_package_name(policy_name):
            review_reasons_by_key.setdefault(audit_key, []).append("invalid-package-name")
        trusted_identity = _trusted_registry_identity(package)
        if trusted_identity is not None and package.normalized_name != trusted_identity[0].lower():
            review_reasons_by_key.setdefault(audit_key, []).append("trusted-identity-mismatch")
        if (
            trusted_identity is not None
            and trusted_identity[1] is not None
            and package.version != trusted_identity[1]
        ):
            review_reasons_by_key.setdefault(audit_key, []).append("trusted-version-mismatch")
        if trusted_identity is not None and trusted_identity[1] is None:
            review_reasons_by_key.setdefault(audit_key, []).append("trusted-version-unavailable")
        if _apply_registry_policy(
            package,
            package_policy,
            deny_reasons_by_key,
            review_reasons_by_key,
        ):
            artifact_candidates.append(package)

    hooks_by_key: dict[str, tuple[ScriptHook, ...]] = {}
    source_by_key: dict[str, str] = {}
    for package in candidates:
        audit_key = _audit_key(package)
        hooks = _hooks_from_node_modules(repo_path, package)
        if hooks is not None:
            hooks_by_key[audit_key] = hooks
            source_by_key[audit_key] = "node_modules"

    verified_artifact_keys: set[str] = set()
    if artifact_candidates and fetch_artifacts:
        _resolve_from_artifacts(
            repo_path,
            artifact_candidates,
            artifact_config,
            hooks_by_key,
            source_by_key,
            deny_reasons_by_key,
            review_reasons_by_key,
            verified_artifact_keys,
            warnings,
            package_policy,
        )

    entries: list[ScriptAuditEntry] = []
    for package in candidates:
        audit_key = _audit_key(package)
        hooks = hooks_by_key.get(audit_key)
        classification = classify_install_scripts(
            hooks or (),
            deny_reasons=tuple(deny_reasons_by_key.get(audit_key, ())),
            scripts_available=hooks is not None,
            verified_artifact_analysis=audit_key in verified_artifact_keys,
        )
        verdict = classification.verdict
        reasons = list(classification.reasons)
        pending_review_reasons = review_reasons_by_key.get(audit_key, ())
        if pending_review_reasons:
            reasons.extend(pending_review_reasons)
            if verdict != VERDICT_DENY:
                verdict = VERDICT_REVIEW
        if (
            classification.verdict == VERDICT_ALLOW_CANDIDATE
            and verdict != VERDICT_DENY
            and _hooks_require_verified_native_evidence(hooks or ())
        ):
            # These whole-command patterns invoke executables resolved from the
            # lifecycle PATH. The package artifact alone cannot prove which
            # dependency (or alias) provides that binary, so it is supporting
            # evidence only until executable provenance is modeled end-to-end.
            verdict = VERDICT_REVIEW
            reasons.append("executable-provenance-unverified")
        if blockers and verdict != VERDICT_DENY:
            if verdict == VERDICT_ALLOW_CANDIDATE:
                verdict = VERDICT_REVIEW
            reasons.append("audit-blocked")
        entries.append(
            ScriptAuditEntry(
                package=package,
                hooks=hooks or (),
                verdict=verdict,
                reasons=tuple(dict.fromkeys(reasons)),
                notes=classification.notes,
                scripts_source=source_by_key.get(audit_key, "unavailable"),
            )
        )

    entries = _verify_installed_tree(repo_path, entries)

    entries.sort(
        key=lambda entry: (
            _VERDICT_SORT[entry.verdict],
            entry.package.name,
            entry.package.version or "",
            str(entry.package.metadata.get("lock_path") or ""),
        )
    )
    return ScriptsAuditReport(
        repo_path=str(repo_path),
        entries=tuple(entries),
        warnings=tuple(dict.fromkeys(warnings)),
        blockers=tuple(dict.fromkeys(blockers)),
    )


def scripts_audit_report_to_json(report: ScriptsAuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def scripts_audit_report_to_table(report: ScriptsAuditReport) -> str:
    summary = report.summary()
    lines = [
        f"ca9 install-script audit for {_single_line(report.repo_path)}",
        (
            f"Packages with install scripts: {summary['packages_with_install_scripts']} | "
            f"Deny: {summary['deny']} | Review: {summary['review']} | "
            f"Allow candidates: {summary['allow_candidates']}"
        ),
    ]

    if report.blockers:
        lines.append("")
        lines.append("Audit blockers:")
        lines.extend(f"  - {_single_line(blocker)}" for blocker in report.blockers)

    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {_single_line(warning)}" for warning in report.warnings)

    if report.entries:
        lines.append("")
        lines.append("Packages:")
        for entry in report.entries:
            package = entry.package
            lines.append(
                f"  [{entry.verdict.upper()}] {_single_line(package.name)}@"
                f"{_single_line(package.version or 'unknown')} "
                f"({_single_line(package.dependency_kind)}, "
                f"scripts: {_single_line(entry.scripts_source)}, "
                f"lock: {_single_line(package.metadata.get('lock_path') or 'unknown')})"
            )
            installed_names = package.metadata.get("installed_names")
            if isinstance(installed_names, list) and installed_names:
                lines.append(
                    "    Installed as: " + ", ".join(_single_line(name) for name in installed_names)
                )
            policy_name = _policy_name(package)
            lines.append(f"    npm policy identity: {_single_line(policy_name or 'unavailable')}")
            for hook in entry.hooks:
                lines.append(f"    {_single_line(hook.name)}: {_truncate(hook.command)}")
            lines.append(f"    Why: {_comment_text(entry.reasons)}")
            if entry.notes:
                lines.append(f"    Notes: {_comment_text(entry.notes)}")
    else:
        lines.append("")
        lines.append("No dependency install scripts found.")

    return "\n".join(lines)


def scripts_audit_report_to_commands(report: ScriptsAuditReport) -> str:
    lines = [
        "# generated by ca9 scripts audit; review the audit report before running",
        f"# audited repository: {_single_line(report.repo_path)}",
        "# POSIX-shell/PowerShell comments; run commands from the audited repository",
        "# approvals require every locked occurrence and the installed tree to match",
    ]
    lines.extend(f"# warning: {_single_line(warning)}" for warning in report.warnings)
    if report.blockers:
        lines.append(
            "# approvals suppressed by audit blocker(s): " + _comment_text(report.blockers)
        )

    grouped: dict[str, list[ScriptAuditEntry]] = {}
    for entry in report.entries:
        policy_name = _policy_name(entry.package)
        group_key = (
            f"name:{policy_name.lower()}"
            if policy_name is not None
            else f"occurrence:{_audit_key(entry.package)}"
        )
        grouped.setdefault(group_key, []).append(entry)

    deny_groups: list[tuple[str, list[ScriptAuditEntry]]] = []
    allow_groups: list[tuple[str, list[ScriptAuditEntry]]] = []
    review_groups: list[tuple[str, list[ScriptAuditEntry]]] = []
    for normalized_name, entries in sorted(grouped.items()):
        group = (normalized_name, entries)
        if any(entry.verdict == VERDICT_DENY for entry in entries):
            deny_groups.append(group)
        elif all(
            entry.verdict == VERDICT_ALLOW_CANDIDATE and entry.installed_tree_verified
            for entry in entries
        ):
            allow_groups.append(group)
        else:
            review_groups.append(group)

    for _normalized_name, entries in deny_groups:
        name = _policy_name(entries[0].package)
        if (
            name is not None
            and _is_safe_npm_package_name(name)
            and all(entry.installed_tree_verified for entry in entries)
        ):
            lines.append(f"npm deny-scripts {name}  # {_group_comment(entries)}")
        elif name is not None and _is_safe_npm_package_name(name):
            lines.append(
                "# denial command suppressed until the installed tree matches: "
                f"{_single_line(name)} ({_group_comment(entries)})"
            )
        else:
            lines.append(
                "# trusted npm policy identity unavailable; deny command not emitted: "
                f"{_single_line(entries[0].package.name)}"
            )

    for _normalized_name, entries in allow_groups:
        name = _policy_name(entries[0].package)
        if report.blockers:
            lines.append(
                f"# approval suppressed: {_single_line(name or entries[0].package.name)} "
                f"({_group_comment(entries)})"
            )
        elif name is not None and _is_safe_npm_package_name(name):
            lines.append(
                f"npm approve-scripts {name} --allow-scripts-pin  # {_group_comment(entries)}"
            )
        elif name is None:
            lines.append(
                "# trusted npm policy identity unavailable; approval not emitted: "
                f"{_single_line(entries[0].package.name)}"
            )
        else:
            lines.append(f"# invalid package name; approval not emitted: {_single_line(name)}")

    for _normalized_name, entries in review_groups:
        name = _policy_name(entries[0].package)
        if name is not None and _is_safe_npm_package_name(name):
            lines.append(
                "# review needed, no command emitted: "
                f"{_single_line(name)} ({_group_comment(entries)})"
            )
        else:
            lines.append(
                "# trusted npm policy identity unavailable; no command emitted: "
                f"{_single_line(entries[0].package.name)} ({_group_comment(entries)})"
            )
    return "\n".join(lines)


def _script_candidates(inventory: Inventory, lock_data: dict[str, Any]) -> list[Package]:
    lock_package_paths = _eligible_lock_package_paths(lock_data)
    candidates: dict[str, Package] = {}
    for package in inventory.packages:
        if package.ecosystem.lower() != "npm":
            continue
        if package.dependency_kind not in {"direct", "transitive"}:
            continue
        if package.metadata.get("local_workspace"):
            continue
        lock_path = package.metadata.get("lock_path")
        if not isinstance(lock_path, str) or lock_path not in lock_package_paths:
            continue
        if not package.metadata.get("has_install_script"):
            continue
        candidates.setdefault(_audit_key(package), package)
    return list(candidates.values())


def _apply_malware_tier(
    candidates: list[Package],
    package_policy: PackagePolicy,
    feed_cache_dir: Path | None,
    deny_reasons_by_key: dict[str, list[str]],
    review_reasons_by_key: dict[str, list[str]],
    warnings: list[str],
    blockers: list[str],
) -> None:
    from ca9.package_feed import FeedError, feed_status, package_malware_findings

    feed_packages: dict[str, Package] = {}
    audit_keys_by_feed_key: dict[str, set[str]] = {}
    for package in candidates:
        identities = {(package.name, package.version)}
        self_name = package.metadata.get("self_name")
        if isinstance(self_name, str) and self_name.strip():
            identities.add((self_name.strip(), package.version))
        trusted_identity = _trusted_registry_identity(package)
        if trusted_identity is not None:
            identities.add(trusted_identity)
        for name, version in identities:
            feed_package = replace(package, name=name, version=version)
            feed_packages.setdefault(feed_package.key, feed_package)
            audit_keys_by_feed_key.setdefault(feed_package.key, set()).add(_audit_key(package))

    try:
        status = feed_status(policy=package_policy, cache_dir=feed_cache_dir)
        if status.state in {"missing", "stale"} and not package_policy.malware.fail_closed:
            warnings.append(
                f"malware feed is {status.state}; malware tier skipped: {status.reason}"
            )
            for package in candidates:
                review_reasons_by_key.setdefault(_audit_key(package), []).append(
                    "malware-tier-unavailable"
                )
        malware_findings, feed_warnings = package_malware_findings(
            tuple(feed_packages.values()),
            package_policy,
            cache_dir=feed_cache_dir,
        )
    except FeedError as exc:
        reason = f"malware feed unavailable: {exc}"
        if package_policy.malware.fail_closed:
            blockers.append(reason)
        else:
            warnings.append(f"{reason}; malware tier skipped")
            for package in candidates:
                review_reasons_by_key.setdefault(_audit_key(package), []).append(
                    "malware-tier-unavailable"
                )
        return
    warnings.extend(feed_warnings)
    for finding in malware_findings:
        if finding.signal_type == "malware":
            for audit_key in audit_keys_by_feed_key.get(finding.package_key, ()):
                deny_reasons_by_key.setdefault(audit_key, []).append(_malware_reason(finding))
        elif finding.metadata.get("action") == "block":
            blockers.append(
                str(finding.metadata.get("reason") or finding.title or finding.signal_type)
            )
        else:
            warnings.append(f"malware feed: {finding.metadata.get('reason') or finding.title}")


def _resolve_from_artifacts(
    repo_path: Path,
    packages: list[Package],
    artifact_config: ArtifactScanConfig | None,
    hooks_by_key: dict[str, tuple[ScriptHook, ...]],
    source_by_key: dict[str, str],
    deny_reasons_by_key: dict[str, list[str]],
    review_reasons_by_key: dict[str, list[str]],
    verified_artifact_keys: set[str],
    warnings: list[str],
    package_policy: PackagePolicy | None,
) -> None:
    from ca9.analyzers.npm_build_controls import analyze_native_build_controls
    from ca9.analyzers.package_code import analyze_package_snapshots

    for package in packages:
        audit_key = _audit_key(package)
        active_config = artifact_config or ArtifactScanConfig()
        if active_config.allowed_local_roots is None:
            active_config = replace(
                active_config,
                allowed_local_roots=(repo_path.resolve(),),
            )
        caller_validator = active_config.url_validator
        active_config = replace(
            active_config,
            url_validator=lambda url, caller_validator=caller_validator, policy=package_policy: (
                (caller_validator is None or caller_validator(url))
                and _artifact_url_permitted(url, policy)
            ),
        )
        result = collect_artifact_snapshots(
            Inventory(repo_path=str(repo_path), packages=(package,)),
            active_config,
        )
        warnings.extend(result.warnings)
        analysis_findings = analyze_package_snapshots(result.snapshots)
        blocked = False
        investigated = False
        for finding in [*result.findings, *analysis_findings]:
            if finding.metadata.get("action") == "block":
                deny_reasons_by_key.setdefault(audit_key, []).append(finding.signal_type)
                blocked = True
            elif (
                finding.metadata.get("action") == "investigate"
                and finding.signal_type != "npm-install-script"
            ):
                review_reasons_by_key.setdefault(audit_key, []).append(finding.signal_type)
                investigated = True

        snapshots = list(result.snapshots)
        manifest_result = _manifest_from_snapshots(snapshots, package)
        if manifest_result is None:
            if snapshots:
                review_reasons_by_key.setdefault(audit_key, []).append("artifact-manifest-mismatch")
            continue
        manifest, snapshot = manifest_result
        artifact_hooks = install_hooks_from_manifest(
            manifest,
            include_prepare=_include_prepare(package),
        )
        existing_hooks = hooks_by_key.get(audit_key)
        if existing_hooks is not None and existing_hooks != artifact_hooks:
            review_reasons_by_key.setdefault(audit_key, []).append(
                "installed-artifact-script-drift"
            )
            hooks_by_key[audit_key] = _merge_hooks(existing_hooks, artifact_hooks)
            source_by_key[audit_key] = "node_modules+artifact"
        else:
            hooks_by_key[audit_key] = artifact_hooks
            source_by_key[audit_key] = (
                "node_modules+artifact" if existing_hooks is not None else "artifact"
            )
        hooks = hooks_by_key[audit_key]
        if not _hooks_require_verified_native_evidence(hooks):
            continue
        build_controls = analyze_native_build_controls((snapshot,))
        if not build_controls.safe:
            review_reasons_by_key.setdefault(audit_key, []).extend(
                ["native-build-control-review", *build_controls.reasons]
            )
            continue
        if _hooks_require_binding_gyp(hooks) and not build_controls.binding_gyp_present:
            review_reasons_by_key.setdefault(audit_key, []).append("binding-gyp-missing")
            continue
        if not _snapshot_has_native_build_evidence(snapshot):
            review_reasons_by_key.setdefault(audit_key, []).append(
                "native-build-evidence-unavailable"
            )
            continue
        if snapshot.artifact.hash and not blocked and not investigated:
            verified_artifact_keys.add(audit_key)


def _hooks_from_node_modules(repo_path: Path, package: Package) -> tuple[ScriptHook, ...] | None:
    parts = _npm_package_parts(package.name)
    if parts is None:
        return None

    lock_path = package.metadata.get("lock_path")
    if isinstance(lock_path, str):
        lock_manifest = _safe_manifest_path(repo_path, lock_path)
        if lock_manifest is not None:
            safe_path = _safe_existing_path(repo_path, lock_manifest)
            if safe_path is not None:
                manifest = _read_matching_manifest(safe_path, package)
                if manifest is not None:
                    return install_hooks_from_manifest(
                        manifest,
                        include_prepare=_include_prepare(package),
                    )
        # Every package-lock occurrence has a precise install/source path. Do
        # not fall back to a different same-name occurrence when that evidence
        # is absent or mismatched.
        return None

    top_level = repo_path.joinpath("node_modules", *parts, "package.json")
    safe_path = _safe_existing_path(repo_path, top_level)
    if safe_path is not None:
        manifest = _read_matching_manifest(safe_path, package)
        if manifest is not None:
            return install_hooks_from_manifest(
                manifest,
                include_prepare=_include_prepare(package),
            )
    return None


def _read_matching_manifest(manifest_path: Path, package: Package) -> dict[str, Any] | None:
    try:
        data = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if str(data.get("name") or "").strip().lower() not in _manifest_names(package):
        return None
    if not package.version or str(data.get("version") or "") != package.version:
        return None
    return data


def _manifest_from_snapshots(
    snapshots: list[ArtifactSnapshot],
    package: Package,
) -> tuple[dict[str, Any], ArtifactSnapshot] | None:
    for snapshot in snapshots:
        files_by_path = {file.relative_path: file for file in snapshot.files}
        for relative_path in ("package/package.json", "package.json"):
            file = files_by_path.get(relative_path)
            if file is None:
                continue
            try:
                data = json.loads(file.path.read_text())
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            if str(data.get("name") or "").strip().lower() not in _manifest_names(package):
                continue
            if not package.version or str(data.get("version") or "") != package.version:
                continue
            return data, snapshot
    return None


def _load_and_validate_package_lock(repo_path: Path) -> dict[str, Any]:
    lock_path = repo_path / "package-lock.json"
    if not lock_path.is_file():
        raise ScriptsAuditError(
            f"package-lock.json is required at {lock_path}; generate it with npm install "
            "--package-lock-only"
        )
    try:
        data = json.loads(lock_path.read_text())
    except OSError as exc:
        raise ScriptsAuditError(f"cannot read package-lock.json: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ScriptsAuditError(f"cannot parse package-lock.json: {exc}") from exc
    if not isinstance(data, dict):
        raise ScriptsAuditError("package-lock.json must contain a JSON object")

    lockfile_version = data.get("lockfileVersion")
    if (
        isinstance(lockfile_version, bool)
        or not isinstance(lockfile_version, int)
        or lockfile_version not in _SUPPORTED_LOCKFILE_VERSIONS
    ):
        supported = ", ".join(str(value) for value in sorted(_SUPPORTED_LOCKFILE_VERSIONS))
        raise ScriptsAuditError(
            f"unsupported package-lock.json lockfileVersion {lockfile_version!r}; "
            f"supported versions are {supported}"
        )

    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise ScriptsAuditError("package-lock.json packages table must be an object")
    if "" not in packages or not isinstance(packages.get(""), dict):
        raise ScriptsAuditError("package-lock.json packages table is missing its root entry")
    invalid_path = next(
        (path for path, entry in packages.items() if not isinstance(entry, dict)),
        None,
    )
    if invalid_path is not None:
        raise ScriptsAuditError(
            f"package-lock.json package entry {_single_line(invalid_path)!r} must be an object"
        )
    for path, entry in packages.items():
        for field in ("hasInstallScript", "link"):
            if field in entry and not isinstance(entry[field], bool):
                raise ScriptsAuditError(
                    "package-lock.json package entry "
                    f"{_single_line(path)!r} has a non-boolean {field} field"
                )
        for field in ("name", "version", "resolved", "integrity"):
            if field in entry and (not isinstance(entry[field], str) or not entry[field].strip()):
                raise ScriptsAuditError(
                    "package-lock.json package entry "
                    f"{_single_line(path)!r} has an invalid {field} field"
                )
    unsafe_path = next(
        (
            path
            for path in packages
            if path
            and not _is_external_file_target_path(path)
            and not _is_safe_lock_package_path(path)
        ),
        None,
    )
    if unsafe_path is not None:
        raise ScriptsAuditError(
            f"package-lock.json contains an unsafe package path: {_single_line(unsafe_path)!r}"
        )
    for path, entry in packages.items():
        if entry.get("link") is not True or entry.get("hasInstallScript") is not True:
            continue
        target = _lock_link_target(entry.get("resolved"))
        target_entry = packages.get(target) if target is not None else None
        if (
            not isinstance(target_entry, dict)
            or target_entry.get("link") is True
            or target_entry.get("hasInstallScript") is not True
        ):
            raise ScriptsAuditError(
                "package-lock.json script-bearing link has no auditable target: "
                f"{_single_line(path)!r}"
            )
    return data


def _eligible_lock_package_paths(lock_data: dict[str, Any]) -> set[str]:
    packages = lock_data["packages"]
    paths: set[str] = set()
    for path, entry in packages.items():
        if not path or entry.get("link") is True:
            continue
        if entry.get("hasInstallScript") is not True:
            continue
        paths.add(path)
    return paths


def _lock_entry_name(path: str, entry: dict[str, Any]) -> str | None:
    name = entry.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    segment = path.rsplit("node_modules/", 1)[-1]
    parts = segment.split("/")
    if parts and parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts and parts[0] else None


def _apply_registry_policy(
    package: Package,
    package_policy: PackagePolicy | None,
    deny_reasons_by_key: dict[str, list[str]],
    review_reasons_by_key: dict[str, list[str]],
) -> bool:
    if package_policy is None or not package.source_registry:
        return True
    audit_key = _audit_key(package)
    registry = package.source_registry
    registry_target = next(
        (artifact.url for artifact in package.artifacts if artifact.url),
        registry,
    )
    if _registry_identity(registry_target) is None:
        review_reasons_by_key.setdefault(audit_key, []).append("policy:ambiguous-registry-url")
        return False
    if _registry_matches(registry_target, package_policy.registries.deny):
        deny_reasons_by_key.setdefault(audit_key, []).append("policy:denied-registry")
        return False
    if package_policy.registries.custom_requires_approval and not _registry_matches(
        registry_target,
        package_policy.registries.allow,
    ):
        review_reasons_by_key.setdefault(audit_key, []).append("policy:unapproved-registry")
        return False
    return True


def _registry_matches(registry: str, candidates: tuple[str, ...]) -> bool:
    registry_identity = _registry_identity(registry)
    if registry_identity is None:
        return False
    registry_host, registry_path = registry_identity
    for candidate in candidates:
        candidate_identity = _registry_identity(candidate)
        if candidate_identity is None:
            continue
        candidate_host, candidate_path = candidate_identity
        if registry_host != candidate_host:
            continue
        if (
            not candidate_path
            or registry_path == candidate_path
            or registry_path.startswith(candidate_path + "/")
        ):
            return True
    return False


def _registry_identity(value: str) -> tuple[str, str] | None:
    raw = value.strip()
    if not raw or any(char.isspace() or not char.isprintable() for char in raw):
        return None
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return None
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    hostname = parsed.hostname
    if not hostname:
        return None
    try:
        host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    host = host[:-1] if host.endswith(".") else host
    if not host or any(not label for label in host.split(".")):
        return None
    scheme = parsed.scheme.lower()
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    try:
        decoded_path = unquote_to_bytes(parsed.path).decode("utf-8")
    except UnicodeDecodeError:
        return None
    if (
        "%" in decoded_path
        or "\\" in decoded_path
        or any(char.isspace() or not char.isprintable() for char in decoded_path)
    ):
        return None
    segments: list[str] = []
    for segment in decoded_path.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return host, "/" + "/".join(segments) if segments else ""


def _artifact_url_permitted(url: str, package_policy: PackagePolicy | None) -> bool:
    if url.startswith(("//", "\\")):
        return False
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme in {"", "file"}:
        return True
    if scheme not in {"http", "https"}:
        return False
    if _registry_identity(url) is None:
        return False
    if package_policy is None:
        return True
    if _registry_matches(url, package_policy.registries.deny):
        return False
    return not package_policy.registries.custom_requires_approval or _registry_matches(
        url,
        package_policy.registries.allow,
    )


def _include_prepare(package: Package) -> bool:
    source_kind = package.metadata.get("requested_source_kind")
    if isinstance(source_kind, str):
        return source_kind != "registry"
    return package.metadata.get("source_kind") != "registry"


def _npm_package_parts(name: str) -> tuple[str, ...] | None:
    if not _is_safe_npm_package_name(name):
        return None
    if name.startswith("@"):
        scope, package_name = name[1:].split("/", 1)
        return f"@{scope}", package_name
    return (name,)


def _safe_manifest_path(repo_path: Path, lock_path: str) -> Path | None:
    relative = Path(lock_path)
    if relative.is_absolute():
        return None
    if any(part in {"", ".", ".."} for part in relative.parts):
        return None
    return repo_path / relative / "package.json"


def _safe_existing_path(repo_path: Path, manifest_path: Path) -> Path | None:
    try:
        if not manifest_path.is_file():
            return None
        resolved_repo = repo_path.resolve()
        resolved_manifest = manifest_path.resolve()
        resolved_manifest.relative_to(resolved_repo)
    except (OSError, ValueError):
        return None
    return resolved_manifest


def _snapshot_has_native_build_evidence(snapshot: ArtifactSnapshot) -> bool:
    for file in snapshot.files:
        normalized = f"/{file.relative_path.lower().lstrip('/')}"
        if normalized.endswith("/binding.gyp") or "/prebuilds/" in normalized:
            return True
    return False


def _hooks_require_binding_gyp(hooks: tuple[ScriptHook, ...]) -> bool:
    return any(_normalized_hook_command(hook) in _BINDING_GYP_COMMANDS for hook in hooks)


def _hooks_require_verified_native_evidence(hooks: tuple[ScriptHook, ...]) -> bool:
    return any(_normalized_hook_command(hook) in _VERIFIED_NATIVE_COMMANDS for hook in hooks)


def _normalized_hook_command(hook: ScriptHook) -> str:
    return re.sub(r"[ \t]+", " ", hook.command).strip(" \t")


def _is_safe_lock_package_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _is_external_file_target_path(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("../") or "\\" in value:
        return False
    path = Path(value)
    if path.is_absolute():
        return False
    parts = path.parts
    if "node_modules" in parts:
        return False
    leading_parents = 0
    while leading_parents < len(parts) and parts[leading_parents] == "..":
        leading_parents += 1
    return leading_parents > 0 and all(
        part not in {"", ".", ".."} for part in parts[leading_parents:]
    )


def _lock_link_target(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    raw = value.removeprefix("file:").rstrip("/")
    path = Path(raw)
    if not raw or path.is_absolute():
        return None
    parts = path.parts
    leading_parents = 0
    while leading_parents < len(parts) and parts[leading_parents] == "..":
        leading_parents += 1
    if any(part in {"", ".", ".."} for part in parts[leading_parents:]):
        return None
    return "/".join(parts)


def _audit_key(package: Package) -> str:
    occurrence = package.metadata.get("lock_occurrence_id")
    if isinstance(occurrence, str) and occurrence:
        return occurrence
    lock_path = package.metadata.get("lock_path")
    if isinstance(lock_path, str) and lock_path:
        return f"{package.key}\0{lock_path}"
    return package.key


def _policy_name(package: Package) -> str | None:
    trusted = _trusted_registry_identity(package)
    return trusted[0] if trusted is not None else None


def _trusted_registry_identity(package: Package) -> tuple[str, str | None] | None:
    requested_kind = package.metadata.get("requested_source_kind")
    if requested_kind in {"remote", "git", "file", "workspace", "mixed"}:
        return None

    for artifact in package.artifacts:
        if not artifact.url:
            continue
        parsed = urlsplit(artifact.url)
        if parsed.scheme.lower() not in {"http", "https"}:
            continue
        identity = _registry_tarball_identity(parsed.path)
        if identity is not None:
            return identity

    if requested_kind != "registry":
        return None
    specifiers = package.metadata.get("requested_specifiers")
    alias_names: set[str] = set()
    if isinstance(specifiers, list):
        for specifier in specifiers:
            if isinstance(specifier, str) and specifier.startswith("npm:"):
                alias_name = _npm_alias_target_name(specifier)
                if alias_name:
                    alias_names.add(alias_name)
    if len(alias_names) == 1:
        return alias_names.pop(), None
    if alias_names:
        return None
    installed_names = package.metadata.get("installed_names")
    if (
        isinstance(installed_names, list)
        and len(installed_names) == 1
        and isinstance(installed_names[0], str)
        and _is_safe_npm_package_name(installed_names[0])
    ):
        return installed_names[0], None
    return None


def _registry_tarball_identity(raw_path: str) -> tuple[str, str] | None:
    try:
        parts = [unquote_to_bytes(part).decode("utf-8") for part in raw_path.split("/") if part]
    except UnicodeDecodeError:
        return None
    try:
        separator = len(parts) - 1 - parts[::-1].index("-")
    except ValueError:
        return None
    if separator < 1 or separator + 2 != len(parts):
        return None
    name_parts = parts[:separator]
    tail_name = name_parts[-1]
    if tail_name.startswith("@") and "/" in tail_name:
        name = tail_name
    elif len(name_parts) >= 2 and name_parts[-2].startswith("@"):
        name = f"{name_parts[-2]}/{tail_name}"
    else:
        name = tail_name
    if not _is_safe_npm_package_name(name):
        return None
    filename = parts[separator + 1]
    basename = name.rsplit("/", 1)[-1]
    prefix = f"{basename}-"
    if not filename.startswith(prefix) or not filename.endswith(".tgz"):
        return None
    version = filename[len(prefix) : -4]
    if _NPM_SEMVER_RE.fullmatch(version) is None:
        return None
    return name, version


def _npm_alias_target_name(specifier: str) -> str | None:
    value = specifier.removeprefix("npm:").strip()
    if value.startswith("@"):
        slash = value.find("/")
        if slash <= 1:
            return None
        version_marker = value.find("@", slash)
        name = value if version_marker < 0 else value[:version_marker]
    else:
        name = value.split("@", 1)[0]
    return name if _is_safe_npm_package_name(name) else None


def _manifest_names(package: Package) -> set[str]:
    names = {package.normalized_name}
    self_name = package.metadata.get("self_name")
    if isinstance(self_name, str) and self_name.strip():
        names.add(self_name.strip().lower())
    return names


def _merge_hooks(
    left: tuple[ScriptHook, ...], right: tuple[ScriptHook, ...]
) -> tuple[ScriptHook, ...]:
    return tuple(dict.fromkeys((*left, *right)))


def _verify_installed_tree(
    repo_path: Path, entries: list[ScriptAuditEntry]
) -> list[ScriptAuditEntry]:
    observed = _installed_occurrences(repo_path)
    grouped: dict[str, list[ScriptAuditEntry]] = {}
    for entry in entries:
        policy_name = _policy_name(entry.package)
        if policy_name is not None:
            grouped.setdefault(policy_name.lower(), []).append(entry)

    verified_keys: set[str] = set()
    for policy_name, group in grouped.items():
        expected: dict[str, str] = {}
        complete = True
        for entry in group:
            lock_path = entry.package.metadata.get("lock_path")
            version = entry.package.version
            if (
                not isinstance(lock_path, str)
                or "node_modules" not in Path(lock_path).parts
                or not version
            ):
                complete = False
                break
            installed_names = entry.package.metadata.get("installed_names")
            if installed_names != [policy_name]:
                complete = False
                break
            expected[lock_path] = version
        actual = observed.get(policy_name, {})
        if complete and actual == expected:
            verified_keys.update(_audit_key(entry.package) for entry in group)

    verified_entries: list[ScriptAuditEntry] = []
    for entry in entries:
        installed_verified = _audit_key(entry.package) in verified_keys
        verdict = entry.verdict
        reasons = list(entry.reasons)
        if verdict == VERDICT_ALLOW_CANDIDATE and not installed_verified:
            verdict = VERDICT_REVIEW
            reasons.append("installed-tree-unverified")
        verified_entries.append(
            replace(
                entry,
                verdict=verdict,
                reasons=tuple(dict.fromkeys(reasons)),
                installed_tree_verified=installed_verified,
            )
        )
    return verified_entries


def _installed_occurrences(repo_path: Path) -> dict[str, dict[str, str]]:
    node_modules = repo_path / "node_modules"
    if not node_modules.is_dir():
        return {}

    occurrences: dict[str, dict[str, str]] = {}
    with suppress(OSError):
        for directory, child_directories, filenames in os.walk(node_modules, followlinks=False):
            directory_path = Path(directory)
            if "package.json" not in filenames:
                continue
            manifest_path = directory_path / "package.json"
            try:
                relative = manifest_path.relative_to(repo_path)
            except ValueError:
                continue
            parts = relative.parts
            node_indexes = [i for i, part in enumerate(parts) if part == "node_modules"]
            if not node_indexes:
                continue
            tail = parts[node_indexes[-1] + 1 : -1]
            if len(tail) == 1:
                policy_name = tail[0]
            elif len(tail) == 2 and tail[0].startswith("@"):
                policy_name = f"{tail[0]}/{tail[1]}"
            else:
                continue
            if not _is_safe_npm_package_name(policy_name):
                continue
            safe_path = _safe_existing_path(repo_path, manifest_path)
            if safe_path is None:
                continue
            try:
                manifest = json.loads(safe_path.read_text())
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            version = manifest.get("version") if isinstance(manifest, dict) else None
            if not isinstance(version, str) or not version.strip():
                continue
            install_path = "/".join(parts[:-1])
            occurrences.setdefault(policy_name.lower(), {})[install_path] = version.strip()
            # Package contents are irrelevant here; only a nested dependency
            # tree can contain another installed occurrence.
            child_directories[:] = [child for child in child_directories if child == "node_modules"]
    return occurrences


def _is_safe_npm_package_name(name: str) -> bool:
    if not isinstance(name, str) or not name or len(name) > 214:
        return False
    if name.startswith("@"):
        parts = name[1:].split("/")
        return len(parts) == 2 and all(_SAFE_NPM_SEGMENT_RE.fullmatch(part) for part in parts)
    return "/" not in name and _SAFE_NPM_SEGMENT_RE.fullmatch(name) is not None


def _group_comment(entries: list[ScriptAuditEntry]) -> str:
    versions = sorted({entry.package.version or "unknown" for entry in entries})
    reasons = tuple(dict.fromkeys(reason for entry in entries for reason in entry.reasons))
    return _single_line(
        f"audited versions: {', '.join(versions)}; reasons: {_comment_text(reasons)}"
    )


def _comment_text(values: tuple[str, ...] | list[str]) -> str:
    return ", ".join(_single_line(value) for value in values)


def _single_line(value: object) -> str:
    text = "".join(char if char.isprintable() else " " for char in str(value))
    return " ".join(text.split())[:500]


def _truncate(command: str) -> str:
    flattened = _single_line(command)
    if len(flattened) <= _MAX_COMMAND_CHARS:
        return flattened
    return flattened[: _MAX_COMMAND_CHARS - 3] + "..."


def _malware_reason(finding: Finding) -> str:
    for signal in finding.signals:
        if signal.advisory_key:
            return f"feed:{signal.advisory_key}"
    return "feed:malware"
