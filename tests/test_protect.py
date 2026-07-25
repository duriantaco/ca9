from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from ca9.cli import main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import MalwarePolicy, PackagePolicy, PolicyException
from ca9.protect import (
    build_protect_report,
    protect_report_to_markdown,
    protect_report_to_sarif,
)


def test_protect_reports_supported_npm_and_pip_workflows(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_package_lock(repo)
    (repo / "requirements.txt").write_text("Requests==2.31.0\n")

    report = build_protect_report(
        repo,
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        scan_workflows=False,
        feed_cache_dir=tmp_path / "cache" / "feed",
    )

    managers = {manager.manager: manager for manager in report.managers}
    assert report.status == "pass"
    assert report.exit_code == 0
    assert managers["npm"].coverage == "supported"
    assert managers["npm"].runtime_commands == ("ca9 run -- npm ci",)
    assert managers["pip"].coverage == "supported"
    assert managers["pip"].runtime_commands == ("ca9 run -- pip install -r requirements.txt",)
    assert report.to_dict()["schema_version"] == "ca9.protect.v1"


def test_protect_blocks_manifest_without_enforceable_lock(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "demo", "dependencies": {"left-pad": "1.3.0"}})
    )

    report = build_protect_report(
        repo,
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        scan_workflows=False,
        feed_cache_dir=tmp_path / "cache" / "feed",
    )

    check = next(item for item in report.checks if item.check_id == "ca9.protect.npm")
    assert report.status == "block"
    assert report.exit_code == 1
    assert check.status == "block"
    assert "without a lockfile" in check.detail


def test_protect_blocks_unsafe_pip_requirement_include(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("-r ../outside.txt\n")
    (tmp_path / "outside.txt").write_text("requests==2.31.0\n")

    report = build_protect_report(
        repo,
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        scan_workflows=False,
        feed_cache_dir=tmp_path / "cache" / "feed",
    )

    manager = next(item for item in report.managers if item.manager == "pip")
    check = next(item for item in report.checks if item.check_id == "ca9.protect.pip")
    assert manager.coverage == "partial"
    assert check.status == "block"
    assert "escapes the repository" in check.detail


def test_protect_scans_workflows_and_emits_sarif(tmp_path):
    repo = tmp_path / "repo"
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (repo / "requirements.txt").write_text("requests==2.31.0\n")
    (workflow_dir / "danger.yml").write_text(
        """
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    )

    report = build_protect_report(
        repo,
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        feed_cache_dir=tmp_path / "cache" / "feed",
    )
    sarif = json.loads(protect_report_to_sarif(report))

    assert report.status == "block"
    workflow_check = next(
        item for item in report.checks if item.check_id == "ca9.protect.github_actions"
    )
    assert workflow_check.status == "block"
    results = sarif["runs"][0]["results"]
    assert any(
        result["ruleId"] == "ca9.github_actions_pull_request_target_checkout"
        and result["level"] == "error"
        for result in results
    )
    assert any(
        result.get("locations", [{}])[0]
        .get("physicalLocation", {})
        .get("artifactLocation", {})
        .get("uri")
        == ".github/workflows/danger.yml"
        for result in results
    )


def test_protect_marks_unsupported_manager_without_failing(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0.0"\ndependencies = ["requests==2.31.0"]\n'
    )
    (repo / "uv.lock").write_text('version = 1\nrevision = 1\nrequires-python = ">=3.12"\n')

    report = build_protect_report(
        repo,
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        scan_workflows=False,
        feed_cache_dir=tmp_path / "cache" / "feed",
    )

    uv = next(item for item in report.managers if item.manager == "uv")
    assert report.status == "warn"
    assert report.exit_code == 0
    assert uv.coverage == "unsupported"


def test_protect_blocks_local_feed_malware_match(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("badlib==1.0.0\n")
    cache_dir = tmp_path / "cache" / "feed"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_dir)

    report = build_protect_report(
        repo,
        PackagePolicy(),
        scan_workflows=False,
        feed_cache_dir=cache_dir,
    )

    assert report.status == "block"
    assert any(
        decision.policy_id == "ca9.malware" and decision.action == "block"
        for decision in report.supply_chain.decisions
    )


def test_protect_warns_about_expired_policy_exception(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n")
    policy = PackagePolicy(
        malware=MalwarePolicy(enabled=False),
        exceptions=(
            PolicyException(
                policy_id="ca9.package_age",
                package="requests",
                owner="security",
                reason="Old rollout",
                expires="2000-01-01",
            ),
        ),
    )

    report = build_protect_report(
        repo,
        policy,
        scan_workflows=False,
        feed_cache_dir=tmp_path / "cache" / "feed",
    )

    check = next(item for item in report.checks if item.check_id == "ca9.protect.policy_exceptions")
    assert report.status == "warn"
    assert check.status == "warn"
    assert "expired" in check.detail


def test_protect_cli_writes_json_and_preserves_blocking_exit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "demo"}\n')
    policy_path = repo / "ca9.toml"
    policy_path.write_text("[malware]\nenabled = false\n")
    output = tmp_path / "protect.json"

    result = CliRunner().invoke(
        main,
        [
            "protect",
            "--repo",
            str(repo),
            "--policy",
            str(policy_path),
            "--no-scan-workflows",
            "-f",
            "json",
            "-o",
            str(output),
        ],
    )

    assert result.exit_code == 1
    assert result.output == ""
    data = json.loads(output.read_text())
    assert data["summary"]["status"] == "block"
    assert data["summary"]["blocking_checks"] == 1


def test_protect_markdown_contains_actionable_enforcement_command(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n")

    report = build_protect_report(
        repo,
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        scan_workflows=False,
        feed_cache_dir=tmp_path / "cache" / "feed",
    )
    markdown = protect_report_to_markdown(report)

    assert "# ca9 protect report" in markdown
    assert "ca9 run -- pip install -r requirements.txt" in markdown


def _write_package_lock(repo):
    lock = {
        "name": "demo-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "demo-app",
                "version": "1.0.0",
                "dependencies": {"left-pad": "1.3.0"},
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-test",
            },
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(lock))


def _write_feed_bundle(tmp_path):
    expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-07-25T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "pypi-malware": {
                "packages": [
                    {
                        "name": "badlib",
                        "version": "1.0.0",
                        "id": "MAL-PYPI-PROTECT",
                    }
                ]
            },
            "npm-malware": {"packages": []},
            "pypi-releases": {"packages": {}},
            "npm-releases": {"packages": {}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    return path
