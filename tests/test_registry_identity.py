from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from ca9.analyzers.supply_chain import SupplyChainPolicy, _registry_matches
from ca9.cli import main
from ca9.core.models import Finding, Inventory
from ca9.readers.package_lock import read_package_lock
from ca9.supply_chain import build_supply_chain_report

ARTIFACTORY = "https://artifactory.acme.example/api/npm"


def _write_lock(repo, packages):
    repo.mkdir(parents=True, exist_ok=True)
    root = {
        "name": "app",
        "dependencies": {path.removeprefix("node_modules/"): "1.0.0" for path in packages},
    }
    (repo / "package-lock.json").write_text(
        json.dumps({"name": "app", "lockfileVersion": 3, "packages": {"": root, **packages}})
    )


@pytest.mark.parametrize(
    ("resolved", "registry"),
    [
        (f"{ARTIFACTORY}/npm-remote/left-pad/-/left-pad-1.3.0.tgz", f"{ARTIFACTORY}/npm-remote"),
        (f"{ARTIFACTORY}/npm-internal/@acme/util/-/util-1.0.0.tgz", f"{ARTIFACTORY}/npm-internal"),
        (
            f"{ARTIFACTORY}/npm-internal/@acme%2futil/-/util-1.0.0.tgz",
            f"{ARTIFACTORY}/npm-internal",
        ),
        ("https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", "https://registry.npmjs.org"),
        ("https://REGISTRY.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "https://registry.npmjs.org"),
        ("https://codeload.example/owner/repo/tar.gz/abc", "https://codeload.example"),
    ],
)
def test_package_lock_keeps_registry_base_path(tmp_path, resolved, registry):
    _write_lock(
        tmp_path,
        {"node_modules/pkg": {"version": "1.0.0", "resolved": resolved, "integrity": "sha512-x"}},
    )

    package = next(p for p in read_package_lock(tmp_path).packages if p.name == "pkg")

    assert package.source_registry == registry


@pytest.mark.parametrize(
    ("registry", "candidate", "expected"),
    [
        (f"{ARTIFACTORY}/npm-remote", f"{ARTIFACTORY}/npm-remote", True),
        (f"{ARTIFACTORY}/npm-remote", f"{ARTIFACTORY}/npm-remote/", True),
        (f"{ARTIFACTORY}/npm-remote", ARTIFACTORY, True),
        (f"{ARTIFACTORY}/npm-remote", "https://artifactory.acme.example", True),
        (f"{ARTIFACTORY}/npm-internal-evil", f"{ARTIFACTORY}/npm-internal", False),
        (f"{ARTIFACTORY}/npm-internal", f"{ARTIFACTORY}/npm-remote", False),
        ("https://artifactory.acme.example", f"{ARTIFACTORY}/npm-remote", False),
        ("https://pypi.org/simple", "https://pypi.org/simple/", True),
    ],
)
def test_configured_indexes_match_by_url_prefix(registry, candidate, expected):
    assert _registry_matches(registry, (candidate,)) is expected


def test_vet_accepts_packages_from_configured_artifactory_repositories(tmp_path):
    _write_lock(
        tmp_path,
        {
            "node_modules/left-pad": {
                "version": "1.0.0",
                "resolved": f"{ARTIFACTORY}/npm-remote/left-pad/-/left-pad-1.0.0.tgz",
                "integrity": "sha512-x",
            },
            "node_modules/@acme/util": {
                "version": "1.0.0",
                "resolved": f"{ARTIFACTORY}/npm-internal/@acme/util/-/util-1.0.0.tgz",
                "integrity": "sha512-y",
            },
        },
    )

    result = CliRunner().invoke(
        main,
        [
            "vet",
            "--repo",
            str(tmp_path),
            "-f",
            "json",
            "--trusted-index",
            f"{ARTIFACTORY}/npm-remote",
            "--private-index",
            f"{ARTIFACTORY}/npm-internal",
            "--internal-package",
            "@acme/*",
        ],
    )

    assert result.exit_code == 0, result.output
    signals = {finding["signal_type"] for finding in json.loads(result.output)["findings"]}
    assert not signals & {"untrusted_registry", "dependency_confusion"}


def test_internal_package_from_the_public_repository_on_the_same_host_is_still_confusion(
    tmp_path,
):
    _write_lock(
        tmp_path,
        {
            "node_modules/@acme/util": {
                "version": "1.0.0",
                "resolved": f"{ARTIFACTORY}/npm-remote/@acme/util/-/util-1.0.0.tgz",
                "integrity": "sha512-y",
            },
        },
    )
    policy = SupplyChainPolicy(
        trusted_indexes=(f"{ARTIFACTORY}/npm-remote",),
        private_indexes=(f"{ARTIFACTORY}/npm-internal",),
        internal_package_patterns=("@acme/*",),
    )

    report = build_supply_chain_report(read_package_lock(tmp_path), policy=policy)

    assert [finding.signal_type for finding in report.findings] == ["dependency_confusion"]


def test_report_findings_sort_by_severity_rank():
    findings = [
        Finding(title=severity, signal_type="x", package_key=f"pypi:{severity}", severity=severity)
        for severity in ("low", "medium", "critical", "high")
    ]

    report = build_supply_chain_report(Inventory(repo_path="."), extra_findings=findings)

    assert [finding.severity for finding in report.findings] == [
        "critical",
        "high",
        "medium",
        "low",
    ]
