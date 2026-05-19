from __future__ import annotations

import json

from click.testing import CliRunner

from ca9.cli import main
from ca9.inventory import build_inventory
from ca9.readers.fyn_lock import read_fyn_lock

FYN_LOCK = """
version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "pytest", marker = "python_version >= '3.10'" }]

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]
wheels = [
  { url = "https://files.pythonhosted.org/requests.whl", hash = "sha256:abc", size = 42, upload-time = "2024-01-01T00:00:00Z" },
]

[[package]]
name = "urllib3"
version = "2.2.0"
source = { registry = "https://pypi.org/simple" }
"""


def test_fyn_lock_inventory_includes_packages_edges_and_artifacts(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(FYN_LOCK)

    inventory = read_fyn_lock(repo)

    packages = {package.name: package for package in inventory.packages}
    assert packages["demo"].dependency_kind == "project"
    assert packages["requests"].dependency_kind == "direct"
    assert packages["pytest"].dependency_kind == "direct"
    assert packages["urllib3"].dependency_kind == "transitive"
    assert packages["requests"].artifacts[0].hash == "sha256:abc"

    pytest_edge = next(edge for edge in inventory.dependency_edges if edge.child_name == "pytest")
    assert pytest_edge.dependency_kind == "direct"
    assert pytest_edge.groups == ("dev",)
    assert pytest_edge.marker == "python_version >= '3.10'"

    urllib3_edge = next(edge for edge in inventory.dependency_edges if edge.child_name == "urllib3")
    assert urllib3_edge.dependency_kind == "transitive"
    assert urllib3_edge.parent_name == "requests"


def test_build_inventory_falls_back_to_declared_dependencies(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n")

    inventory = build_inventory(repo)

    assert inventory.summary()["packages"] == 1
    assert inventory.packages[0].name == "requests"
    assert inventory.packages[0].version == "2.31.0"
    assert inventory.source_inputs[0].source == "ca9 native manifest readers"


def test_inventory_cli_outputs_json_for_fyn_lock(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(FYN_LOCK)

    runner = CliRunner()
    result = runner.invoke(main, ["inventory", "--repo", str(repo), "-f", "json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "ca9.inventory.v1"
    assert data["summary"]["packages"] == 4
    assert data["summary"]["dependency_edges"] == 3
    assert data["summary"]["dependency_kinds"]["direct"] == 2
    assert data["source_inputs"][0]["source"] == "fyn.lock"
    assert any(package["name"] == "requests" for package in data["packages"])
