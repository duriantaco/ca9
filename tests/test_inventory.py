from __future__ import annotations

import json

from click.testing import CliRunner

from ca9.cli import main
from ca9.inventory import build_inventory
from ca9.readers.fyn_lock import read_fyn_lock
from ca9.readers.npm_lock import read_npm_lock

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


def test_build_inventory_reads_npm_package_lock(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "webapp",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "webapp",
                        "version": "1.0.0",
                        "dependencies": {"node-ipc": "^9.1.0"},
                    },
                    "node_modules/node-ipc": {
                        "version": "9.1.6",
                        "resolved": "https://registry.npmjs.org/node-ipc/-/node-ipc-9.1.6.tgz",
                        "integrity": "sha512-test",
                    },
                },
            }
        )
    )

    inventory = build_inventory(repo)

    packages = {package.name: package for package in inventory.packages}
    assert inventory.metadata["reader"] == "npm lockfile"
    assert packages["webapp"].ecosystem == "npm"
    assert packages["webapp"].dependency_kind == "project"
    assert packages["node-ipc"].version == "9.1.6"
    assert packages["node-ipc"].dependency_kind == "direct"
    assert packages["node-ipc"].source_registry == "https://registry.npmjs.org"
    assert packages["node-ipc"].artifacts[0].hash == "sha512-test"


def test_build_inventory_merges_python_and_npm_lockfiles(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(FYN_LOCK)
    (repo / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "webapp",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "webapp",
                        "version": "1.0.0",
                        "dependencies": {"node-ipc": "^9.1.0"},
                    },
                    "node_modules/node-ipc": {
                        "version": "9.1.6",
                        "resolved": "https://registry.npmjs.org/node-ipc/-/node-ipc-9.1.6.tgz",
                        "integrity": "sha512-test",
                    },
                },
            }
        )
    )

    inventory = build_inventory(repo)

    package_keys = {package.key for package in inventory.packages}
    assert "pypi:requests@2.31.0" in package_keys
    assert "npm:node-ipc@9.1.6" in package_keys
    assert inventory.metadata["reader"] == "merged inventory"
    assert inventory.metadata["readers"] == ["fyn.lock", "npm lockfile"]


def test_npm_lock_inventory_resolves_scoped_transitive_edges(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "webapp",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "webapp",
                        "version": "1.0.0",
                        "dependencies": {"@tanstack/react-router": "1.120.13"},
                    },
                    "node_modules/@tanstack/react-router": {
                        "version": "1.120.13",
                        "resolved": (
                            "https://registry.npmjs.org/@tanstack/react-router/-/"
                            "react-router-1.120.13.tgz"
                        ),
                        "dependencies": {"@tanstack/router-core": "1.120.13"},
                    },
                    "node_modules/@tanstack/router-core": {
                        "version": "1.120.13",
                        "resolved": (
                            "https://registry.npmjs.org/@tanstack/router-core/-/"
                            "router-core-1.120.13.tgz"
                        ),
                    },
                },
            }
        )
    )

    inventory = read_npm_lock(repo)

    packages = {package.name: package for package in inventory.packages}
    assert packages["@tanstack/react-router"].dependency_kind == "direct"
    assert packages["@tanstack/router-core"].dependency_kind == "transitive"
    edge = next(
        edge for edge in inventory.dependency_edges if edge.parent_name == "@tanstack/react-router"
    )
    assert edge.child_name == "@tanstack/router-core"
    assert edge.child_version == "1.120.13"


def test_npm_lock_hydrates_rootless_root_package_entry(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "webapp",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "dependencies": {"node-ipc": "^9.1.0"},
                    },
                    "node_modules/node-ipc": {
                        "version": "9.1.6",
                        "resolved": "https://registry.npmjs.org/node-ipc/-/node-ipc-9.1.6.tgz",
                        "integrity": "sha512-test",
                    },
                },
            }
        )
    )

    inventory = read_npm_lock(repo)

    packages = {package.name: package for package in inventory.packages}
    assert packages["webapp"].dependency_kind == "project"
    assert packages["webapp"].version == "1.0.0"
    assert packages["node-ipc"].dependency_kind == "direct"


def test_npm_v1_lock_uses_requires_for_transitive_edges(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "webapp",
                "version": "1.0.0",
                "lockfileVersion": 1,
                "dependencies": {
                    "foo": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                        "integrity": "sha512-foo",
                        "requires": {"bar": "^2.0.0"},
                    },
                    "bar": {
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/bar/-/bar-2.0.0.tgz",
                        "integrity": "sha512-bar",
                    },
                },
            }
        )
    )

    inventory = read_npm_lock(repo)

    packages = {package.name: package for package in inventory.packages}
    assert packages["foo"].dependency_kind == "direct"
    assert packages["bar"].dependency_kind == "transitive"
    root_edges = {
        edge.child_name for edge in inventory.dependency_edges if edge.parent_name == "webapp"
    }
    assert root_edges == {"foo"}
    foo_edge = next(edge for edge in inventory.dependency_edges if edge.parent_name == "foo")
    assert foo_edge.child_name == "bar"
    assert foo_edge.dependency_kind == "transitive"
