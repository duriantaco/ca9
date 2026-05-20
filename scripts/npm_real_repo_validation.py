from __future__ import annotations

import argparse
import json
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ca9.inventory import build_inventory

SCHEMA_VERSION = "ca9.npm-real-repo-validation.v1"


CASES = (
    {
        "name": "axios",
        "repo": "axios/axios",
        "commit": "979918445324cb9150134d068ba06f8cc9723346",
        "path": "package-lock.json",
    },
    {
        "name": "mocha",
        "repo": "mochajs/mocha",
        "commit": "6695fba397a6d1ca2d7cd4de86d9dda2d3fba342",
        "path": "package-lock.json",
    },
    {
        "name": "npm-cli",
        "repo": "npm/cli",
        "commit": "c97b39b1e3436cd20a67ab5f4012a5f395c538b9",
        "path": "package-lock.json",
    },
    {
        "name": "socket.io",
        "repo": "socketio/socket.io",
        "commit": "5257ef9adfa02a4e8f8eaa5f6810565f979ccc48",
        "path": "package-lock.json",
    },
)


@dataclass(frozen=True)
class Baseline:
    package_keys: set[str]
    edge_keys: set[tuple[str | None, str, str]]
    artifact_count: int
    direct_count: int
    lockfile_version: int | None


def run_validation(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="ca9-npm-real-repo-") as tmp:
        root = Path(tmp)
        for case in CASES:
            results.append(_run_case(case, root / case["name"], output_dir))

    passed = sum(1 for result in results if result["status"] == "pass")
    return {
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "cases": len(results),
            "passed": passed,
            "failed": len(results) - passed,
        },
        "cases": results,
    }


def render_table(report: dict[str, Any]) -> str:
    lines = [
        "ca9 npm real-repo validation",
        f"Cases: {report['summary']['cases']} | Passed: {report['summary']['passed']} | Failed: {report['summary']['failed']}",
        "",
        "Case | Status | Lockfile | Packages | Edges | Direct | Artifacts",
        "-- | -- | -- | --: | --: | --: | --:",
    ]
    for case in report["cases"]:
        lines.append(
            " | ".join(
                [
                    case["name"],
                    case["status"],
                    str(case["lockfile_version"]),
                    str(case["packages"]),
                    str(case["edges"]),
                    str(case["direct"]),
                    str(case["artifacts"]),
                ]
            )
        )
    return "\n".join(lines)


def _run_case(case: dict[str, str], repo_path: Path, output_dir: Path) -> dict[str, Any]:
    repo_path.mkdir(parents=True, exist_ok=True)
    lock_path = repo_path / "package-lock.json"
    lock_data = _download_lockfile(case)
    lock_path.write_text(json.dumps(lock_data, indent=2))

    baseline = _baseline_from_lock(lock_data)
    inventory = build_inventory(repo_path)
    ca9_package_keys = {package.key for package in inventory.packages}
    ca9_edge_keys = {
        (edge.parent_key, edge.child_key, ",".join(edge.groups))
        for edge in inventory.dependency_edges
    }
    ca9_artifact_count = sum(len(package.artifacts) for package in inventory.packages)
    ca9_direct_count = sum(
        1 for package in inventory.packages if package.dependency_kind == "direct"
    )

    missing_packages = sorted(baseline.package_keys - ca9_package_keys)
    extra_packages = sorted(ca9_package_keys - baseline.package_keys)
    missing_edges = sorted(baseline.edge_keys - ca9_edge_keys, key=str)
    extra_edges = sorted(ca9_edge_keys - baseline.edge_keys, key=str)
    errors = []
    if missing_packages or extra_packages:
        errors.append("package_key_mismatch")
    if missing_edges or extra_edges:
        errors.append("dependency_edge_mismatch")
    if ca9_artifact_count != baseline.artifact_count:
        errors.append("artifact_count_mismatch")
    if ca9_direct_count != baseline.direct_count:
        errors.append("direct_count_mismatch")

    result = {
        "name": case["name"],
        "repo": case["repo"],
        "commit": case["commit"],
        "source_url": _raw_url(case),
        "status": "fail" if errors else "pass",
        "errors": errors,
        "lockfile_version": baseline.lockfile_version,
        "packages": len(ca9_package_keys),
        "expected_packages": len(baseline.package_keys),
        "edges": len(ca9_edge_keys),
        "expected_edges": len(baseline.edge_keys),
        "direct": ca9_direct_count,
        "expected_direct": baseline.direct_count,
        "artifacts": ca9_artifact_count,
        "expected_artifacts": baseline.artifact_count,
        "missing_packages": missing_packages[:20],
        "extra_packages": extra_packages[:20],
        "missing_edges": [list(edge) for edge in missing_edges[:20]],
        "extra_edges": [list(edge) for edge in extra_edges[:20]],
    }
    (output_dir / f"{case['name'].replace('/', '-')}.json").write_text(json.dumps(result, indent=2))
    return result


def _download_lockfile(case: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(_raw_url(case), headers={"User-Agent": "ca9-validation"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.loads(response.read().decode())
    if not isinstance(data, dict):
        raise ValueError(f"{case['name']} package-lock.json did not parse to an object")
    return data


def _raw_url(case: dict[str, str]) -> str:
    return f"https://raw.githubusercontent.com/{case['repo']}/{case['commit']}/{case['path']}"


def _baseline_from_lock(lock_data: dict[str, Any]) -> Baseline:
    raw_packages = lock_data.get("packages", {})
    if not isinstance(raw_packages, dict):
        raise ValueError("package-lock.json packages object is required for npm validation")
    package_paths = {path for path in raw_packages if path}
    package_keys = _baseline_package_keys(raw_packages)
    edge_keys = _baseline_edge_keys(raw_packages, package_paths)
    root = raw_packages.get("", {})
    root_dependencies = _root_dependency_paths(root, raw_packages, package_paths)
    return Baseline(
        package_keys=package_keys,
        edge_keys=edge_keys,
        artifact_count=sum(
            1
            for path, entry in raw_packages.items()
            if path
            and isinstance(entry, dict)
            and _has_package_identity(path, entry)
            and isinstance(entry.get("resolved"), str)
        ),
        direct_count=len(root_dependencies),
        lockfile_version=lock_data.get("lockfileVersion")
        if isinstance(lock_data.get("lockfileVersion"), int)
        else None,
    )


def _baseline_package_keys(raw_packages: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for path, entry in raw_packages.items():
        if not isinstance(entry, dict):
            continue
        name = _entry_name(path, entry)
        version = _string_or_none(entry.get("version"))
        if name and version:
            keys.add(_npm_key(name, version))
    return keys


def _baseline_edge_keys(
    raw_packages: dict[str, Any],
    package_paths: set[str],
) -> set[tuple[str | None, str, str]]:
    edges: set[tuple[str | None, str, str]] = set()
    for parent_path, entry in raw_packages.items():
        if not isinstance(entry, dict):
            continue
        parent_name = _entry_name(parent_path, entry)
        parent_version = _string_or_none(entry.get("version"))
        parent_key = (
            _npm_key(parent_name, parent_version) if parent_name and parent_version else None
        )
        for dependency in _iter_dependencies(entry):
            child_path = _resolve_child_path(parent_path, dependency["name"], package_paths)
            child_entry = raw_packages.get(child_path, {}) if child_path else {}
            child_version = (
                _string_or_none(child_entry.get("version"))
                if isinstance(child_entry, dict)
                else None
            )
            group = "" if dependency["group"] == "runtime" else dependency["group"]
            edges.add((parent_key, _npm_key(dependency["name"], child_version), group))
    return edges


def _root_dependency_paths(
    root: object,
    raw_packages: dict[str, Any],
    package_paths: set[str],
) -> set[str]:
    if not isinstance(root, dict):
        return set()
    paths: set[str] = set()
    for dependency in _iter_dependencies(root):
        child_path = _resolve_child_path("", dependency["name"], package_paths)
        child_entry = raw_packages.get(child_path, {}) if child_path else {}
        if (
            child_path
            and isinstance(child_entry, dict)
            and _has_package_identity(child_path, child_entry)
        ):
            paths.add(child_path)
    return paths


def _iter_dependencies(entry: dict[str, Any]) -> list[dict[str, str]]:
    dependencies = []
    for group, field in (
        ("runtime", "dependencies"),
        ("dev", "devDependencies"),
        ("optional", "optionalDependencies"),
        ("peer", "peerDependencies"),
    ):
        raw = entry.get(field, {})
        if isinstance(raw, dict):
            dependencies.extend(
                {"name": name.strip(), "group": group}
                for name in sorted(raw)
                if isinstance(name, str) and name.strip()
            )
    return dependencies


def _resolve_child_path(parent_path: str, name: str, package_paths: set[str]) -> str | None:
    for candidate in _node_modules_candidates(parent_path, name):
        if candidate in package_paths:
            return candidate
    return None


def _node_modules_candidates(parent_path: str, name: str) -> list[str]:
    if not parent_path:
        return [f"node_modules/{name}"]

    candidates = [f"{parent_path}/node_modules/{name}"]
    current = parent_path
    while "/node_modules/" in current:
        current = current.rsplit("/node_modules/", 1)[0]
        candidates.append(f"{current}/node_modules/{name}")
    candidates.append(f"node_modules/{name}")
    return candidates


def _entry_name(path: str, entry: dict[str, Any]) -> str | None:
    name = _string_or_none(entry.get("name"))
    if name:
        return name
    if not path:
        return None
    segment = path.rsplit("node_modules/", 1)[-1]
    parts = segment.split("/")
    if parts and parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts and parts[0] else None


def _has_package_identity(path: str, entry: dict[str, Any]) -> bool:
    return (
        _entry_name(path, entry) is not None and _string_or_none(entry.get("version")) is not None
    )


def _npm_key(name: str, version: str | None = None) -> str:
    base = f"npm:{name.strip().lower()}"
    if version:
        return f"{base}@{version}"
    return base


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate npm package-lock inventory against pinned real repos."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/ca9-npm-real-repo-validation"),
        help="Directory for per-case validation JSON artifacts.",
    )
    parser.add_argument("-f", "--format", choices=("table", "json"), default="table")
    args = parser.parse_args()

    report = run_validation(args.output_dir)
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_table(report))
    if report["summary"]["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
