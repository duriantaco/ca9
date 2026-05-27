from __future__ import annotations

import argparse
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from ca9.analyzers.supply_chain import findings_from_malware_advisories
from ca9.core.models import package_key
from ca9.inventory import build_inventory
from ca9.models import Vulnerability

SCHEMA_VERSION = "ca9.incident-replay.v1"
FIXTURE_SCHEMA_VERSION = "ca9.incident.v1"


def load_incidents(fixtures_dir: Path) -> list[dict[str, Any]]:
    incidents: list[dict[str, Any]] = []
    for path in sorted(fixtures_dir.glob("*.json")):
        with path.open() as f:
            incident = json.load(f)
        if incident.get("schema_version") != FIXTURE_SCHEMA_VERSION:
            raise ValueError(f"{path} has unsupported schema_version")
        incident["_fixture_path"] = str(path)
        incidents.append(incident)
    return incidents


def replay_incidents(fixtures_dir: Path) -> dict[str, Any]:
    incidents = load_incidents(fixtures_dir)
    results = []
    with tempfile.TemporaryDirectory(prefix="ca9-incident-replay-") as tmp:
        root = Path(tmp)
        for incident in incidents:
            results.append(replay_incident(incident, root / incident["id"]))

    summary = Counter(result["overall_status"] for result in results)
    expectation_failures = _expectation_failures(results)
    return {
        "schema_version": SCHEMA_VERSION,
        "fixtures_dir": str(fixtures_dir),
        "summary": {
            "incidents": len(results),
            "covered": summary["covered"],
            "partial": summary["partial"],
            "gap": summary["gap"],
            "expectation_failures": len(expectation_failures),
        },
        "incidents": results,
        "expectation_failures": expectation_failures,
    }


def replay_incident(incident: dict[str, Any], repo_path: Path) -> dict[str, Any]:
    repo_path.mkdir(parents=True, exist_ok=True)
    _write_repo_fixture(incident, repo_path)

    checks = [
        _inventory_check(incident, repo_path),
        _malware_advisory_check(incident),
        _workflow_check(incident, repo_path),
    ]
    overall_status = _overall_status(checks)
    expected_current = incident.get("expected_current", {})
    return {
        "id": incident["id"],
        "title": incident["title"],
        "incident_date": incident.get("incident_date", ""),
        "source_urls": incident.get("source_urls", []),
        "threat_classes": incident.get("threat_classes", []),
        "overall_status": overall_status,
        "expected_current": expected_current,
        "checks": checks,
        "known_gaps": incident.get("known_gaps", []),
    }


def render_table(report: dict[str, Any]) -> str:
    rows = [
        "Incident replay results",
        f"Fixtures: {report['fixtures_dir']}",
        (
            "Summary: "
            f"covered={report['summary']['covered']} "
            f"partial={report['summary']['partial']} "
            f"gap={report['summary']['gap']}"
        ),
        "",
        "ID | Status | Inventory | Malware advisory | Workflow",
        "-- | -- | -- | -- | --",
    ]
    for incident in report["incidents"]:
        checks = {check["name"]: check["status"] for check in incident["checks"]}
        rows.append(
            " | ".join(
                [
                    incident["id"],
                    incident["overall_status"],
                    checks.get("inventory", "not_applicable"),
                    checks.get("malware_advisory", "not_applicable"),
                    checks.get("workflow", "not_applicable"),
                ]
            )
        )
    return "\n".join(rows)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Incident Replay Coverage",
        "",
        "Generated from local incident fixtures. `gap` means ca9 does not currently cover that",
        "attack surface; it is not a passing detection claim.",
        "",
        "| Incident | Status | Inventory | Malware advisory | Workflow |",
        "| --- | --- | --- | --- | --- |",
    ]
    for incident in report["incidents"]:
        checks = {check["name"]: check["status"] for check in incident["checks"]}
        lines.append(
            "| "
            + " | ".join(
                [
                    incident["id"],
                    incident["overall_status"],
                    checks.get("inventory", "not_applicable"),
                    checks.get("malware_advisory", "not_applicable"),
                    checks.get("workflow", "not_applicable"),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Gaps", ""])
    for incident in report["incidents"]:
        if not incident["known_gaps"]:
            continue
        lines.append(f"### {incident['id']}")
        for gap in incident["known_gaps"]:
            lines.append(f"- {gap}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def assert_expectations(report: dict[str, Any]) -> None:
    if not report["expectation_failures"]:
        return
    failures = ", ".join(
        (
            f"{failure['incident_id']} {failure['field']} "
            f"expected {failure['expected']} got {failure['actual']}"
        )
        for failure in report["expectation_failures"]
    )
    raise AssertionError(f"incident replay expectations changed: {failures}")


def _expectation_failures(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    for result in results:
        expected = result.get("expected_current", {})
        expected_overall = expected.get("overall_status")
        if expected_overall is not None and result["overall_status"] != expected_overall:
            failures.append(
                {
                    "incident_id": result["id"],
                    "field": "overall_status",
                    "expected": expected_overall,
                    "actual": result["overall_status"],
                }
            )

        checks = {check["name"]: check for check in result["checks"]}
        for check_name in ("inventory", "malware_advisory", "workflow"):
            expected_status = expected.get(check_name)
            if expected_status is None:
                continue
            actual_status = checks.get(check_name, {}).get("status", "not_applicable")
            if actual_status != expected_status:
                failures.append(
                    {
                        "incident_id": result["id"],
                        "field": check_name,
                        "expected": expected_status,
                        "actual": actual_status,
                    }
                )
    return failures


def _write_repo_fixture(incident: dict[str, Any], repo_path: Path) -> None:
    packages = incident.get("packages", [])
    pypi_packages = [package for package in packages if package["ecosystem"] == "pypi"]
    npm_packages = [package for package in packages if package["ecosystem"] == "npm"]

    if pypi_packages:
        (repo_path / "fyn.lock").write_text(_render_fyn_lock(pypi_packages))
    if npm_packages:
        (repo_path / "package.json").write_text(_render_package_json(npm_packages))
        (repo_path / "package-lock.json").write_text(_render_package_lock(npm_packages))
    if incident.get("workflow_patterns"):
        workflow_dir = repo_path / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)
        for pattern in incident["workflow_patterns"]:
            workflow_name = pattern.get("workflow", "replay.yml")
            (workflow_dir / workflow_name).write_text(pattern["snippet"])


def _render_fyn_lock(packages: list[dict[str, Any]]) -> str:
    dependencies = ", ".join(f'{{ name = "{package["name"]}" }}' for package in packages)
    lines = [
        "version = 1",
        "",
        "[[package]]",
        'name = "incident-replay"',
        'version = "0.0.0"',
        'source = { editable = "." }',
        f"dependencies = [{dependencies}]",
        "",
    ]
    for package in packages:
        lines.extend(
            [
                "[[package]]",
                f'name = "{package["name"]}"',
                f'version = "{package["version"]}"',
                'source = { registry = "https://pypi.org/simple" }',
                "",
            ]
        )
    return "\n".join(lines)


def _render_package_json(packages: list[dict[str, Any]]) -> str:
    dependencies = {package["name"]: package["version"] for package in packages}
    return json.dumps(
        {"name": "ca9-incident-replay", "private": True, "dependencies": dependencies},
        indent=2,
    )


def _render_package_lock(packages: list[dict[str, Any]]) -> str:
    root_dependencies = {package["name"]: package["version"] for package in packages}
    lock_packages: dict[str, Any] = {
        "": {
            "name": "ca9-incident-replay",
            "dependencies": root_dependencies,
        }
    }
    dependencies: dict[str, Any] = {}
    for package in packages:
        entry = {
            "version": package["version"],
            "resolved": package.get(
                "resolved",
                f"https://registry.npmjs.org/{package['name']}/-/{package['name']}.tgz",
            ),
            "integrity": package.get("integrity", "sha512-incident-replay"),
        }
        if package.get("optional_dependencies"):
            entry["optionalDependencies"] = package["optional_dependencies"]
        lock_packages[f"node_modules/{package['name']}"] = entry
        dependencies[package["name"]] = {
            "version": package["version"],
            "resolved": entry["resolved"],
            "integrity": entry["integrity"],
        }
    return json.dumps(
        {
            "name": "ca9-incident-replay",
            "lockfileVersion": 3,
            "requires": True,
            "packages": lock_packages,
            "dependencies": dependencies,
        },
        indent=2,
    )


def _inventory_check(incident: dict[str, Any], repo_path: Path) -> dict[str, Any]:
    expected_packages = {
        package_key(package["ecosystem"], package["name"], package["version"])
        for package in incident.get("packages", [])
    }
    if not expected_packages:
        return {"name": "inventory", "status": "not_applicable", "details": "no packages"}

    inventory = build_inventory(repo_path)
    actual_packages = {package.key for package in inventory.packages}
    missing = sorted(expected_packages - actual_packages)
    status = "pass" if not missing else "gap"
    return {
        "name": "inventory",
        "status": status,
        "expected_package_keys": sorted(expected_packages),
        "actual_package_keys": sorted(actual_packages),
        "missing_package_keys": missing,
        "warnings": list(inventory.warnings),
    }


def _malware_advisory_check(incident: dict[str, Any]) -> dict[str, Any]:
    advisories = [
        advisory for advisory in incident.get("advisories", []) if advisory.get("malicious", False)
    ]
    if not advisories:
        return {
            "name": "malware_advisory",
            "status": "not_applicable",
            "details": "no malicious advisory fixture",
        }

    vulnerabilities = [
        Vulnerability(
            id=advisory["id"],
            package_name=advisory["package_name"],
            package_version=advisory["package_version"],
            severity=advisory.get("severity", "critical"),
            title=advisory.get("title", advisory["id"]),
            description=advisory.get("description", ""),
            ecosystem=advisory["ecosystem"],
            aliases=tuple(advisory.get("aliases", [])),
            advisory_source=advisory.get("source", ""),
            advisory_url=advisory.get("url", ""),
        )
        for advisory in advisories
    ]
    findings = findings_from_malware_advisories(vulnerabilities)
    expected_keys = {
        package_key(advisory["ecosystem"], advisory["package_name"], advisory["package_version"])
        for advisory in advisories
    }
    detected_keys = {finding.package_key for finding in findings}
    missing = sorted(expected_keys - detected_keys)
    status = "pass" if not missing else "gap"
    return {
        "name": "malware_advisory",
        "status": status,
        "expected_package_keys": sorted(expected_keys),
        "detected_package_keys": sorted(detected_keys),
        "missing_package_keys": missing,
        "advisory_ids": [advisory["id"] for advisory in advisories],
    }


def _workflow_check(incident: dict[str, Any], repo_path: Path) -> dict[str, Any]:
    patterns = incident.get("workflow_patterns", [])
    if not patterns:
        return {"name": "workflow", "status": "not_applicable", "details": "no workflow fixture"}

    workflow_paths = sorted(
        str(path.relative_to(repo_path)) for path in repo_path.glob(".github/workflows/*")
    )
    return {
        "name": "workflow",
        "status": "gap",
        "workflow_paths": workflow_paths,
        "missing_capability": "github_actions_workflow_scanner",
    }


def _overall_status(checks: list[dict[str, Any]]) -> str:
    relevant = [check for check in checks if check["status"] != "not_applicable"]
    if not relevant:
        return "gap"
    if all(check["status"] == "pass" for check in relevant):
        return "covered"
    if any(check["status"] == "pass" for check in relevant):
        return "partial"
    return "gap"


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay real supply-chain incidents against ca9.")
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path("tests/fixtures/incidents"),
        help="Directory containing incident JSON fixtures.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("table", "json", "markdown"),
        default="table",
        help="Output format.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if current replay status differs from fixture expectations.",
    )
    args = parser.parse_args()

    report = replay_incidents(args.fixtures)
    if args.strict:
        assert_expectations(report)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "markdown":
        print(render_markdown(report), end="")
    else:
        print(render_table(report))


if __name__ == "__main__":
    main()
