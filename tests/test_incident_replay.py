from __future__ import annotations

from pathlib import Path

from scripts.incident_replay import assert_expectations, render_markdown, replay_incidents

FIXTURES = Path(__file__).parent / "fixtures" / "incidents"


def test_incident_replay_current_expectations_match_fixtures():
    report = replay_incidents(FIXTURES)

    assert report["schema_version"] == "ca9.incident-replay.v1"
    assert report["summary"]["incidents"] == 4
    assert report["summary"]["covered"] == 0
    assert report["summary"]["partial"] == 3
    assert report["summary"]["gap"] == 1
    assert_expectations(report)


def test_incident_replay_exposes_pypi_import_dropper_partial_coverage():
    report = replay_incidents(FIXTURES)
    incident = _incident(report, "pypi-import-dropper-2026-05")
    checks = _checks(incident)

    assert incident["overall_status"] == "partial"
    assert checks["inventory"]["status"] == "pass"
    assert checks["malware_advisory"]["status"] == "gap"
    assert checks["malware_advisory"]["advisory_ids"] == ["GHSA-wx9m-wx4f-4cmg"]
    assert checks["malware_advisory"]["missing_package_keys"] == ["pypi:mistralai@2.4.6"]


def test_incident_replay_exposes_npm_inventory_and_remaining_gaps():
    report = replay_incidents(FIXTURES)
    npm_actions = _incident(report, "npm-actions-oidc-2026-05")
    npm_actions_checks = _checks(npm_actions)
    npm_sdk = _incident(report, "npm-sdk-compromise-2026-05")
    npm_sdk_checks = _checks(npm_sdk)

    assert npm_actions["overall_status"] == "partial"
    assert npm_actions_checks["inventory"]["status"] == "pass"
    assert npm_actions_checks["malware_advisory"]["status"] == "gap"
    assert npm_actions_checks["workflow"]["status"] == "gap"
    assert npm_actions_checks["workflow"]["missing_capability"] == "github_actions_workflow_scanner"
    assert npm_actions_checks["inventory"]["expected_package_keys"] == [
        "npm:@tanstack/history@1.161.9",
        "npm:@tanstack/react-router@1.169.5",
    ]
    assert npm_actions_checks["inventory"]["missing_package_keys"] == []

    assert npm_sdk["overall_status"] == "partial"
    assert npm_sdk_checks["inventory"]["status"] == "pass"
    assert npm_sdk_checks["inventory"]["expected_package_keys"] == [
        "npm:@mistralai/mistralai-azure@1.7.3",
        "npm:@mistralai/mistralai-gcp@1.7.3",
        "npm:@mistralai/mistralai@2.2.4",
    ]
    assert npm_sdk_checks["inventory"]["missing_package_keys"] == []


def test_incident_replay_markdown_calls_out_gaps():
    report = replay_incidents(FIXTURES)
    markdown = render_markdown(report)

    assert "| pypi-import-dropper-2026-05 | partial | pass | gap | not_applicable |" in markdown
    assert "| npm-actions-oidc-2026-05 | partial | pass | gap | gap |" in markdown
    assert "github_actions_workflow_scanner" not in markdown
    assert "pnpm-lock.yaml and yarn.lock inventory are not currently implemented." in markdown


def _incident(report: dict, incident_id: str) -> dict:
    return next(incident for incident in report["incidents"] if incident["id"] == incident_id)


def _checks(incident: dict) -> dict:
    return {check["name"]: check for check in incident["checks"]}
