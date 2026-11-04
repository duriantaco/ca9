from __future__ import annotations

import urllib.error

from ca9 import npm_publisher
from ca9.core.models import Package, SourceEvidence

ATTESTED = {"attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/x"}}
TRUSTED = {"name": "npm-oidc-no-reply", "trustedPublisher": {"id": "github"}}


def _document(states: dict[str, dict], times: dict[str, str] | None = None, name="pkg"):
    default_times = {
        version: f"2025-0{index + 1}-01T00:00:00.000Z" for index, version in enumerate(states)
    }
    return {"name": name, "time": times or default_times, "versions": states}


def _plain(publisher="maintainer"):
    return {"_npmUser": {"name": publisher}, "dist": {}}


def _attested():
    return {"_npmUser": {"name": "maintainer"}, "dist": dict(ATTESTED)}


def test_release_without_provenance_after_attested_releases_regresses():
    document = _document({"1.0.0": _attested(), "1.1.0": _attested(), "1.2.0": _plain()})

    result = npm_publisher.provenance_from_document(document, "pkg", "1.2.0")

    assert result["status"] == "regressed"
    assert result["evidence"]["previous_with_provenance"] == ["1.1.0", "1.0.0"]
    assert result["evidence"]["this_version"] == {"provenance": False, "trusted_publisher": False}


def test_trusted_publisher_history_counts_as_provenance():
    document = _document(
        {"1.0.0": {"_npmUser": TRUSTED, "dist": {}}, "1.1.0": _plain("someone-else")}
    )

    assert npm_publisher.provenance_from_document(document, "pkg", "1.1.0")["status"] == "regressed"


def test_package_that_never_had_provenance_is_ok():
    document = _document({"1.0.0": _plain(), "1.1.0": _plain(), "1.2.0": _plain()})

    assert npm_publisher.provenance_from_document(document, "pkg", "1.2.0")["status"] == "ok"


def test_package_that_kept_provenance_is_ok():
    document = _document({"1.0.0": _attested(), "1.1.0": _attested()})

    assert npm_publisher.provenance_from_document(document, "pkg", "1.1.0")["status"] == "ok"


def test_old_release_from_before_provenance_is_ok():
    document = _document({"1.0.0": _plain(), "2.0.0": _attested(), "2.1.0": _attested()})

    assert npm_publisher.provenance_from_document(document, "pkg", "1.0.0")["status"] == "ok"


def test_provenance_claimed_outside_the_registry_dist_block_does_not_count():
    forged = {
        "_npmUser": {"name": "attacker"},
        "dist": {"attestations": "yes"},
        "attestations": dict(ATTESTED["attestations"]),
        "provenance": True,
        "trustedPublisher": {"id": "github"},
    }
    document = _document({"1.0.0": _attested(), "1.1.0": forged})

    assert npm_publisher.provenance_from_document(document, "pkg", "1.1.0")["status"] == "regressed"


def test_only_recent_stable_releases_are_compared():
    states = {f"1.{minor}.0": _plain() for minor in range(6)}
    states = {"0.9.0": _attested(), **states, "2.0.0-beta.1": _attested(), "2.0.0": _plain()}
    times = {
        version: f"2025-{index + 1:02d}-01T00:00:00.000Z" for index, version in enumerate(states)
    }
    document = _document(states, times)

    result = npm_publisher.provenance_from_document(document, "pkg", "2.0.0")

    assert result["status"] == "ok"
    assert "2.0.0-beta.1" not in result["evidence"]["previous_versions_checked"]
    assert len(result["evidence"]["previous_versions_checked"]) == 5


def test_registry_errors_are_unknown(monkeypatch):
    def fail(url, *, max_bytes):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(npm_publisher, "_fetch_json", fail)

    assert npm_publisher.check_npm_provenance("pkg", "1.0.0")["status"] == "unknown"


def test_vet_publisher_scan_blocks_a_provenance_regression(monkeypatch):
    document = _document({"1.0.0": _attested(), "1.1.0": _attested(), "1.2.0": _plain()})
    monkeypatch.setattr(npm_publisher, "_fetch_json", lambda url, *, max_bytes: document)
    package = Package(
        name="pkg",
        version="1.2.0",
        ecosystem="npm",
        dependency_kind="direct",
        source_registry=npm_publisher.REGISTRY_ORIGIN,
        evidence=(SourceEvidence(source="package-lock.json", reader="package-lock.json"),),
        metadata={
            "source_kind": "registry",
            "lock_path": "node_modules/pkg",
            "installed_names": ["pkg"],
            "requested_specifiers": ["^1.0.0"],
        },
    )

    findings, _warnings = npm_publisher.scan_npm_publisher_changes([package])

    regression = [f for f in findings if f.signal_type == "provenance_regression"]
    assert regression[0].severity == "high"
    assert regression[0].metadata["action"] == "block"


def test_oversized_packument_falls_back_to_abbreviated_version_order(monkeypatch):
    abbreviated = {
        "name": "big",
        "modified": "2026-01-01T00:00:00Z",
        "versions": {
            "3.0.0": {"dist": dict(ATTESTED)},
            "2.9.9": {"dist": dict(ATTESTED)},
            "3.0.1": {"dist": {}},
        },
    }
    accepts = []

    def fetch(url, *, max_bytes, accept="application/json"):
        accepts.append(accept)
        if accept == "application/json":
            raise npm_publisher.RegistryFetchError(f"response exceeds {max_bytes} bytes")
        return dict(abbreviated)

    monkeypatch.setattr(npm_publisher, "_fetch_json", fetch)

    result = npm_publisher.check_npm_provenance("big", "3.0.1")

    assert accepts == ["application/json", npm_publisher.ABBREVIATED_PACKUMENT]
    assert result["status"] == "regressed"
    assert result["evidence"]["previous_with_provenance"] == ["3.0.0"]
    assert result["evidence"]["ordering"] == "version"


def test_plain_release_on_an_old_line_after_attested_newer_lines_regresses_as_newer():
    document = _document(
        {
            "4.9.0": _plain(),
            "5.0.0": _attested(),
            "5.1.0": _attested(),
            "4.9.1": _plain(),
        }
    )

    result = npm_publisher.provenance_from_document(document, "pkg", "4.9.1")

    assert result["status"] == "regressed"
    assert result["evidence"]["line"] == "newer"
    assert result["evidence"]["previous_with_provenance"] == ["5.1.0", "5.0.0"]


def test_old_line_release_published_before_any_attested_release_is_ok():
    document = _document(
        {"4.9.0": _plain(), "4.9.1": _plain(), "5.0.0": _attested(), "5.1.0": _attested()}
    )

    assert npm_publisher.provenance_from_document(document, "pkg", "4.9.1")["status"] == "ok"


def test_backport_without_provenance_on_an_attested_line_regresses():
    document = _document(
        {
            "4.8.0": _attested(),
            "4.9.0": _attested(),
            "5.0.0": _attested(),
            "4.9.1": _plain(),
        }
    )

    result = npm_publisher.provenance_from_document(document, "pkg", "4.9.1")

    assert result["status"] == "regressed"
    assert result["evidence"]["previous_with_provenance"] == ["4.9.0", "4.8.0"]
    assert result["evidence"]["line"] == "same"


def test_new_major_without_provenance_after_attested_releases_regresses():
    document = _document({"5.0.0": _attested(), "5.1.0": _attested(), "6.0.0": _plain()})

    result = npm_publisher.provenance_from_document(document, "pkg", "6.0.0")

    assert result["status"] == "regressed"
    assert result["evidence"]["line"] == "older"


def test_zero_major_lines_are_split_by_minor():
    document = _document(
        {"0.4.0": _plain(), "0.5.0": _attested(), "0.5.1": _attested(), "0.4.1": _plain()}
    )

    result = npm_publisher.provenance_from_document(document, "pkg", "0.4.1")

    assert result["status"] == "regressed"
    assert result["evidence"]["line"] == "newer"
