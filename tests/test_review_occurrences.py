from __future__ import annotations

import json

import pytest

from ca9.review import service
from test_dependency_review import Registry


@pytest.fixture
def registry(tmp_path, monkeypatch):
    return Registry(tmp_path, monkeypatch)


@pytest.mark.parametrize("declared_name", [False, True])
def test_alias_review_verifies_actual_package_identity(registry, declared_name):
    before = registry.release("1.0.0", name="actual")
    after = registry.release("2.0.0", name="actual")
    if declared_name:
        before["name"] = after["name"] = "actual"
    base = registry.lock(
        "base.json",
        entries={"node_modules/alias": before},
        root_dependencies={"alias": "npm:actual@*"},
    )
    head = registry.lock(
        "head.json",
        entries={"node_modules/alias": after},
        root_dependencies={"alias": "npm:actual@*"},
    )

    report = registry.review(base, head)

    assert report.complete
    assert report.decision == "pass"
    assert len(report.packages) == 1
    package = report.packages[0]
    assert package["path"] == "node_modules/alias"
    assert package["head"]["name"] == "actual"
    assert package["head"]["installed_name"] == "alias"
    assert package["head"]["chains"] == [["", "node_modules/alias"]]
    assert package["head_inspection"]["status"] == "verified"
    assert len(registry.downloads) == 2


def test_alias_target_change_is_visible_and_reviewed(registry):
    base = registry.lock(
        "base.json",
        entries={"node_modules/alias": registry.release("1.0.0", name="original")},
        root_dependencies={"alias": "npm:original@*"},
    )
    head = registry.lock(
        "head.json",
        entries={"node_modules/alias": registry.release("1.0.0", name="replacement")},
        root_dependencies={"alias": "npm:replacement@*"},
    )

    report = registry.review(base, head)

    assert report.complete
    assert report.decision == "review"
    assert report.packages[0]["path"] == "node_modules/alias"
    identity = next(
        delta
        for delta in report.packages[0]["deltas"]
        if delta["kind"] == "lock_metadata" and delta["key"] == "name"
    )
    assert identity["status"] == "changed"
    assert identity["base"] == "original"
    assert identity["head"] == "replacement"
    assert identity["action"] == "review"


def _repeated_entries(registry, before, after):
    parent = registry.release("1.0.0", name="parent", manifest={"dependencies": {"sample": "*"}})
    parent["dependencies"] = {"sample": "*"}
    common = {"node_modules/parent": parent}
    return (
        {
            **common,
            "node_modules/sample": before,
            "node_modules/parent/node_modules/sample": before,
        },
        {
            **common,
            "node_modules/sample": after,
            "node_modules/parent/node_modules/sample": after,
        },
    )


def test_repeated_occurrences_keep_separate_chains_and_share_artifact_inspection(
    registry, monkeypatch
):
    before = registry.release("1.0.0")
    after = registry.release("2.0.0")
    base_entries, head_entries = _repeated_entries(registry, before, after)
    roots = {"parent": "*", "sample": "*"}
    base = registry.lock("base.json", entries=base_entries, root_dependencies=roots)
    head = registry.lock("head.json", entries=head_entries, root_dependencies=roots)
    inspected = []
    original = service.inspect_snapshot

    def inspect(snapshot):
        inspected.append(snapshot.package.version)
        return original(snapshot)

    monkeypatch.setattr(service, "inspect_snapshot", inspect)

    report = registry.review(base, head)

    assert report.complete
    assert report.summary["packages_changed"] == 2
    assert report.summary["packages_unchanged"] == 1
    by_path = {package["path"]: package for package in report.packages}
    assert set(by_path) == {"node_modules/sample", "node_modules/parent/node_modules/sample"}
    assert by_path["node_modules/sample"]["head"]["chains"] == [["", "node_modules/sample"]]
    assert by_path["node_modules/parent/node_modules/sample"]["head"]["chains"] == [
        ["", "node_modules/parent", "node_modules/parent/node_modules/sample"]
    ]
    assert registry.downloads == [before["resolved"], after["resolved"]]
    assert inspected == ["1.0.0", "2.0.0"]


def test_nested_upgrade_does_not_collapse_into_unchanged_root_occurrence(registry):
    before = registry.release("1.0.0")
    after = registry.release("2.0.0")
    base_entries, head_entries = _repeated_entries(registry, before, after)
    head_entries["node_modules/sample"] = before
    roots = {"parent": "*", "sample": "*"}
    base = registry.lock("base.json", entries=base_entries, root_dependencies=roots)
    head = registry.lock("head.json", entries=head_entries, root_dependencies=roots)

    report = registry.review(base, head)

    assert report.complete
    assert report.decision == "pass"
    assert report.summary["packages_changed"] == 1
    assert report.summary["packages_unchanged"] == 2
    assert len(report.packages) == 1
    assert report.packages[0]["path"] == "node_modules/parent/node_modules/sample"
    assert report.packages[0]["head"]["chains"] == [
        ["", "node_modules/parent", "node_modules/parent/node_modules/sample"]
    ]
    assert registry.downloads == [before["resolved"], after["resolved"]]


def test_root_requested_constraint_change_is_reported_for_same_locked_release(registry):
    release = registry.release("1.0.0")
    base = registry.lock("base.json", release, root_dependencies={"sample": "^1.0.0"})
    head = registry.lock("head.json", release, root_dependencies={"sample": "~1.0.0"})

    report = registry.review(base, head)

    assert report.complete
    assert report.summary["packages_changed"] == 1
    package = report.packages[0]
    assert package["base"]["version"] == package["head"]["version"] == "1.0.0"
    delta = next(
        item
        for item in package["deltas"]
        if item["kind"] == "lock_metadata" and item["key"] == "requested_specifiers"
    )
    assert delta["status"] == "changed"
    assert delta["base"] == ["^1.0.0"]
    assert delta["head"] == ["~1.0.0"]
    assert registry.downloads == [release["resolved"]]


def test_unchanged_workspace_does_not_make_changed_registry_review_incomplete(registry):
    common = {
        "node_modules/local": {"link": True, "resolved": "packages/local"},
        "packages/local": {"name": "local", "version": "1.0.0"},
    }
    paths = [
        registry.lock(
            filename,
            entries={**common, "node_modules/sample": registry.release(version)},
            root_dependencies={"sample": "*", "local": "workspace:*"},
        )
        for filename, version in (("base.json", "1.0.0"), ("head.json", "2.0.0"))
    ]
    for path in paths:
        data = json.loads(path.read_text())
        data["packages"][""]["workspaces"] = ["packages/*"]
        path.write_text(json.dumps(data))

    report = registry.review(*paths)

    assert report.complete
    assert report.decision == "pass"
    assert report.issues == ()
    assert report.summary["packages_unchanged"] == 2
    assert [package["path"] for package in report.packages] == ["node_modules/sample"]
    assert len(registry.downloads) == 2


@pytest.mark.parametrize("malformed", [None, [], {}, {"version": "2.0.0", "dependencies": []}])
def test_malformed_changed_occurrence_is_incomplete_instead_of_removed(registry, malformed):
    base = registry.lock("base.json", registry.release("1.0.0"), root_dependencies={"sample": "*"})
    head = registry.lock(
        "head.json", entries={"node_modules/sample": malformed}, root_dependencies={"sample": "*"}
    )

    report = registry.review(base, head)

    assert not report.complete
    assert report.decision == "incomplete"
    assert report.exit_code == 2
    assert report.summary["packages_changed"] == 1
    assert report.summary["packages_removed"] == 0
    assert report.packages[0]["head"] is not None
    assert report.packages[0]["head_inspection"]["status"] == "incomplete"


@pytest.mark.parametrize(
    "field,key,value",
    [
        ("os", "platforms", ["linux"]),
        ("cpu", "platforms", ["arm64"]),
        ("libc", "platforms", ["musl"]),
        ("peerDependenciesMeta", "peer_metadata", {"optional-peer": {"optional": True}}),
    ],
)
def test_platform_and_peer_metadata_changes_have_visible_deltas(registry, field, key, value):
    release = registry.release("1.0.0")
    base = registry.lock("base.json", release)
    head = registry.lock("head.json", {**release, field: value})

    report = registry.review(base, head)

    assert report.complete
    delta = next(
        item
        for item in report.packages[0]["deltas"]
        if item["kind"] == "lock_metadata" and item["key"] == key
    )
    assert delta["status"] == "changed"
    assert delta["head"] != delta["base"]


@pytest.mark.parametrize(
    "fields",
    [
        {"os": "linux"},
        {"cpu": [None]},
        {"libc": [""]},
        {"peerDependenciesMeta": []},
        {"peerDependenciesMeta": {"peer": {"optional": "yes"}}},
    ],
)
def test_malformed_platform_and_peer_metadata_is_incomplete(registry, fields):
    release = registry.release("1.0.0")
    base = registry.lock("base.json", release)
    head = registry.lock("head.json", {**release, **fields})

    report = registry.review(base, head)

    assert not report.complete
    assert report.decision == "incomplete"
    assert report.packages[0]["head_inspection"]["status"] == "incomplete"
