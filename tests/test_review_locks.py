from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca9.review import locks
from ca9.review.locks import compare_locks, load_lock


def _package(version="1.0.0", **fields):
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/example/-/example-{version}.tgz",
        "integrity": "sha512-dGVzdA==",
        **fields,
    }


def _write(tmp_path: Path, packages: dict, *, name="lock.json", version=3):
    path = tmp_path / name
    path.write_text(json.dumps({"lockfileVersion": version, "packages": packages}))
    return path


@pytest.mark.parametrize("version", [2, 3])
def test_supported_lock_versions_preserve_labels(tmp_path, version):
    path = _write(
        tmp_path,
        {"": {"dependencies": {"example": "^1"}}, "node_modules/example": _package()},
        version=version,
    )
    state = load_lock(path, label="before")
    occurrence = state.occurrences["node_modules/example"]
    assert state.label == "before"
    assert state.issues == ()
    assert occurrence.package.name == "example"
    assert occurrence.chains == (("", "node_modules/example"),)
    assert occurrence.metadata["inspection_supported"] is True


@pytest.mark.parametrize(
    "contents",
    [
        "[]",
        "{}",
        '{"lockfileVersion":1,"packages":{"":{}}}',
        '{"lockfileVersion":"3","packages":{"":{}}}',
        '{"lockfileVersion":true,"packages":{"":{}}}',
        '{"lockfileVersion":3,"packages":[]}',
        '{"lockfileVersion":3,"packages":{}}',
        '{"lockfileVersion":3,"packages":{"":null}}',
        '{"lockfileVersion":3,"lockfileVersion":2,"packages":{"":{}}}',
        '{"lockfileVersion":3,"packages":{"":{},"x":{},"x":{}}}',
        "invalid json",
    ],
)
def test_fundamentally_invalid_schema_is_rejected(tmp_path, contents):
    path = tmp_path / "lock.json"
    path.write_text(contents)
    with pytest.raises(ValueError):
        load_lock(path)


def test_lockfile_size_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(locks, "MAX_LOCK_BYTES", 20)
    path = _write(tmp_path, {"": {}})
    with pytest.raises(ValueError, match="exceeds"):
        load_lock(path)


def test_matching_uses_occurrences_not_package_keys(tmp_path):
    base_packages = {
        "": {"dependencies": {"parent": "1", "example": "1"}},
        "node_modules/parent": _package(dependencies={"example": "1"}),
        "node_modules/example": _package(),
        "node_modules/parent/node_modules/example": _package(),
    }
    head_packages = {**base_packages, "node_modules/parent/node_modules/example": _package("2.0.0")}
    base = load_lock(_write(tmp_path, base_packages, name="base.json"))
    head = load_lock(_write(tmp_path, head_packages, name="head.json"))
    changes = {change.path: change for change in compare_locks(base, head)}
    assert len(changes) == 3
    assert changes["node_modules/example"].status == "unchanged"
    changed = changes["node_modules/parent/node_modules/example"]
    assert changed.status == "changed"
    assert changed.head.chains == (("", "node_modules/parent", changed.path),)


def test_aliases_keep_installation_and_advisory_identities(tmp_path):
    state = load_lock(
        _write(
            tmp_path,
            {
                "": {"dependencies": {"alias": "npm:@org/actual@^1"}},
                "node_modules/alias": _package(name="@org/actual"),
            },
        )
    )
    occurrence = state.occurrences["node_modules/alias"]
    assert occurrence.package.name == "@org/actual"
    assert occurrence.metadata["installed_name"] == "alias"
    assert occurrence.metadata["source_kind"] == "registry"
    assert state.issues == ()


def test_alias_identity_can_be_inferred_from_requested_specifier(tmp_path):
    state = load_lock(
        _write(
            tmp_path,
            {"": {"dependencies": {"alias": "npm:actual@1"}}, "node_modules/alias": _package()},
        )
    )
    assert state.occurrences["node_modules/alias"].package.name == "actual"
    assert state.issues == ()


@pytest.mark.parametrize("bad_entry", [None, [], "invalid", {}, {"version": []}])
def test_malformed_occurrence_is_retained_not_removed(tmp_path, bad_entry):
    root = {"dependencies": {"example": "1"}}
    base = load_lock(_write(tmp_path, {"": root, "node_modules/example": _package()}, name="base"))
    head = load_lock(_write(tmp_path, {"": root, "node_modules/example": bad_entry}, name="head"))
    change = compare_locks(base, head)[0]
    assert change.status == "changed"
    assert change.head is not None
    assert change.head.metadata["inspection_supported"] is False
    assert head.issues


@pytest.mark.parametrize(
    "fields",
    [
        {"hasInstallScript": "yes"},
        {"dependencies": ["missing"]},
        {"dependencies": {"bad/name/path": "1"}},
        {"dependencies": {"child": None}},
        {"name": "bad/name/path"},
        {"resolved": "https://[invalid"},
        {"resolved": "https://token:secret@registry.npmjs.org/example.tgz"},
        {"resolved": "file:../example.tgz"},
        {"integrity": ""},
        {"inBundle": True},
    ],
)
def test_uninspectable_metadata_is_explicit(tmp_path, fields):
    state = load_lock(_write(tmp_path, {"": {}, "node_modules/example": _package(**fields)}))
    assert state.issues
    assert state.occurrences["node_modules/example"].metadata["inspection_supported"] is False


def test_workspaces_and_links_remain_in_inventory_with_chains(tmp_path):
    state = load_lock(
        _write(
            tmp_path,
            {
                "": {"workspaces": ["packages/*"], "dependencies": {"example": "workspace:*"}},
                "node_modules/example": {"link": True, "resolved": "packages/example"},
                "packages/example": {"name": "example", "version": "1.0.0"},
            },
        )
    )
    assert set(state.occurrences) == {"node_modules/example", "packages/example"}
    assert state.occurrences["packages/example"].chains == (
        ("", "node_modules/example", "packages/example"),
    )
    assert all(not item.metadata["inspection_supported"] for item in state.occurrences.values())
    assert state.issues


def test_hoisted_dependencies_report_all_root_chains(tmp_path):
    state = load_lock(
        _write(
            tmp_path,
            {
                "": {"dependencies": {"a": "1", "b": "1"}},
                "node_modules/a": _package(dependencies={"shared": "1"}),
                "node_modules/b": _package(dependencies={"shared": "1"}),
                "node_modules/shared": _package(),
            },
        )
    )
    assert state.occurrences["node_modules/shared"].chains == (
        ("", "node_modules/a", "node_modules/shared"),
        ("", "node_modules/b", "node_modules/shared"),
    )


def test_dependency_cycles_are_bounded_and_explicit(tmp_path):
    state = load_lock(
        _write(
            tmp_path,
            {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": _package(dependencies={"b": "1"}),
                "node_modules/b": _package(dependencies={"a": "1"}),
            },
        )
    )
    assert state.issues == ()
    assert state.occurrences["node_modules/b"].metadata["cycle_references"] == ["node_modules/a"]
    assert state.occurrences["node_modules/b"].chains == (("", "node_modules/a", "node_modules/b"),)


def test_chain_count_limits_are_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(locks, "MAX_CHAINS_PER_OCCURRENCE", 1)
    state = load_lock(
        _write(
            tmp_path,
            {
                "": {"dependencies": {"a": "1", "b": "1"}},
                "node_modules/a": _package(dependencies={"shared": "1"}),
                "node_modules/b": _package(dependencies={"shared": "1"}),
                "node_modules/shared": _package(),
            },
        )
    )
    assert any("count limit" in issue for issue in state.issues)
    assert len(state.occurrences["node_modules/shared"].chains) == 1


def test_optional_missing_dependencies_do_not_invent_incomplete_chains(tmp_path):
    state = load_lock(
        _write(
            tmp_path,
            {
                "": {
                    "dependencies": {"example": "1"},
                    "optionalDependencies": {"platform-only": "1"},
                    "peerDependencies": {"optional-peer": "1"},
                    "peerDependenciesMeta": {"optional-peer": {"optional": True}},
                },
                "node_modules/example": _package(devDependencies={"not-installed": "1"}),
            },
        )
    )
    assert state.issues == ()


def test_required_unresolved_dependencies_are_explicit(tmp_path):
    state = load_lock(_write(tmp_path, {"": {"dependencies": {"missing": "1"}}}))
    assert state.issues == ("root: unresolved runtime dependency missing",)


def test_order_and_irrelevant_metadata_do_not_change_identity(tmp_path):
    base = load_lock(
        _write(tmp_path, {"": {}, "node_modules/example": _package(license="MIT")}, name="base")
    )
    head = load_lock(
        _write(
            tmp_path,
            {"node_modules/example": _package(license="ISC", dev=False, name="example"), "": {}},
            name="head",
        )
    )
    assert compare_locks(base, head)[0].status == "unchanged"


def test_sources_are_redacted_but_distinct_sources_still_compare_changed(tmp_path):
    sources = [
        "https://user:secret@registry.npmjs.org/example.tgz?token=secret#secret",
        "https://user:other@registry.npmjs.org/example.tgz?token=other#other",
    ]
    states = [
        load_lock(
            _write(
                tmp_path, {"": {}, "node_modules/example": _package(resolved=source)}, name=str(i)
            )
        )
        for i, source in enumerate(sources)
    ]
    assert "secret" not in json.dumps(states[0].occurrences["node_modules/example"].metadata)
    assert "secret" not in json.dumps(states[0].issues)
    assert states[0].occurrences["node_modules/example"].package.artifacts[0].url == sources[0]
    assert compare_locks(*states)[0].status == "changed"


def test_added_and_removed_occurrences_are_deterministic(tmp_path):
    base = load_lock(_write(tmp_path, {"": {}, "node_modules/b": _package()}, name="base"))
    head = load_lock(_write(tmp_path, {"": {}, "node_modules/a": _package()}, name="head"))
    assert [(item.path, item.status) for item in compare_locks(base, head)] == [
        ("node_modules/a", "added"),
        ("node_modules/b", "removed"),
    ]


def test_root_requested_specifier_change_retains_same_release_delta(tmp_path):
    states = [
        load_lock(
            _write(
                tmp_path,
                {"": {"dependencies": {"example": specifier}}, "node_modules/example": _package()},
                name=str(i),
            )
        )
        for i, specifier in enumerate(("^1", "~1"))
    ]
    change = compare_locks(*states)[0]
    assert change.status == "changed"
    assert change.base.package.version == change.head.package.version
    assert change.base.metadata["requested_specifiers"] == ["^1"]
    assert change.head.metadata["requested_specifiers"] == ["~1"]


def test_integrity_token_order_does_not_change_artifact_identity(tmp_path):
    states = [
        load_lock(
            _write(
                tmp_path,
                {"": {}, "node_modules/example": _package(integrity=integrity)},
                name=str(i),
            )
        )
        for i, integrity in enumerate(("sha512-eA== sha256-eQ==", "sha256-eQ==  sha512-eA=="))
    ]
    assert compare_locks(*states)[0].status == "unchanged"


@pytest.mark.parametrize("limit", ["MAX_CHAIN_DEPTH", "MAX_CHAIN_STEPS"])
def test_other_chain_limits_are_explicit(tmp_path, monkeypatch, limit):
    monkeypatch.setattr(locks, limit, 1)
    state = load_lock(
        _write(
            tmp_path,
            {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": _package(dependencies={"b": "1"}),
                "node_modules/b": _package(),
            },
        )
    )
    assert any("limit" in issue for issue in state.issues)


@pytest.mark.parametrize("path", ["../node_modules/a", "C:/node_modules/a", "/node_modules/a"])
def test_invalid_installation_paths_remain_explicit(tmp_path, path):
    state = load_lock(_write(tmp_path, {"": {}, path: _package()}))
    assert path in state.occurrences
    assert state.occurrences[path].metadata["inspection_supported"] is False
    assert any("installation path" in issue for issue in state.issues)
