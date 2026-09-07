from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Artifact, Package
from ca9.review.behavior import inspect_snapshot


def snapshot(tmp_path: Path, manifest: dict, files: dict[str, str | bytes]) -> ArtifactSnapshot:
    contents = {
        "package.json": json.dumps({"name": "example", "version": "1.0.0", **manifest}),
        **files,
    }
    entries = []
    for name, content in contents.items():
        raw = content.encode() if isinstance(content, str) else content
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        entries.append(ArtifactFile(f"package/{name}", path, len(raw)))
    artifact = Artifact("npm-tarball", "https://registry.npmjs.org/example/-/example.tgz")
    return ArtifactSnapshot(
        Package("example", "1.0.0", "npm"),
        artifact,
        tmp_path / "archive.tgz",
        tmp_path,
        tuple(entries),
    )


def test_nested_extensionless_bin_is_inspected_before_completeness(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {},
            {
                "node_modules/child/package.json": '{"bin":"bin/hello"}',
                "node_modules/child/bin/hello": b"\x00inert binary fixture",
            },
        )
    )
    assert any("binary data" in issue and "child/bin/hello" in issue for issue in profile.issues)


@pytest.mark.parametrize("command", ["node setup", "node ./setup", "node -- setup"])
def test_local_node_lifecycle_target_is_inspected(tmp_path: Path, command: str) -> None:
    profile = inspect_snapshot(
        snapshot(tmp_path, {"scripts": {"install": command}}, {"setup": b"\x00inert fixture"})
    )
    assert any("binary data" in issue and "setup" in issue for issue in profile.issues)


def test_missing_lifecycle_target_is_unknown(tmp_path: Path) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {"scripts": {"install": "node missing"}}, {}))
    assert any("lifecycle" in issue.lower() and "missing" in issue for issue in profile.issues)


@pytest.mark.parametrize("command", ["npm run setup", "node first.js && node second.js"])
def test_lifecycle_indirection_and_chains_are_explicitly_unknown(
    tmp_path: Path, command: str
) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {"scripts": {"install": command}},
            {"first.js": "void 0;", "second.js": "void 0;"},
        )
    )
    assert any("lifecycle" in issue.lower() for issue in profile.issues)


def test_ordinary_node_lifecycle_file_remains_complete(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(tmp_path, {"scripts": {"install": "node install.js"}}, {"install.js": "void 0;"})
    )
    assert not profile.issues


def test_type_change_is_a_comparable_module_format_fact(tmp_path: Path) -> None:
    before = inspect_snapshot(snapshot(tmp_path / "base", {"type": "commonjs"}, {"index.js": "0;"}))
    after = inspect_snapshot(snapshot(tmp_path / "head", {"type": "module"}, {"index.js": "0;"}))
    left = {fact.key: fact.value for fact in before.facts if fact.kind == "module_format"}
    right = {fact.key: fact.value for fact in after.facts if fact.kind == "module_format"}
    assert left["type"] == "commonjs"
    assert right["type"] == "module"


def test_invalid_module_format_is_unknown(tmp_path: Path) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {"type": ["module"]}, {}))
    assert any("type" in issue for issue in profile.issues)


def test_directories_bin_adds_comparable_executables(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {"directories": {"bin": "commands"}},
            {"commands/hello": "#!/usr/bin/env node\nconsole.log('ready');"},
        )
    )
    assert not profile.issues
    assert any(
        fact.kind == "entrypoint"
        and fact.key == "bin"
        and fact.value == {"hello": "commands/hello"}
        for fact in profile.facts
    )


def test_directories_bin_inspects_extensionless_binary(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(tmp_path, {"directories": {"bin": "commands"}}, {"commands/hello": b"\x00fixture"})
    )
    assert any("binary data" in issue for issue in profile.issues)


def test_directories_bin_missing_directory_is_unknown(tmp_path: Path) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {"directories": {"bin": "missing"}}, {}))
    assert any("directories.bin" in issue for issue in profile.issues)


def test_conflicting_bin_declarations_are_unknown(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {"bin": "commands/hello", "directories": {"bin": "commands"}},
            {"commands/hello": "#!/usr/bin/env node\nvoid 0;"},
        )
    )
    assert any("directories.bin" in issue for issue in profile.issues)


def test_gypfile_false_disables_implicit_install_hook(tmp_path: Path) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {"gypfile": False}, {"binding.gyp": "{}"}))
    assert not any(fact.kind == "lifecycle_script" for fact in profile.facts)
    assert any("binding.gyp" in issue for issue in profile.issues)


@pytest.mark.parametrize("main", [".", "./", "lib/../index.js", "missing.js"])
def test_valid_legacy_main_resolution_and_root_fallback(tmp_path: Path, main: str) -> None:
    profile = inspect_snapshot(
        snapshot(tmp_path, {"main": main}, {"index.js": "module.exports = 1;"})
    )
    assert not profile.issues


def test_implicit_json_entrypoint_is_comparable(tmp_path: Path) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {}, {"index.json": '{"value":1}'}))
    assert any(
        fact.kind == "entrypoint" and fact.key == "main" and fact.value == "index.json"
        for fact in profile.facts
    )


@pytest.mark.parametrize("suffix", [".mjs", ".cjs"])
def test_legacy_main_does_not_invent_extension_search(tmp_path: Path, suffix: str) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {"main": "start"}, {f"start{suffix}": "0;"}))
    assert any("cannot be resolved" in issue for issue in profile.issues)


def test_nested_main_is_resolved_relative_to_its_manifest(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {},
            {
                "node_modules/child/package.json": '{"main":"entry"}',
                "node_modules/child/entry": b"\x00fixture",
            },
        )
    )
    assert any("binary data" in issue and "child/entry" in issue for issue in profile.issues)


def test_nested_lifecycle_is_resolved_relative_to_its_manifest(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {},
            {
                "setup": "void 0;",
                "node_modules/child/package.json": '{"scripts":{"install":"node setup"}}',
                "node_modules/child/setup": b"\x00fixture",
            },
        )
    )
    assert any("binary data" in issue and "child/setup" in issue for issue in profile.issues)


def test_nested_missing_entrypoint_is_unknown(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(tmp_path, {}, {"node_modules/child/package.json": '{"bin":"bin/missing"}'})
    )
    assert any(
        "child/package.json" in issue and "cannot be resolved" in issue for issue in profile.issues
    )


def test_directory_bins_include_nested_files_and_exclude_hidden_files(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {"directories": {"bin": "commands"}},
            {
                "commands/nested/hello": "#!/usr/bin/env node\nvoid 0;",
                "commands/.hidden": b"\x00fixture",
            },
        )
    )
    assert not profile.issues
    bins = next(fact.value for fact in profile.facts if fact.key == "bin")
    assert bins == {"hello": "commands/nested/hello"}


def test_duplicate_directory_bin_names_are_unknown(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {"directories": {"bin": "commands"}},
            {
                "commands/one/hello": "#!/usr/bin/env node\nvoid 0;",
                "commands/two/hello": "#!/usr/bin/env node\nvoid 0;",
            },
        )
    )
    assert any("Ambiguous directories.bin" in issue for issue in profile.issues)


def test_direct_extensionless_script_needs_a_supported_interpreter(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(tmp_path, {"scripts": {"install": "./setup"}}, {"setup": "echo ready"})
    )
    assert any("Unsupported executable" in issue for issue in profile.issues)


def test_node_lifecycle_target_can_resolve_directory_main(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {"scripts": {"install": "node tools"}},
            {"tools/package.json": '{"main":"setup"}', "tools/setup": "void 0;"},
        )
    )
    assert not profile.issues


def test_unspecified_type_is_not_assumed_equivalent_to_commonjs(tmp_path: Path) -> None:
    absent = inspect_snapshot(snapshot(tmp_path / "absent", {}, {"index.js": "void 0;"}))
    explicit = inspect_snapshot(
        snapshot(tmp_path / "explicit", {"type": "commonjs"}, {"index.js": "void 0;"})
    )
    absent_type = next(fact.value for fact in absent.facts if fact.kind == "module_format")
    explicit_type = next(fact.value for fact in explicit.facts if fact.kind == "module_format")
    assert absent_type == "unspecified"
    assert explicit_type == "commonjs"


def test_nested_gypfile_false_disables_only_nested_implicit_hook(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(
            tmp_path,
            {},
            {
                "binding.gyp": "{}",
                "node_modules/child/package.json": '{"gypfile":false}',
                "node_modules/child/binding.gyp": "{}",
            },
        )
    )
    hooks = [fact.key for fact in profile.facts if fact.kind == "lifecycle_script"]
    assert hooks == ["install"]


def test_native_gap_does_not_hide_verified_gypfile_declarations(tmp_path: Path) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {"gypfile": False}, {"binding.gyp": "{}"}))
    assert profile.issues
    assert profile.declarations_complete
    assert not any(fact.kind == "lifecycle_script" for fact in profile.facts)


@pytest.mark.parametrize("manifest", [{"scripts": []}, {"dependencies": []}, {"type": 1}])
def test_invalid_root_declarations_are_not_complete(tmp_path: Path, manifest: dict) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, manifest, {}))
    assert profile.issues
    assert not profile.declarations_complete


@pytest.mark.parametrize("nested", ['{"scripts":[]}', '{"scripts":'])
def test_invalid_nested_declarations_are_not_complete(tmp_path: Path, nested: str) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {}, {"node_modules/child/package.json": nested}))
    assert profile.issues
    assert not profile.declarations_complete


def test_missing_executable_preserves_verified_declarations(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        snapshot(tmp_path, {"scripts": {"install": "node missing"}, "bin": "missing"}, {})
    )
    assert profile.issues
    assert profile.declarations_complete


def test_invalid_directories_declaration_is_not_complete(tmp_path: Path) -> None:
    profile = inspect_snapshot(snapshot(tmp_path, {"directories": {"bin": False}}, {}))
    assert profile.issues
    assert not profile.declarations_complete
