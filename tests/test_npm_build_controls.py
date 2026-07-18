from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca9.analyzers.npm_build_controls import (
    MAX_BINDING_GYP_BYTES,
    MAX_BINDING_GYP_NODES,
    analyze_native_build_controls,
)
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Artifact, Package


def _snapshot(
    tmp_path: Path,
    content: str | bytes | None,
    *,
    relative_path: str = "package/binding.gyp",
    declared_size: int | None = None,
) -> ArtifactSnapshot:
    extract_dir = tmp_path / "extract"
    file_path = extract_dir / relative_path
    raw = content.encode() if isinstance(content, str) else content
    if raw is not None:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(raw)

    package = Package(name="native-addon", version="1.0.0", ecosystem="npm")
    artifact = Artifact(kind="npm-tarball", hash="sha512-test")
    file = ArtifactFile(
        relative_path=relative_path,
        path=file_path,
        size=len(raw or b"") if declared_size is None else declared_size,
    )
    return ArtifactSnapshot(
        package=package,
        artifact=artifact,
        archive_path=tmp_path / "native-addon.tgz",
        extract_dir=extract_dir,
        files=(file,),
    )


def test_absent_binding_gyp_is_distinct_from_unsafe(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        '{"targets": []}',
        relative_path="package/package.json",
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is True
    assert result.binding_gyp_present is False
    assert result.reasons == ()


def test_simple_binding_gyp_is_safe(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        json.dumps(
            {
                "targets": [
                    {
                        "target_name": "addon",
                        "sources": ["src/addon.cc"],
                        "include_dirs": ["include"],
                    }
                ]
            }
        ),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is True
    assert result.binding_gyp_present is True
    assert result.reasons == ()


def test_python_style_gyp_literal_is_supported(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        """{
          # GYP permits Python-style comments and literals.
          'targets': [{'target_name': 'addon', 'sources': ['addon.cc']}],
        }""",
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is True
    assert result.binding_gyp_present is True


@pytest.mark.parametrize(
    ("control", "reason"),
    [
        ("actions", "binding-gyp-actions"),
        ("actions+", "binding-gyp-actions"),
        ("actions=", "binding-gyp-actions"),
        ("rules", "binding-gyp-rules"),
        ("postbuilds", "binding-gyp-postbuilds"),
        ("msvs_prebuild", "binding-gyp-msvs-prebuild"),
        ("msvs_external_builder_build_cmd", "binding-gyp-msvs-external-builder"),
        ("conditions", "binding-gyp-conditions"),
        ("target_conditions", "binding-gyp-conditions"),
        ("make_global_settings", "binding-gyp-make-global-settings"),
    ],
)
def test_executable_control_is_unsafe(tmp_path: Path, control: str, reason: str):
    snapshot = _snapshot(
        tmp_path,
        json.dumps(
            {
                "targets": [
                    {
                        "target_name": "addon",
                        control: [{"action": ["python", "generate.py"]}],
                    }
                ]
            }
        ),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.binding_gyp_present is True
    assert result.reasons == (reason,)


@pytest.mark.parametrize(
    "substitution",
    [
        "<!(node generate.js)",
        "<!@(node list.js)",
        ">!(node generate.js)",
        "^!@(node list.js)",
        "<!pymod_do_main(evil)",
    ],
)
def test_shell_command_substitution_is_unsafe(tmp_path: Path, substitution: str):
    snapshot = _snapshot(
        tmp_path,
        json.dumps(
            {
                "targets": [
                    {
                        "target_name": "addon",
                        "sources": [substitution],
                    }
                ]
            }
        ),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-shell-substitution",)


def test_control_word_in_a_string_is_not_treated_as_a_control(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        json.dumps({"targets": [{"target_name": "actions", "sources": ["actions.cc"]}]}),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is True
    assert result.reasons == ()


def test_gyp_include_requires_review(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        json.dumps(
            {
                "includes": ["build/common.gypi"],
                "targets": [{"target_name": "addon", "sources": ["addon.cc"]}],
            }
        ),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-includes",)


def test_separate_gypi_controls_are_inspected(tmp_path: Path):
    binding = _snapshot(tmp_path, json.dumps({"targets": []}))
    gypi = _snapshot(
        tmp_path,
        json.dumps({"actions": [{"action": ["node", "generate.js"]}]}),
        relative_path="package/build/common.gypi",
    )
    snapshot = ArtifactSnapshot(
        package=binding.package,
        artifact=binding.artifact,
        archive_path=binding.archive_path,
        extract_dir=binding.extract_dir,
        files=(*binding.files, *gypi.files),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.binding_gyp_present is True
    assert result.reasons == ("binding-gyp-actions",)


def test_case_variant_dependency_gyp_requires_review(tmp_path: Path):
    binding = _snapshot(
        tmp_path,
        json.dumps(
            {
                "targets": [
                    {
                        "target_name": "addon",
                        "dependencies": ["evil.GYP:pwn"],
                    }
                ]
            }
        ),
    )
    dependency = _snapshot(
        tmp_path,
        json.dumps({"actions": [{"action": ["node", "payload.js"]}]}),
        relative_path="package/evil.GYP",
    )
    snapshot = ArtifactSnapshot(
        package=binding.package,
        artifact=binding.artifact,
        archive_path=binding.archive_path,
        extract_dir=binding.extract_dir,
        files=(*binding.files, *dependency.files),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert "binding-gyp-dependencies" in result.reasons
    assert "binding-gyp-actions" in result.reasons


def test_malformed_binding_gyp_is_unsafe(tmp_path: Path):
    snapshot = _snapshot(tmp_path, "{'targets': [}")

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-invalid-format",)


def test_declared_oversized_binding_gyp_is_unsafe(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        '{"targets": []}',
        declared_size=MAX_BINDING_GYP_BYTES + 1,
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-too-large",)


def test_actual_size_is_bounded_even_if_metadata_understates_it(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        b" " * (MAX_BINDING_GYP_BYTES + 1),
        declared_size=1,
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-too-large",)


def test_read_error_is_unsafe(tmp_path: Path):
    snapshot = _snapshot(tmp_path, None, declared_size=10)

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-read-error",)


def test_invalid_utf8_is_unsafe(tmp_path: Path):
    snapshot = _snapshot(tmp_path, b"{\xff}")

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-invalid-utf8",)


def test_parsed_structure_has_a_fixed_node_limit(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path,
        json.dumps({"targets": ["source.cc"] * (MAX_BINDING_GYP_NODES + 1)}),
    )

    result = analyze_native_build_controls((snapshot,))

    assert result.safe is False
    assert result.reasons == ("binding-gyp-analysis-limit",)
