from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ca9.cli import main
from ca9.review.render import write_json, write_markdown


@dataclass
class ExampleReport:
    decision: str = "pass"
    complete: bool = True
    exit_code: int = 0

    def to_dict(self):
        return {
            "schema_version": "ca9.dependency-review.v1",
            "base": "base-package-lock.json",
            "head": "package-lock.json",
            "decision": self.decision,
            "complete": self.complete,
            "exit_code": self.exit_code,
            "scope": {"ecosystem": "npm", "executes_package_code": False},
            "summary": {
                "packages_added": 0,
                "packages_removed": 0,
                "packages_changed": 1,
                "packages_unchanged": 2,
                "packages_reviewed": 1,
            },
            "issues": [] if self.complete else ["Head artifact unavailable."],
            "packages": [
                {
                    "path": "node_modules/example",
                    "status": "changed",
                    "base": {"name": "example", "version": "1.0.0"},
                    "head": {"name": "example", "version": "1.1.0"},
                    "base_inspection": {"status": "complete", "issues": []},
                    "head_inspection": {
                        "status": "complete" if self.complete else "uninspectable",
                        "issues": [] if self.complete else ["Artifact unavailable."],
                    },
                    "deltas": [
                        {
                            "kind": "lifecycle_script",
                            "key": "postinstall",
                            "status": "added",
                            "base": None,
                            "head": "node setup.js",
                            "action": "review",
                            "reason": "New install hook.",
                        },
                        {
                            "kind": "entry_point",
                            "key": "main",
                            "status": "unchanged",
                            "base": "index.js",
                            "head": "index.js",
                            "action": "info",
                            "reason": "Unchanged declaration.",
                        },
                    ],
                }
            ],
        }


@pytest.fixture
def lock_paths(tmp_path: Path) -> tuple[Path, Path]:
    paths = (tmp_path / "base.json", tmp_path / "head.json")
    for path in paths:
        path.write_text('{"lockfileVersion": 3, "packages": {"": {}}}')
    return paths


def test_review_command_is_registered():
    result = CliRunner().invoke(main, ["review", "--help"])
    assert result.exit_code == 0
    assert "--base" in result.output
    assert "--no-scan-artifacts" in result.output
    assert "without executing package code" in result.output


@pytest.mark.parametrize(
    ("decision", "complete", "exit_code"),
    [("pass", True, 0), ("review", True, 1), ("block", False, 1), ("incomplete", False, 2)],
)
def test_review_json_and_exit_code(lock_paths, decision, complete, exit_code):
    base, head = lock_paths
    report = ExampleReport(decision, complete, exit_code)
    with patch("ca9.review.service.review_lockfiles", return_value=report) as review:
        result = CliRunner().invoke(
            main, ["review", "--base", str(base), "--head", str(head), "-f", "json"]
        )
    assert result.exit_code == exit_code
    assert json.loads(result.output) == report.to_dict()
    review.assert_called_once_with(
        base,
        head,
        cache_dir=None,
        trusted_registries=("https://registry.npmjs.org",),
        scan_artifacts=True,
    )


def test_review_options_and_report_file(lock_paths, tmp_path):
    base, head = lock_paths
    output = tmp_path / "reports" / "review.json"
    cache = tmp_path / "artifacts"
    with patch("ca9.review.service.review_lockfiles", return_value=ExampleReport()) as review:
        result = CliRunner().invoke(
            main,
            [
                "review",
                "--base",
                str(base),
                "--head",
                str(head),
                "--cache-dir",
                str(cache),
                "--trusted-registry",
                "https://packages.example.org",
                "--trusted-registry",
                "https://registry.npmjs.org",
                "--no-scan-artifacts",
                "-f",
                "json",
                "-o",
                str(output),
            ],
        )
    assert result.exit_code == 0
    assert result.output == ""
    assert json.loads(output.read_text())["schema_version"] == "ca9.dependency-review.v1"
    review.assert_called_once_with(
        base,
        head,
        cache_dir=cache,
        trusted_registries=("https://registry.npmjs.org", "https://packages.example.org"),
        scan_artifacts=False,
    )


def test_review_defaults_to_markdown_and_reports_incomplete_evidence(lock_paths):
    base, head = lock_paths
    with patch(
        "ca9.review.service.review_lockfiles", return_value=ExampleReport("incomplete", False, 2)
    ):
        result = CliRunner().invoke(main, ["review", "--base", str(base), "--head", str(head)])
    assert result.exit_code == 2
    assert result.output.startswith("# Dependency update review\n")
    assert "**incomplete**" in result.output
    assert "Head artifact unavailable." in result.output
    assert "postinstall" in result.output
    assert "1 unchanged observation(s) omitted" in result.output
    assert "index.js" not in result.output


def test_review_rejects_invalid_lockfile(lock_paths):
    base, head = lock_paths
    with patch(
        "ca9.review.service.review_lockfiles",
        side_effect=ValueError("Unsupported lockfile version"),
    ):
        result = CliRunner().invoke(main, ["review", "--base", str(base), "--head", str(head)])
    assert result.exit_code == 2
    assert "Unsupported lockfile version" in result.output
    assert "Traceback" not in result.output


def test_review_requires_existing_file_inputs(tmp_path):
    with patch("ca9.review.service.review_lockfiles") as review:
        result = CliRunner().invoke(
            main, ["review", "--base", str(tmp_path), "--head", str(tmp_path / "missing.json")]
        )
    assert result.exit_code == 2
    review.assert_not_called()


def test_review_empty_lockfiles_pass_without_artifact_downloads(lock_paths):
    base, head = lock_paths
    with patch("ca9.review.service.collect_artifact_snapshots") as collect:
        result = CliRunner().invoke(
            main, ["review", "--base", str(base), "--head", str(head), "-f", "json"]
        )
    assert result.exit_code == 0
    assert json.loads(result.output)["decision"] == "pass"
    collect.assert_not_called()


def test_review_metadata_mode_marks_changed_behavior_incomplete(lock_paths):
    base, head = lock_paths
    for path, version in ((base, "1.0.0"), (head, "1.1.0")):
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"example": version}},
                        "node_modules/example": {
                            "version": version,
                            "resolved": f"https://registry.npmjs.org/example/-/example-{version}.tgz",
                            "integrity": "sha512-" + "A" * 86 + "==",
                        },
                    },
                }
            )
        )
    with patch("ca9.review.service.collect_artifact_snapshots") as collect:
        result = CliRunner().invoke(
            main,
            [
                "review",
                "--base",
                str(base),
                "--head",
                str(head),
                "--no-scan-artifacts",
                "-f",
                "json",
            ],
        )
    assert result.exit_code == 2
    data = json.loads(result.output)
    assert data["decision"] == "incomplete"
    assert data["summary"]["packages_changed"] == 1
    assert data["packages"][0]["head_inspection"]["status"] == "incomplete"
    collect.assert_not_called()


def test_markdown_escapes_untrusted_fields_and_json_preserves_data():
    hostile = "<img src=x> [link](https://example.org) | `x`\n## forged\x1b[31m\u202e"
    data = ExampleReport().to_dict()
    data["base"] = hostile
    data["issues"] = [hostile]
    data["packages"][0]["path"] = hostile
    data["packages"][0]["head"]["name"] = hostile
    data["packages"][0]["deltas"][0]["head"] = hostile
    with patch.object(ExampleReport, "to_dict", return_value=data):
        markdown = write_markdown(ExampleReport())
        serialized = write_json(ExampleReport())
    assert "<img" not in markdown
    assert "[link](" not in markdown
    assert "`x`" not in markdown
    assert "\n## forged" not in markdown
    assert "\x1b" not in markdown
    assert "\u202e" not in markdown
    assert "&lt;img src=x&gt;" in markdown
    assert "\\|" in markdown
    assert json.loads(serialized) == data
    assert "\x1b" not in serialized
    assert "\u202e" not in serialized


def test_json_is_stable_across_dictionary_insertion_order():
    report = ExampleReport()
    expected = write_json(report)
    data = dict(reversed(list(report.to_dict().items())))
    with patch.object(ExampleReport, "to_dict", return_value=data):
        assert write_json(report) == expected
