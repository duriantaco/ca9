from __future__ import annotations

import json

from click.testing import CliRunner

from ca9.cli import main
from ca9.ingest.sarif import evidence_report_to_table, load_sarif_report, sarif_to_evidence_report


def _sample_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.17.0",
                        "informationUri": "https://codeql.github.com/",
                        "rules": [
                            {
                                "id": "py/path-injection",
                                "name": "Uncontrolled data used in path expression",
                                "shortDescription": {"text": "Path injection"},
                                "fullDescription": {
                                    "text": "User-controlled data is used in a filesystem path."
                                },
                                "defaultConfiguration": {"level": "warning"},
                                "properties": {
                                    "security-severity": "7.5",
                                    "precision": "high",
                                    "tags": ["security", "external/cwe/cwe-022"],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/path-injection",
                        "ruleIndex": 0,
                        "level": "warning",
                        "message": {"text": "User-controlled path reaches open()."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 42, "startColumn": 13},
                                }
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                    }
                ],
            }
        ],
    }


def test_sarif_to_evidence_report_preserves_tool_rule_and_location(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    report = sarif_to_evidence_report(
        _sample_sarif(),
        source_path=tmp_path / "codeql.sarif",
        repo_path=repo,
    )

    assert report.summary()["findings"] == 1
    assert report.tool_runs[0].name == "CodeQL"
    assert report.target_key == "repo:repo"

    finding = report.findings[0]
    assert finding.signal_type == "static_analysis"
    assert finding.severity == "high"
    assert finding.signals[0].confidence == "high"
    assert finding.metadata["rule"]["id"] == "py/path-injection"
    assert finding.metadata["location"]["uri"] == "app.py"
    assert finding.metadata["location"]["start_line"] == 42
    assert finding.metadata["sarif"]["partial_fingerprints"]["primaryLocationLineHash"] == "abc123"


def test_sarif_table_output_is_human_readable(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    report = sarif_to_evidence_report(_sample_sarif(), repo_path=repo)

    table = evidence_report_to_table(report)

    assert "ca9 evidence report" in table
    assert "[HIGH] CodeQL py/path-injection app.py:42:13" in table
    assert "User-controlled path reaches open()." in table


def test_load_sarif_report_from_file(tmp_path):
    path = tmp_path / "sample.sarif"
    path.write_text(json.dumps(_sample_sarif()))

    report = load_sarif_report(path, repo_path=tmp_path)

    assert report.source_path == str(path)
    assert report.summary()["by_severity"] == {"high": 1}


def test_sarif_rule_reference_can_point_to_tool_extension(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "CodeQL"},
                    "extensions": [
                        {
                            "name": "python-queries",
                            "rules": [
                                {
                                    "id": "py/unsafe-deserialization",
                                    "shortDescription": {"text": "Unsafe deserialization"},
                                    "properties": {
                                        "security-severity": "9.1",
                                        "precision": "very-high",
                                    },
                                }
                            ],
                        }
                    ],
                },
                "results": [
                    {
                        "ruleId": "py/unsafe-deserialization",
                        "rule": {
                            "index": 0,
                            "toolComponent": {"index": 0},
                        },
                        "message": {"text": "pickle.loads receives attacker input."},
                    }
                ],
            }
        ],
    }

    report = sarif_to_evidence_report(sarif, repo_path=repo)

    finding = report.findings[0]
    assert finding.severity == "critical"
    assert finding.signals[0].confidence == "high"
    assert finding.metadata["rule"]["short_description"] == "Unsafe deserialization"


def test_sarif_rule_reference_id_is_preserved_without_top_level_rule_id(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/path-injection",
                                "properties": {"security-severity": "7.5"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "rule": {"id": "py/path-injection"},
                        "message": {"text": "User-controlled path reaches open()."},
                    }
                ],
            }
        ],
    }

    report = sarif_to_evidence_report(sarif, repo_path=repo)

    finding = report.findings[0]
    assert finding.metadata["rule"]["id"] == "py/path-injection"
    assert finding.metadata["sarif"]["rule_id"] == "py/path-injection"
    assert finding.severity == "high"


def test_sarif_missing_result_level_defaults_to_warning(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "PMD", "rules": [{"id": "UnusedPrivateField"}]}},
                "results": [
                    {
                        "ruleId": "UnusedPrivateField",
                        "message": {"text": "Avoid unused private fields."},
                    }
                ],
            }
        ],
    }

    report = sarif_to_evidence_report(sarif, repo_path=repo)

    assert report.findings[0].severity == "medium"


def test_sarif_fingerprint_is_stable_across_result_order_and_tool_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    base_result = {
        "ruleId": "py/path-injection",
        "ruleIndex": 0,
        "level": "warning",
        "message": {"text": "User-controlled path reaches open()."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 42},
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": "abc123"},
    }
    dummy_result = {
        "ruleId": "py/other",
        "ruleIndex": 1,
        "level": "note",
        "message": {"text": "Different result."},
    }
    sarif_a = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.17.0",
                        "rules": [{"id": "py/path-injection"}, {"id": "py/other"}],
                    }
                },
                "results": [base_result],
            }
        ],
    }
    sarif_b = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.18.0",
                        "rules": [{"id": "py/path-injection"}, {"id": "py/other"}],
                    }
                },
                "results": [dummy_result, base_result],
            }
        ],
    }

    finding_a = sarif_to_evidence_report(sarif_a, repo_path=repo).findings[0]
    finding_b = sarif_to_evidence_report(sarif_b, repo_path=repo).findings[1]

    assert finding_a.fingerprint == finding_b.fingerprint
    assert finding_a.signals[0].key == finding_b.signals[0].key
    assert finding_b.metadata["sarif"]["result_index"] == 1


def test_sarif_fingerprint_ignores_preserved_snippet_when_fingerprints_exist(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def sarif_with_snippet(snippet: str) -> dict:
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [{"id": "py/path-injection"}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/path-injection",
                            "ruleIndex": 0,
                            "level": "warning",
                            "message": {"text": "User-controlled path reaches open()."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {
                                            "startLine": 42,
                                            "snippet": {"text": snippet},
                                        },
                                    }
                                }
                            ],
                            "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                        }
                    ],
                }
            ],
        }

    finding_a = sarif_to_evidence_report(sarif_with_snippet("open(path)"), repo_path=repo).findings[
        0
    ]
    finding_b = sarif_to_evidence_report(
        sarif_with_snippet("open(user_controlled_path)"),
        repo_path=repo,
    ).findings[0]

    assert finding_a.fingerprint == finding_b.fingerprint
    assert finding_b.metadata["location"]["snippet"] == "open(user_controlled_path)"


def test_sarif_tool_metadata_drops_missing_optional_fields(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [{"id": "python.audit.subprocess-shell-true"}],
                    }
                },
                "results": [
                    {
                        "ruleId": "python.audit.subprocess-shell-true",
                        "ruleIndex": 0,
                        "message": {"text": "subprocess called with shell=True"},
                    }
                ],
            }
        ],
    }

    report = sarif_to_evidence_report(sarif, repo_path=repo)

    finding = report.findings[0]
    assert finding.metadata["tool"] == {"name": "Semgrep"}
    assert finding.evidence[0].metadata["tool"] == {"name": "Semgrep"}


def test_ingest_sarif_cli_json(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    path = tmp_path / "sample.sarif"
    path.write_text(json.dumps(_sample_sarif()))

    runner = CliRunner()
    result = runner.invoke(main, ["ingest-sarif", str(path), "--repo", str(repo), "-f", "json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "ca9.evidence.v1"
    assert data["summary"]["findings"] == 1
    assert data["findings"][0]["metadata"]["tool"]["name"] == "CodeQL"
