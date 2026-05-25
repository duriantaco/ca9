from __future__ import annotations

import json

from ca9.hunt import (
    apply_fuzz_introspector_summary,
    generate_atheris_harnesses,
    generate_research_packets,
    hunt_report_to_json,
    scan_hunt_targets,
)


def test_scan_hunt_targets_ranks_parser_with_risky_sink(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "parser.py").write_text(
        """
import json
import subprocess


def parse_payload(payload: str):
    obj = json.loads(payload)
    if obj.get("cmd"):
        subprocess.run(obj["cmd"])
    return obj


def helper(value):
    return value
"""
    )

    report = scan_hunt_targets(repo)

    assert report.targets
    top = report.targets[0]
    assert top.function_name == "parse_payload"
    assert top.priority == "high"
    assert top.harness_kind == "atheris"
    assert "parser" in top.sinks
    assert "command_execution" in top.sinks

    data = json.loads(hunt_report_to_json(report))
    assert data["schema_version"] == "ca9.hunt.v1"
    assert data["summary"]["targets"] >= 1


def test_generate_atheris_harnesses_writes_reviewable_skeleton(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "parser.py").write_text(
        """
import json


def load_body(body: bytes):
    return json.loads(body.decode("utf-8"))
"""
    )

    report = scan_hunt_targets(repo)
    report = generate_atheris_harnesses(report, repo / "fuzz_harnesses")

    assert len(report.generated_harnesses) == 1
    assert report.private_artifact_root == str(repo / "fuzz_harnesses")
    assert (repo / "fuzz_harnesses" / ".gitignore").read_text() == "*\n!.gitignore\n"
    harness = (repo / "fuzz_harnesses").glob("fuzz_*.py")
    text = next(harness).read_text()
    assert "atheris.Setup" in text
    assert "TARGET_RELATIVE = 'parser.py'" in text
    assert "INPUT_PARAMETER = 'body'" in text


def test_generate_research_packets_writes_private_handoff_without_payloads(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "parser.py").write_text(
        """
import json


def parse_payload(payload: str):
    return json.loads(payload)
"""
    )

    report = scan_hunt_targets(repo)
    report = generate_research_packets(
        report,
        repo / "research_packets",
        scope="owned repo",
        recipient="security@example.test",
    )

    packet_dir = repo / "research_packets"
    assert (packet_dir / ".gitignore").read_text() == "*\n!.gitignore\n"
    assert report.summary()["research_packets"] == 2
    assert str(packet_dir) in report.private_artifact_roots
    manifest = json.loads((packet_dir / "manifest.json").read_text())
    assert manifest["schema_version"] == "ca9.research_packet.v1"
    assert manifest["candidate_count"] == 1
    packet = next(path for path in packet_dir.glob("candidate_*.md"))
    text = packet.read_text()
    assert "Authorized scope: owned repo" in text
    assert "Intended recipient: security@example.test" in text
    assert "This packet intentionally omits exploit payloads and crash inputs." in text


def test_scan_hunt_targets_skips_tests_by_default(tmp_path):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (tests / "test_parser.py").write_text(
        """
import json


def parse_payload(payload: str):
    return json.loads(payload)
"""
    )

    assert scan_hunt_targets(repo).targets == ()
    assert scan_hunt_targets(repo, include_tests=True).targets


def test_hunt_scan_and_harness_generation_do_not_open_network_sockets(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "parser.py").write_text(
        """
import json


def parse_payload(payload: str):
    return json.loads(payload)
"""
    )

    def blocked_socket(*args, **kwargs):
        raise AssertionError("hunt must not open network sockets")

    monkeypatch.setattr("socket.socket", blocked_socket)

    report = scan_hunt_targets(repo)
    report = generate_atheris_harnesses(report, repo / "private_harnesses")

    assert report.targets
    assert report.generated_harnesses


def test_apply_fuzz_introspector_summary_boosts_unreached_sink(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "parser.py").write_text(
        """
import json


def parse_payload(payload: str):
    return json.loads(payload)
"""
    )
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            {
                "analyses": {
                    "SinkCoverageAnalyser": [
                        {
                            "func_name": "parse_payload",
                            "filename": "parser.py",
                            "call_loc": "Not in call tree",
                            "fuzzer_reach": [],
                        }
                    ]
                }
            }
        )
    )

    report = scan_hunt_targets(repo)
    enriched = apply_fuzz_introspector_summary(report, summary)

    assert enriched.targets[0].fuzz_introspector == {
        "reach_state": "not_reached",
        "reached_by_fuzzers": [],
        "source": str(summary),
    }
    assert any(s.kind == "fuzz_introspector.sink" for s in enriched.targets[0].signals)
