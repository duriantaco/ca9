import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_composite_action_exposes_protect_command_inputs():
    action = (Path(__file__).parents[1] / "action.yml").read_text()

    assert "Use scan, check, or protect." in action
    assert "CA9_POLICY: ${{ inputs.policy }}" in action
    assert "CA9_SCAN_WORKFLOWS: ${{ inputs.scan-workflows }}" in action
    assert '"$CA9_COMMAND" != "protect"' in action
    assert 'if [[ "$CA9_COMMAND" == "protect" ]]; then' in action
    assert 'cmd+=(--policy "$CA9_POLICY")' in action
    assert "cmd+=(--no-scan-workflows)" in action


def test_composite_action_coverage_generation_is_opt_in():
    action = (Path(__file__).parents[1] / "action.yml").read_text()

    block = action.split("  auto-coverage:\n", 1)[1].split("\n  no-auto-coverage:", 1)[0]
    assert 'default: "false"' in block
    assert "CA9_AUTO_COVERAGE: ${{ inputs.auto-coverage }}" in action
    assert 'elif [[ "$CA9_AUTO_COVERAGE" == "true" ]]; then' in action
    assert "cmd+=(--auto-coverage)" in action
    # The deprecated input still parses and is passed through as a no-op.
    assert "CA9_NO_AUTO_COVERAGE: ${{ inputs.no-auto-coverage }}" in action
    assert "cmd+=(--no-auto-coverage)" in action


def run_action_step(tmp_path, **inputs):
    action = (ROOT / "action.yml").read_text()
    step = action.split("    - name: Run ca9\n", 1)[1].split("    - name: Upload SARIF\n", 1)[0]
    body = textwrap.dedent(step.split("      run: |\n", 1)[1])
    env = {key: "" for key in re.findall(r"^        (CA9_[A-Z_]+):", step, re.MULTILINE)}
    env.update(
        CA9_COMMAND="check",
        CA9_REPORT="input.json",
        CA9_FORMAT="sarif",
        CA9_REPO=".",
        CA9_PROOF_STANDARD="strict",
        CA9_OUTPUT="out/report",
    )
    env.update(inputs)
    outputs = tmp_path / "step_outputs"
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", body],
        cwd=tmp_path,
        env={
            **os.environ,
            **env,
            "GITHUB_OUTPUT": str(outputs),
            "GITHUB_ACTION_PATH": str(ROOT),
            "CA9_CACHE_DIR": str(tmp_path / "cache"),
            "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.environ["PATH"])),
            "PYTHONPATH": str(ROOT / "src"),
        },
        text=True,
        capture_output=True,
    )
    return result, outputs.read_text().splitlines()


@pytest.mark.parametrize(
    "fmt", ["sarif", "json", "vex", "remediation", "action-plan", "markdown", "html", "table"]
)
def test_action_publishes_clean_reports(tmp_path, fmt):
    (tmp_path / "input.json").write_text('{"Results": []}')
    step, outputs = run_action_step(tmp_path, CA9_FORMAT=fmt)
    assert step.returncode == 0, step.stderr
    assert outputs == ["exit-code=0", "report-written=true"]
    content = (tmp_path / "out/report").read_text()
    assert content
    if fmt == "sarif":
        assert json.loads(content)["runs"][0]["results"] == []


def test_action_keeps_inconclusive_report_for_optional_gate(tmp_path):
    finding = {"VulnerabilityID": "TEST-1", "PkgName": "sample", "InstalledVersion": "1.0"}
    (tmp_path / "input.json").write_text(
        json.dumps({"Results": [{"Type": "npm", "Vulnerabilities": [finding]}]})
    )
    step, outputs = run_action_step(tmp_path)
    assert step.returncode == 0, step.stderr
    assert outputs == ["exit-code=2", "report-written=true"]
    assert json.loads((tmp_path / "out/report").read_text())["runs"][0]["results"]


def test_action_keeps_blocking_posture_report_for_optional_gate(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"example"}')
    step, outputs = run_action_step(tmp_path, CA9_COMMAND="protect", CA9_FORMAT="json")
    assert step.returncode == 0, step.stderr
    assert outputs == ["exit-code=1", "report-written=true"]
    assert json.loads((tmp_path / "out/report").read_text())["summary"]["status"] == "block"


@pytest.mark.parametrize("invalid_input", [None, "{"])
def test_action_fails_without_publishing_previous_report(tmp_path, invalid_input):
    if invalid_input is not None:
        (tmp_path / "input.json").write_text(invalid_input)
    old_report = tmp_path / "out/report"
    old_report.parent.mkdir()
    old_report.write_text("previous report")
    step, outputs = run_action_step(tmp_path)
    assert step.returncode in (1, 2)
    assert outputs == [f"exit-code={step.returncode}"]
    assert old_report.read_text() == "previous report"


def test_action_requires_a_report_even_for_exit_zero(tmp_path):
    step, outputs = run_action_step(tmp_path, CA9_EXTRA_ARGS="--help")
    assert step.returncode != 0
    assert "did not produce a report" in step.stderr
    assert outputs == ["exit-code=0"]
    assert not (tmp_path / "out/report").exists()


def test_action_checks_arguments_on_every_line(tmp_path):
    (tmp_path / "input.json").write_text('{"Results": []}')
    step, outputs = run_action_step(tmp_path, CA9_EXTRA_ARGS="--verbose\n--invalid-second-line")
    assert step.returncode != 0
    assert "--invalid-second-line" in step.stderr
    assert "report-written=true" not in outputs
