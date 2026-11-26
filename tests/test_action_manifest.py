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

    assert "Use scan, check, protect, or review." in action
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
    outputs.write_text("")
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


def test_default_scan_report_inputs_still_write_sarif(tmp_path):
    (tmp_path / "input.json").write_text('{"Results": []}')
    run, outputs = run_action_step(tmp_path, CA9_FORMAT="", CA9_OUTPUT="")
    assert run.returncode == 0, run.stderr
    assert "report-written=true" in outputs
    assert json.loads((tmp_path / "ca9.sarif").read_text())["version"] == "2.1.0"


@pytest.fixture
def review_inputs(tmp_path):
    checkout = tmp_path / "source checkout"
    checkout.mkdir()

    def git(*args):
        return subprocess.run(
            [
                "git",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "user.name=Test",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *args,
            ],
            cwd=checkout,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

    git("init", "-q")
    lock = checkout / "package-lock.json"
    commits = []
    for version in ("1.0.0", "1.1.0"):
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"widget": version}},
                        "node_modules/widget": {"version": version},
                    },
                }
            )
        )
        git("add", "package-lock.json")
        git("commit", "-qm", version)
        commits.append(git("rev-parse", "HEAD"))
    base, head = commits
    # Simulate a checkout different from the PR head. Only the event commits describe the change.
    git("checkout", "-q", "--detach", base)
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}))
    return {
        "CA9_COMMAND": "review",
        "CA9_REPO": checkout.name,
        "CA9_FORMAT": "",
        "CA9_OUTPUT": "",
        "CA9_EXTRA_ARGS": "--no-scan-artifacts",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }


@pytest.mark.parametrize("fmt,filename", [("", "ca9-review.json"), ("markdown", "ca9-review.md")])
def test_action_reviews_event_commits_and_preserves_findings_exit(
    tmp_path, review_inputs, fmt, filename
):
    review_inputs["CA9_FORMAT"] = fmt
    step, outputs = run_action_step(tmp_path, **review_inputs)
    assert step.returncode == 0, step.stderr
    values = dict(line.split("=", 1) for line in outputs)
    assert values["exit-code"] == "2"
    assert values["report-written"] == "true"
    assert (tmp_path / values["output-path"]).resolve() == tmp_path / filename
    content = (tmp_path / filename).read_text()
    if fmt == "":
        report = json.loads(content)
        event = json.loads(Path(review_inputs["GITHUB_EVENT_PATH"]).read_text())["pull_request"]
        assert report["base"] == event["base"]["sha"]
        assert report["head"] == event["head"]["sha"]
        assert report["exit_code"] == 2
        [lock] = report["lockfiles"]
        assert lock["path"] == "package-lock.json"
        assert lock["report"]["summary"]["packages_changed"] == 1
    else:
        assert "package-lock.json" in content
        assert "widget" in content
    assert "review" in (tmp_path / "summary.md").read_text().lower()
    assert not (tmp_path / "ca9.sarif").exists()


def test_review_no_lock_changes_publishes_to_custom_path(tmp_path, review_inputs):
    event = Path(review_inputs["GITHUB_EVENT_PATH"])
    payload = json.loads(event.read_text())
    payload["pull_request"]["head"]["sha"] = payload["pull_request"]["base"]["sha"]
    event.write_text(json.dumps(payload))
    review_inputs["CA9_OUTPUT"] = "artifacts/dependency review.json"
    step, outputs = run_action_step(tmp_path, **review_inputs)
    assert step.returncode == 0, step.stderr
    assert "exit-code=0" in outputs
    assert "report-written=true" in outputs
    assert json.loads((tmp_path / review_inputs["CA9_OUTPUT"]).read_text())["exit_code"] == 0


@pytest.mark.parametrize(
    "error", ["push", "pull_request_target", "missing_commit", "outside_workspace"]
)
def test_review_errors_cannot_publish_stale_reports(tmp_path, review_inputs, error):
    if error in ("push", "pull_request_target"):
        review_inputs["GITHUB_EVENT_NAME"] = error
    elif error == "missing_commit":
        event = Path(review_inputs["GITHUB_EVENT_PATH"])
        payload = json.loads(event.read_text())
        payload["pull_request"]["base"]["sha"] = "a" * 40
        event.write_text(json.dumps(payload))
    else:
        review_inputs["CA9_REPO"] = ".."
    previous = tmp_path / "ca9-review.json"
    previous.write_text("old report")
    step, outputs = run_action_step(tmp_path, **review_inputs)
    assert step.returncode != 0
    assert "report-written=true" not in outputs
    assert not any(row.startswith("output-path=") for row in outputs)
    assert previous.read_text() == "old report"


def test_review_uses_shared_findings_gate_and_skips_sarif_upload():
    manifest = (ROOT / "action.yml").read_text()
    upload, gate = manifest.split("    - name: Upload SARIF\n", 1)[1].split(
        "    - name: Enforce ca9 result\n", 1
    )
    assert "inputs.command != 'review'" in upload
    assert "steps.ca9.outputs.report-written == 'true'" in upload
    assert "inputs.fail-on-findings == 'true' && steps.ca9.outputs.exit-code != '0'" in gate
    assert 'run: exit "${{ steps.ca9.outputs.exit-code }}"' in gate


@pytest.mark.parametrize(
    "path",
    [
        "reports/new.json",
        "bad\nreport-written=true",
        "https://example.invalid/report.json",
    ],
)
def test_review_rejects_invalid_output_locations(tmp_path, tmp_path_factory, review_inputs, path):
    outside = tmp_path_factory.mktemp("outside-workspace")
    (tmp_path / "reports").symlink_to(outside, target_is_directory=True)
    review_inputs["CA9_OUTPUT"] = path
    step, outputs = run_action_step(tmp_path, **review_inputs)
    assert step.returncode != 0, step.stderr
    assert not (tmp_path / path).exists()
    assert not (outside / "new.json").exists()
    assert not any(row.startswith(("report-written=true", "output-path=")) for row in outputs)
