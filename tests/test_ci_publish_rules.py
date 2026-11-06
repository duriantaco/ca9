"""Publish-job rules replayed on real incident workflows, controls and bypass attempts.

Fixtures in ``fixtures/ci_incidents`` are upstream files copied unchanged:
subquery/subql@506863d (publish.yml and its two composite actions), nrwl/nx@400e3003d7
publish.yml, BerriAI/litellm@8a3aa4d3 workflows, TanStack/router@b1c061af release.yml and
cap-js/cds-dbs@6f88226615 release-please.yml. The package.json files are trimmed to the
fields the model reads (packageManager, the publish script, the relevant devDependencies).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ca9 import api

INCIDENTS = Path(__file__).parent / "fixtures" / "ci_incidents"
A = "unpinned_tool_in_credentialed_job"
B = "unverified_download_into_publish"
C = "oidc_publish_without_environment"
D = "publish_on_dispatch_or_any_branch"
SHA = "0123456789abcdef0123456789abcdef01234567"


def _incident(tmp_path: Path, case: str) -> Path:
    source = INCIDENTS / case
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for path in source.iterdir():
        if path.name.endswith(".action.yml"):
            target = tmp_path / ".github" / "actions" / path.name.removesuffix(".action.yml")
            target.mkdir(parents=True)
            shutil.copy(path, target / "action.yml")
        elif path.name == "package.json":
            shutil.copy(path, tmp_path / "package.json")
        else:
            shutil.copy(path, workflows / path.name)
    return tmp_path


def _repo(tmp_path: Path, workflows: dict[str, str], **extra: str) -> Path:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    for name, text in workflows.items():
        (directory / name).write_text(text)
    for rel, text in extra.items():
        target = tmp_path / rel.replace("__", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return tmp_path


def _fired(repo: Path) -> set[tuple[str, str, str]]:
    result = api.audit_workflows(repo)
    assert result["receipt"]["complete"] is True
    return {
        (item["signal_type"], item["file"].rsplit("/", 1)[-1], item["name"])
        for item in result["findings"]
    }


def _by_signal(repo: Path, signal: str) -> list[dict]:
    return [item for item in api.audit_workflows(repo)["findings"] if item["signal_type"] == signal]


def test_subql_release_commit_fires_download_oidc_and_dispatch_rules(tmp_path):
    repo = _incident(tmp_path, "subql")

    fired = _fired(repo)
    download = _by_signal(repo, B)

    assert fired == {
        (B, "publish.yml", "release"),
        (C, "publish.yml", "release"),
        (C, "publish.yml", "prerelease"),
        (D, "publish.yml", ".github/workflows/publish.yml"),
    }
    assert download[0]["action"] == "block"
    assert download[0]["line"] == 168
    assert download[0]["evidence"]["host"] == "ci-artifacts.dev"
    assert download[0]["evidence"]["lands_in"] == "packages/common"
    assert download[0]["evidence"]["replaces_source"] is True


def test_nx_prefix_publish_fires_download_oidc_and_dispatch_but_not_unpinned_tools(tmp_path):
    fired = _fired(_incident(tmp_path, "nx"))

    assert fired == {
        (B, "publish.yml", "publish"),
        (C, "publish.yml", "publish"),
        (D, "publish.yml", ".github/workflows/publish.yml"),
    }


def test_litellm_token_publish_workflows_fire_unpinned_tools_and_dispatch(tmp_path):
    fired = _fired(_incident(tmp_path, "litellm"))

    assert fired == {
        (A, "simple_pypi_publish.yml", "publish"),
        (A, "publish_proxy_extras.yml", "publish"),
        (A, "publish_enterprise.yml", "publish"),
        (D, "simple_pypi_publish.yml", ".github/workflows/simple_pypi_publish.yml"),
        (D, "publish_proxy_extras.yml", ".github/workflows/publish_proxy_extras.yml"),
        (D, "publish_enterprise.yml", ".github/workflows/publish_enterprise.yml"),
    }


def test_tanstack_release_fires_unpinned_npx_oidc_and_wildcard_branch_rules(tmp_path):
    repo = _incident(tmp_path, "tanstack")

    fired = _fired(repo)
    trigger = _by_signal(repo, D)[0]
    tool = _by_signal(repo, A)[0]

    assert fired == {
        (A, "release.yml", "release"),
        (C, "release.yml", "release"),
        (D, "release.yml", ".github/workflows/release.yml"),
    }
    assert [(item["name"], item["line"]) for item in tool["evidence"]["tools"]] == [
        ("nx-cloud", 41),
        ("nx-cloud", 49),
    ]
    assert trigger["severity"] == "MEDIUM"


def test_sap_main_branch_release_with_environment_stays_quiet(tmp_path):
    assert _fired(_incident(tmp_path, "sap")) == set()


def test_sap_attacker_branch_shape_fires_oidc_and_any_branch_rules(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "release-please.yml": """
on: push
permissions:
  id-token: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: |
          TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=npm:registry.npmjs.org")
          echo "$TOKEN" | base64 | base64
"""
        },
    )

    fired = _fired(repo)

    assert fired == {
        (C, "release-please.yml", "release"),
        (D, "release-please.yml", ".github/workflows/release-please.yml"),
    }
    assert _by_signal(repo, D)[0]["severity"] == "HIGH"


HARDENED = f"""
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: release
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@{SHA}
      - uses: actions/setup-node@{SHA}
        with:
          node-version: 22
          registry-url: https://registry.npmjs.org
      - run: npm ci
      - run: npm publish --provenance --access public
"""

CI_ONLY = """
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL https://example.com/install.sh | sh
      - run: pip install ruff
      - run: npm i -g some-cli@latest
      - run: sudo apt-get install -y jq
      - run: npm test
"""


def test_hardened_oidc_release_and_ci_only_tool_installs_stay_quiet(tmp_path):
    repo = _repo(tmp_path, {"release.yml": HARDENED, "ci.yml": CI_ONLY})

    inventory = api.ci_inventory(repo)
    ci_job = next(wf for wf in inventory["workflows"] if wf["file"].endswith("ci.yml"))["jobs"][0]

    assert _fired(repo) == set()
    assert sorted((tool["name"], tool["route"]) for tool in ci_job["tools"]) == [
        ("example.com/install.sh", "curl_pipe"),
        ("jq", "apt"),
        ("ruff", "pip"),
        ("some-cli", "npm"),
    ]


def _publish_job(
    extra_steps: str = "", *, on: str = "on: workflow_dispatch", job_extra: str = ""
) -> str:
    return f"""
{on}
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
{job_extra}    steps:
      - uses: actions/checkout@{SHA}
{extra_steps}      - run: npm publish
"""


def test_environment_from_an_expression_does_not_count_as_protection(tmp_path):
    workflow = _publish_job(job_extra="    environment: ${{ inputs.target }}\n")

    fired = _fired(_repo(tmp_path, {"release.yml": workflow}))

    assert (C, "release.yml", "publish") in fired
    assert (D, "release.yml", ".github/workflows/release.yml") in fired


def test_secrets_passed_through_local_reusable_workflow_still_report(tmp_path):
    caller = """
on: workflow_dispatch
jobs:
  call:
    uses: ./.github/workflows/publish-reusable.yml
    secrets: inherit
"""
    callee = """
on: workflow_call
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm i -g release-helper
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
"""
    repo = _repo(tmp_path, {"release.yml": caller, "publish-reusable.yml": callee})

    fired = _fired(repo)
    inventory = {wf["file"]: wf for wf in api.ci_inventory(repo)["workflows"]}
    callee_wf = inventory[".github/workflows/publish-reusable.yml"]

    assert (A, "publish-reusable.yml", "publish") in fired
    assert (D, "publish-reusable.yml", ".github/workflows/publish-reusable.yml") in fired
    assert inventory[".github/workflows/release.yml"]["jobs"][0]["secrets"]["inherit"] is True
    assert callee_wf["dispatch"] is True
    assert callee_wf["jobs"][0]["secrets"]["inherit"] is True
    assert callee_wf["called_by"] == [".github/workflows/release.yml#call"]


def test_publish_inside_a_visible_composite_action_still_reports(tmp_path):
    workflow = f"""
on:
  push:
    branches: [main]
permissions:
  id-token: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
      - uses: ./.github/actions/ship
        with:
          package-path: packages/core
"""
    action = """
runs:
  using: composite
  steps:
    - run: npm publish --access public
      shell: bash
      working-directory: ${{ inputs.package-path }}
"""
    repo = _repo(
        tmp_path, {"release.yml": workflow}, **{".github__actions__ship__action.yml": action}
    )

    finding = _by_signal(repo, C)
    publish = api.ci_inventory(repo)["workflows"][0]["jobs"][0]["publishes"][0]

    assert [item["name"] for item in finding] == ["release"]
    assert publish["method"] == "oidc"
    assert publish["via_action"]["file"] == ".github/actions/ship/action.yml"


def test_forty_char_non_hex_ref_is_not_pinned(tmp_path):
    fake = "v0.2.2" + "z" * 34
    workflow = _publish_job(
        f"      - uses: aquasecurity/setup-trivy@{fake}\n        with:\n          version: v0.69.3\n"
    )

    inventory = api.ci_inventory(_repo(tmp_path, {"release.yml": workflow}))
    actions = {item["uses"]: item for item in inventory["workflows"][0]["jobs"][0]["actions"]}

    assert len(fake) == 40
    assert actions["aquasecurity/setup-trivy"]["pinned"] is False
    assert actions["actions/checkout"]["pinned"] is True


def test_setup_action_without_version_in_publish_job_fires(tmp_path):
    workflow = _publish_job("      - uses: aquasecurity/setup-trivy@" + SHA + "\n")

    tools = _by_signal(_repo(tmp_path, {"release.yml": workflow}), A)[0]["evidence"]["tools"]

    assert tools == [{"name": "trivy", "route": "setup_action", "line": 10}]


@pytest.mark.parametrize(
    "on",
    [
        "on: [push, workflow_dispatch]",
        "on:\n  workflow_dispatch: {}",
        "on: workflow_dispatch",
        "on: push",
        "on:\n  push:\n    branches-ignore: [gh-pages]",
    ],
)
def test_dispatch_and_any_branch_trigger_shapes_all_report(tmp_path, on):
    findings = _by_signal(_repo(tmp_path, {"release.yml": _publish_job(on=on)}), D)

    assert [item["severity"] for item in findings] == ["HIGH"]


def test_branch_ref_guard_on_publish_job_silences_dispatch_rule(tmp_path):
    guarded = _publish_job(job_extra="    if: github.ref == 'refs/heads/main'\n")
    either = _publish_job(
        job_extra="    if: github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch'\n"
    )

    assert _by_signal(_repo(tmp_path / "a", {"release.yml": guarded}), D) == []
    assert len(_by_signal(_repo(tmp_path / "b", {"release.yml": either}), D)) == 1


def _download_job(check: str) -> str:
    return _publish_job(
        "      - run: |\n"
        "          curl -fsSL -o dist.tgz https://mirror.example.net/pkg/dist.tgz\n"
        f"          {check}\n"
        "          tar xzf dist.tgz -C dist\n",
        on="on:\n  push:\n    branches: [main]",
        job_extra="    environment: release\n",
    )


def test_checksum_print_is_not_verification_but_checksum_check_is(tmp_path):
    printed = _by_signal(_repo(tmp_path / "a", {"r.yml": _download_job("sha256sum dist.tgz")}), B)
    checked = _by_signal(
        _repo(tmp_path / "b", {"r.yml": _download_job("sha256sum -c dist.tgz.sha256")}), B
    )

    assert [item["evidence"]["host"] for item in printed] == ["mirror.example.net"]
    assert checked == []


def test_executed_download_in_tmp_is_a_tool_not_a_published_file(tmp_path):
    workflow = _publish_job(
        "      - run: |\n"
        "          curl -fsSL -o /tmp/helper https://tools.example.org/helper\n"
        "          chmod +x /tmp/helper\n",
        on="on:\n  push:\n    branches: [main]",
        job_extra="    environment: release\n",
    )

    repo = _repo(tmp_path, {"r.yml": workflow})

    assert _by_signal(repo, B) == []
    assert [tool["name"] for tool in _by_signal(repo, A)[0]["evidence"]["tools"]] == ["helper"]


def test_gitlab_oidc_publish_without_environment_and_unpinned_apt(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        """
publish:
  image: node:22
  id_tokens:
    NPM_ID_TOKEN:
      aud: npm:registry.npmjs.org
  script:
    - apt-get install -y curl
    - npm publish
lint:
  script:
    - pip install ruff
    - ruff check .
"""
    )

    result = api.audit_workflows(tmp_path)
    fired = {(item["signal_type"], item["name"]) for item in result["findings"]}

    assert fired == {(A, "publish"), (C, "publish")}
    assert {item["ecosystem"] for item in result["findings"]} == {"gitlab-ci"}


def test_finding_shape_matches_package_findings(tmp_path):
    finding = api.audit_workflows(_incident(tmp_path, "subql"))["findings"][0]

    assert set(finding) == {
        "signal_type",
        "severity",
        "action",
        "ecosystem",
        "name",
        "version",
        "title",
        "reason",
        "remediation",
        "evidence",
        "file",
        "line",
    }
    assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert finding["action"] in {"block", "warn", "investigate"}
    json.dumps(finding)


def test_publish_hidden_in_a_publish_named_package_script_still_counts(tmp_path):
    workflow = """
on:
  push:
    branches: [main, "v[0-9]*"]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: pnpm run ci-publish "$TAG"
"""
    repo = _repo(
        tmp_path,
        {"publish.yml": workflow},
        **{"package.json": '{"scripts": {"ci-publish": "tsx scripts/publishCI.ts"}}'},
    )

    publish = api.ci_inventory(repo)["workflows"][0]["jobs"][0]["publishes"]

    assert [(item["registry"], item["method"], item["via"]) for item in publish] == [
        ("npm", "oidc", "script_name:ci-publish")
    ]
    assert _fired(repo) == {
        (C, "publish.yml", "publish"),
        (D, "publish.yml", ".github/workflows/publish.yml"),
    }
