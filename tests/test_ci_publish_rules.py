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


R = "credentials_to_remote_reusable_workflow"


def _quoted(condition: str) -> str:
    return "'" + condition.replace("'", "''") + "'"


@pytest.mark.parametrize(
    ("condition", "fires"),
    [
        ("${{ !(github.ref == 'refs/heads/main') }}", True),
        ("github.ref != 'refs/heads/main'", True),
        ("!(github.ref != 'refs/heads/main')", False),
        ("github.ref_name == 'main'", True),
        ("startsWith(github.ref, 'refs/heads/') && github.ref_name == 'main'", False),
        ("github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'", False),
        ("${{ github.ref == 'refs/heads/main' }} && true", True),
        ('github.ref == "refs/heads/main"', True),
    ],
)
def test_only_conditions_that_prove_the_release_branch_silence_dispatch(tmp_path, condition, fires):
    workflow = _publish_job(job_extra=f"    if: {_quoted(condition)}\n")

    findings = _by_signal(_repo(tmp_path, {"release.yml": workflow}), D)

    assert len(findings) == int(fires)


@pytest.mark.parametrize(
    ("on", "condition", "fires"),
    [
        ("on: repository_dispatch", None, True),
        ("on: pull_request_target", None, True),
        ("on: pull_request_target", "github.ref == 'refs/heads/main'", True),
        ("on: issue_comment", None, True),
        (
            "on:\n  push:\n    branches: [main]\n  pull_request_target:",
            "github.event_name != 'pull_request_target'",
            False,
        ),
    ],
)
def test_publish_jobs_started_by_outside_events_report(tmp_path, on, condition, fires):
    extra = ""
    if condition:
        extra = f"    if: {_quoted(condition)}\n"
    workflow = _publish_job(on=on, job_extra=extra)

    findings = _by_signal(_repo(tmp_path, {"release.yml": workflow}), D)

    assert [item["severity"] for item in findings] == ["HIGH"] * int(fires)


def _remote_caller(ref: str, extra: str) -> str:
    return f"""
on:
  push:
    branches: [main]
jobs:
  release:
{extra}    uses: org/shared/.github/workflows/release.yml@{ref}
"""


@pytest.mark.parametrize(
    ("ref", "extra", "handed"),
    [
        ("main", "    secrets: inherit\n", ["all secrets (secrets: inherit)"]),
        (SHA, "    secrets: inherit\n", ["all secrets (secrets: inherit)"]),
        ("v1", "    permissions:\n      id-token: write\n", ["id-token: write"]),
        ("v1", "    secrets:\n      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n", ["NPM_TOKEN"]),
    ],
)
def test_credentials_handed_to_a_remote_reusable_workflow_are_an_explicit_unknown(
    tmp_path, ref, extra, handed
):
    repo = _repo(tmp_path, {"release.yml": _remote_caller(ref, extra)})

    result = api.audit_workflows(repo)
    job = api.ci_inventory(repo)["workflows"][0]["jobs"][0]
    findings = [item for item in result["findings"] if item["signal_type"] == R]

    assert [(item["action"], item["evidence"]["credentials"]) for item in findings] == [
        ("investigate", handed)
    ]
    assert findings[0]["evidence"]["pinned"] is (ref == SHA)
    assert job["remote_reusable"] is True
    assert result["receipt"]["complete"] is False
    assert result["receipt"]["incomplete_reasons"] == ["remote_reusable_workflow"]


def test_remote_call_without_credentials_is_still_unknown_but_local_calls_are_not(tmp_path):
    remote = _repo(tmp_path / "remote", {"lint.yml": _remote_caller("v1", "")})
    local = _repo(
        tmp_path / "local",
        {
            "ci.yml": "on: push\njobs:\n  call:\n    uses: ./.github/workflows/lint.yml\n",
            "lint.yml": "on: workflow_call\njobs:\n  lint:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo lint\n",
        },
    )

    remote_result = api.audit_workflows(remote)
    local_result = api.audit_workflows(local)
    local_jobs = [job for wf in api.ci_inventory(local)["workflows"] for job in wf["jobs"]]

    assert remote_result["findings"] == []
    assert remote_result["receipt"]["complete"] is False
    assert (
        remote_result["receipt"]["unknowns"][0]["uses"]
        == "org/shared/.github/workflows/release.yml@v1"
    )
    assert local_result["receipt"]["complete"] is True
    assert {job["remote_reusable"] for job in local_jobs} == {False}


GITLAB_RELEASE = """release:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - pip install twine
    - twine upload dist/*
"""
GITLAB_TOKEN_RELEASE = """release:
  script:
    - echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
    - npm publish
"""
CURL_INSTALL = "curl -sSL https://tools.example.com/install.sh | sh"


def _gitlab(tmp_path: Path, files: dict[str, str]) -> dict:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return api.audit_workflows(tmp_path)


@pytest.mark.parametrize(
    "files",
    [
        {".gitlab-ci.yml": "include:\n  - local: 'ci/*.yml'\n", "ci/release.yml": GITLAB_RELEASE},
        {".gitlab-ci.yml": "include: '/ci/**/*.yml'\n", "ci/deep/release.yml": GITLAB_RELEASE},
        {
            ".gitlab-ci.yml": "include:\n  - local: ci/all.yml\n",
            "ci/all.yml": "include:\n  - local: 'ci/jobs/*.yml'\n",
            "ci/jobs/release.yml": GITLAB_RELEASE,
        },
        {
            ".gitlab-ci.yml": "include:\n  - local: a.yml\n",
            "a.yml": "include:\n  - local: b.yml\n",
            "b.yml": "include:\n  - local: a.yml\n" + GITLAB_RELEASE,
        },
    ],
    ids=["wildcard", "globstar", "nested", "loop"],
)
def test_gitlab_jobs_from_wildcard_and_nested_local_includes_are_audited(tmp_path, files):
    result = _gitlab(tmp_path, files)

    assert {(item["signal_type"], item["name"]) for item in result["findings"]} == {
        (C, "release"),
        (A, "release"),
    }
    assert result["receipt"]["complete"] is True


@pytest.mark.parametrize("key", ["before_script", "after_script"])
def test_gitlab_top_level_scripts_are_inherited_unless_the_job_opts_out(tmp_path, key):
    inherited = _gitlab(
        tmp_path / "a", {".gitlab-ci.yml": f"{key}:\n  - {CURL_INSTALL}\n" + GITLAB_TOKEN_RELEASE}
    )
    own = _gitlab(
        tmp_path / "b",
        {
            ".gitlab-ci.yml": f"{key}:\n  - {CURL_INSTALL}\n"
            + GITLAB_TOKEN_RELEASE
            + f"  {key}:\n    - echo hi\n"
        },
    )
    opted_out = _gitlab(
        tmp_path / "c",
        {
            ".gitlab-ci.yml": f"{key}:\n  - {CURL_INSTALL}\n"
            + GITLAB_TOKEN_RELEASE
            + "  inherit:\n    default: false\n"
        },
    )

    assert {item["signal_type"] for item in inherited["findings"]} == {A}
    assert own["findings"] == [] and opted_out["findings"] == []


def test_gitlab_partial_job_override_keeps_the_included_script(tmp_path):
    result = _gitlab(
        tmp_path,
        {
            ".gitlab-ci.yml": "include:\n  - local: ci/release.yml\nrelease:\n  tags: [linux]\n",
            "ci/release.yml": GITLAB_RELEASE,
        },
    )

    assert (C, "release") in {(item["signal_type"], item["name"]) for item in result["findings"]}


@pytest.mark.parametrize(
    ("include", "reason"),
    [
        ("  - remote: https://ci.example.com/x.yml\n", "include_remote"),
        ("  - project: org/ci\n    file: x.yml\n", "include_project"),
        ("  - template: Security/SAST.gitlab-ci.yml\n", "include_template"),
        ("  - local: '$CI_DIR/x.yml'\n", "include_variable"),
        ("  - local: ci/missing.yml\n", "include_unreadable"),
    ],
)
def test_gitlab_includes_that_cannot_be_resolved_are_never_complete(tmp_path, include, reason):
    result = _gitlab(tmp_path, {".gitlab-ci.yml": "include:\n" + include + GITLAB_TOKEN_RELEASE})
    inventory = api.ci_inventory(tmp_path)

    assert result["receipt"]["complete"] is False
    assert inventory["status"] == "partial"
    assert [item["reason"] for item in inventory["skipped"]] == [reason]


def test_gitlab_include_cap_is_incomplete(tmp_path):
    files = {".gitlab-ci.yml": "include:\n  - local: 'ci/*.yml'\n"}
    for index in range(160):
        files[f"ci/j{index:03}.yml"] = f"job{index}:\n  script:\n    - echo {index}\n"

    result = _gitlab(tmp_path, files)

    assert result["receipt"]["complete"] is False
    assert result["receipt"]["jobs"] == 150


WORKFLOW_RUN = """
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  publish:
    runs-on: ubuntu-latest
{job_extra}    steps:
      - uses: actions/checkout@{sha}
        with:
          ref: ${{{{ github.event.workflow_run.head_sha }}}}
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{{{ secrets.NPM_TOKEN }}}}
"""


@pytest.mark.parametrize(
    ("job_extra", "severity"),
    [
        ("    environment: release\n", "LOW"),
        ("", "HIGH"),
        ("    if: github.event.workflow_run.conclusion == 'success'\n", "HIGH"),
        ("    if: github.event_name != 'workflow_run'\n", None),
    ],
)
def test_publish_after_workflow_run_is_an_outside_route(tmp_path, job_extra, severity):
    workflow = WORKFLOW_RUN.format(job_extra=job_extra, sha=SHA)

    findings = _by_signal(_repo(tmp_path, {"release.yml": workflow}), D)

    assert [item["severity"] for item in findings] == [severity] * int(severity is not None)
    if findings:
        assert findings[0]["evidence"]["events"] == ["workflow_run"]


IMAGE_JOB = """
on:
  push:
    branches: [main]
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: release
{job_extra}    steps:
      - uses: actions/checkout@{sha}
{steps}      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{{{ secrets.NPM_TOKEN }}}}
"""
DIGEST = "sha256:" + "ab" * 32


@pytest.mark.parametrize(
    ("job_extra", "steps", "tool"),
    [
        (
            "    container:\n      image: ghcr.io/someone/builder:latest\n",
            "",
            ("ghcr.io/someone/builder:latest", "container"),
        ),
        ("    container: someone/builder:1.2\n", "", ("someone/builder:1.2", "container")),
        ("    container: node\n", "", ("node", "container")),
        (
            "",
            "      - uses: docker://someone/tool:latest\n",
            ("someone/tool:latest", "docker_action"),
        ),
        (
            "",
            "      - run: docker run --rm -v $PWD:/w -e CI=1 tool/x:latest build\n",
            ("tool/x:latest", "docker_run"),
        ),
        (
            "",
            "      - run: podman container run --pull=always node:lts-alpine npm test\n",
            ("node:lts-alpine", "docker_run"),
        ),
    ],
)
def test_unpinned_container_images_in_publish_jobs_are_unpinned_tools(
    tmp_path, job_extra, steps, tool
):
    workflow = IMAGE_JOB.format(job_extra=job_extra, steps=steps, sha=SHA)

    findings = _by_signal(_repo(tmp_path, {"release.yml": workflow}), A)

    assert [item["severity"] for item in findings] == ["HIGH"]
    tools = [(item["name"], item["route"]) for item in findings[0]["evidence"]["tools"]]
    assert tools == [tool]


@pytest.mark.parametrize(
    ("job_extra", "steps"),
    [
        (f"    container:\n      image: ghcr.io/someone/builder@{DIGEST}\n", ""),
        ("    container: node:22-bookworm\n", ""),
        ("    container:\n      image: python:3.12-slim\n", ""),
        ("", f"      - uses: docker://someone/tool@{DIGEST}\n"),
        ("", "      - run: docker run --rm node:22-alpine npm test\n"),
        ("", "      - run: docker build -t app . && docker images\n"),
    ],
)
def test_digest_pinned_or_versioned_official_images_stay_quiet(tmp_path, job_extra, steps):
    workflow = IMAGE_JOB.format(job_extra=job_extra, steps=steps, sha=SHA)

    assert _by_signal(_repo(tmp_path, {"release.yml": workflow}), A) == []


def test_container_images_in_jobs_without_credentials_stay_quiet(tmp_path):
    workflow = f"""
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container: someone/builder:latest
    steps:
      - uses: actions/checkout@{SHA}
      - run: docker run --rm tool/x:latest test
"""

    assert _fired(_repo(tmp_path, {"ci.yml": workflow})) == set()


@pytest.mark.parametrize(
    ("pipeline", "tool"),
    [
        ("publish:\n  image: someone/builder:latest\n", "someone/builder:latest"),
        ("image: node\npublish:\n", "node"),
        (
            "default:\n  image: registry.example.com/team/ci:main\npublish:\n",
            "registry.example.com/team/ci:main",
        ),
    ],
)
def test_gitlab_job_images_in_publish_jobs_are_unpinned_tools(tmp_path, pipeline, tool):
    body = "  script:\n    - npm publish\n  variables:\n    NPM_TOKEN: $NPM_TOKEN\n"
    result = _gitlab(tmp_path, {".gitlab-ci.yml": pipeline + body})

    findings = [item for item in result["findings"] if item["signal_type"] == A]

    assert [entry["name"] for entry in findings[0]["evidence"]["tools"]] == [tool]


def test_gitlab_versioned_or_opted_out_images_stay_quiet(tmp_path):
    pipeline = (
        "image: someone/builder:latest\n"
        "publish:\n  image: node:22\n  script:\n    - npm publish\n"
        "release:\n  inherit:\n    default: false\n  script:\n    - npm publish\n"
    )

    result = _gitlab(tmp_path, {".gitlab-ci.yml": pipeline})

    assert [item for item in result["findings"] if item["signal_type"] == A] == []
