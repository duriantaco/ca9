"""ci_inventory contract: names only, bounded, never raises."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

from ca9 import api
from ca9.ci import yamlload

WORKFLOW = """
name: release
on:
  push:
    branches: [main, 'release/*']
  workflow_dispatch:
env:
  NODE_AUTH_TOKEN: npm_LITERALVALUE123
permissions:
  contents: write
jobs:
  build:
    runs-on: [self-hosted, linux, gpu]
    steps:
      - uses: actions/checkout@v4
      - run: |
          npm ci --ignore-scripts
          pnpm add -g turbo@2.1.0
          curl -fsSL -o tool.tgz https://deploy:s3cr3tPass@downloads.example.com/tool.tgz
          echo '${{ toJSON(secrets) }}' > /dev/null
  publish:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: npm
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: pip install twine
      - run: python -m twine upload dist/*
        env:
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
      - run: npm publish --provenance
  call:
    uses: org/shared/.github/workflows/release.yml@v1
    secrets: inherit
"""


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


def _jobs(inventory: dict) -> dict[str, dict]:
    return {job["id"]: job for workflow in inventory["workflows"] for job in workflow["jobs"]}


def test_job_reach_model_for_a_release_workflow(tmp_path):
    inventory = api.ci_inventory(_repo(tmp_path, {".github/workflows/release.yml": WORKFLOW}))
    workflow = inventory["workflows"][0]
    jobs = _jobs(inventory)
    build, publish, call = jobs["build"], jobs["publish"], jobs["call"]

    assert inventory["schema"] == "ca9.ci_inventory.v1"
    assert inventory["status"] == "complete"
    assert workflow["triggers"] == ["push", "workflow_dispatch"]
    assert workflow["dispatch"] is True
    assert workflow["branch_filters"] == ["main", "release/*"]
    assert build["runner"] == {
        "self_hosted": True,
        "labels": ["self-hosted", "linux", "gpu"],
        "inferred": False,
    }
    assert build["permissions"] == {"write": ["contents"], "id_token": False, "source": "workflow"}
    assert build["secrets"]["all_via_tojson"] is True
    assert [(i["manager"], i["kind"], i["ignore_scripts"]) for i in build["installs"]] == [
        ("npm", "frozen", True),
        ("pnpm", "global", False),
    ]
    assert build["tools"] == [{"name": "turbo", "route": "npm", "pinned": True, "line": 18}]
    assert build["downloads"][0]["host"] == "downloads.example.com"
    assert publish["environment"] == "npm"
    assert publish["permissions"] == {"write": [], "id_token": True, "source": "job"}
    assert publish["secrets"]["names"] == ["PYPI_TOKEN"]
    assert publish["uses_cache"] is True
    assert {(p["registry"], p["method"]) for p in publish["publishes"]} == {
        ("pypi", "token"),
        ("npm", "oidc"),
    }
    assert [tool["name"] for tool in publish["tools"] if not tool["pinned"]] == ["twine"]
    assert call["secrets"]["inherit"] is True
    assert call["actions"][0]["kind"] == "workflow"


def test_inventory_never_carries_secret_values_or_url_credentials(tmp_path):
    inventory = api.ci_inventory(_repo(tmp_path, {".github/workflows/release.yml": WORKFLOW}))
    text = json.dumps(inventory)

    assert "npm_LITERALVALUE123" not in text
    assert "s3cr3tPass" not in text
    assert "deploy" not in text
    assert "https://" not in text


def test_yaml_unavailable_is_reported_without_raising(tmp_path, monkeypatch):
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(yamlload, "_LOADER", None)
    monkeypatch.setattr(builtins, "__import__", blocked)
    repo = _repo(tmp_path, {".github/workflows/release.yml": WORKFLOW})

    inventory = api.ci_inventory(repo)
    audit = api.audit_workflows(repo)

    assert inventory["status"] == "yaml_unavailable"
    assert inventory["workflows"] == []
    assert audit["findings"] == []
    assert audit["receipt"]["complete"] is False


def test_max_jobs_truncates_and_bad_files_make_the_inventory_partial(tmp_path):
    repo = _repo(
        tmp_path,
        {
            ".github/workflows/a.yml": WORKFLOW,
            ".github/workflows/broken.yml": "on: push\njobs: [unclosed\n",
        },
    )

    capped = api.ci_inventory(repo, max_jobs=1)
    full = api.ci_inventory(repo)

    assert capped["truncated"] is True
    assert sum(len(workflow["jobs"]) for workflow in capped["workflows"]) == 1
    assert full["truncated"] is False
    assert full["status"] == "partial"
    assert full["skipped"] == [{"file": ".github/workflows/broken.yml", "reason": "invalid_yaml"}]
    assert len(full["workflows"][0]["jobs"]) == 3


def test_missing_repository_and_alias_bombs_do_not_raise(tmp_path):
    anchors = ["l0: &l0 [x, x, x, x, x, x, x, x, x]"]
    for level in range(1, 9):
        refs = ", ".join([f"*l{level - 1}"] * 9)
        anchors.append(f"l{level}: &l{level} [{refs}]")
    workflow = (
        "x-anchors:\n"
        + "".join(f"  {line}\n" for line in anchors)
        + "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    with:\n      bomb: *l8\n"
        + "    steps:\n      - run: echo hi\n"
    )
    repo = _repo(tmp_path, {".github/workflows/bomb.yml": workflow})

    missing = api.ci_inventory(tmp_path / "nope")
    inventory = api.ci_inventory(repo)

    assert missing["status"] == "partial"
    assert inventory["status"] == "partial"
    assert inventory["skipped"] == [{"file": ".github/workflows/bomb.yml", "reason": "too_complex"}]


def test_gitlab_jobs_inherit_project_variables_and_list_includes(tmp_path):
    repo = _repo(
        tmp_path,
        {
            ".gitlab-ci.yml": """
include:
  - project: org/templates
    ref: main
  - local: ci/release.yml
variables:
  NODE_VERSION: "22"
.base:
  tags: [saas-linux-small-amd64]
test:
  extends: .base
  script:
    - npm ci
""",
            "ci/release.yml": """
release:
  tags: [docker, build-box]
  environment: production
  script:
    - echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
    - npm publish
""",
        },
    )

    inventory = api.ci_inventory(repo)
    workflow = inventory["workflows"][0]
    jobs = _jobs(inventory)

    assert workflow["provider"] == "gitlab"
    assert workflow["includes"][0]["uses"] == "org/templates"
    assert workflow["includes"][0]["pinned"] is False
    assert jobs["test"]["runner"]["self_hosted"] is False
    assert jobs["release"]["runner"]["self_hosted"] is True
    assert jobs["release"]["secrets"] == {
        "names": ["NPM_TOKEN"],
        "inherit": True,
        "all_via_tojson": False,
    }
    assert jobs["release"]["publishes"][0]["method"] == "token"
    assert jobs["release"]["environment"] == "production"


def test_symlinked_workflow_outside_the_repository_is_not_read(tmp_path):
    outside = tmp_path / "outside.yml"
    outside.write_text(
        "on: push\njobs:\n  leak:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n"
    )
    repo = tmp_path / "repo"
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "linked.yml").symlink_to(outside)

    inventory = api.ci_inventory(repo)

    assert inventory["workflows"] == []
    assert inventory["skipped"] == [
        {"file": ".github/workflows/linked.yml", "reason": "invalid_yaml"}
    ]


INDIRECT_WORKFLOW = """on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: make ci
      - run: sudo docker --context ci build -t x .
      - run: docker image build .
      - run: podman compose up -d
      - run: tox -e py && python -m nox -s tests
      - run: just ci; task build; gmake all
      - run: ./scripts/bootstrap.sh
      - run: bash scripts/x.sh
      - run: npm run setup
      - uses: docker/build-push-action@v6
      - run: |
          docker ps
          docker login -u x
          docker push img
          echo make tox
          bash -c "echo hi"
          /usr/bin/env true
          node_modules/.bin/eslint .
          $HOME/bin/tool
"""


def test_jobs_list_commands_that_may_install_out_of_sight(tmp_path):
    repo = _repo(
        tmp_path,
        {
            ".github/workflows/ci.yml": INDIRECT_WORKFLOW,
            "package.json": '{"scripts": {"setup": "make install"}}',
            ".gitlab-ci.yml": "release:\n  script:\n    - make ci\n    - sh build.sh\n",
        },
    )

    jobs = _jobs(api.ci_inventory(repo))

    assert [(item["command"], item["line"]) for item in jobs["build"]["indirect"]] == [
        ("make", 8),
        ("docker", 9),
        ("docker", 10),
        ("podman", 11),
        ("tox", 12),
        ("nox", 12),
        ("just", 13),
        ("task", 13),
        ("gmake", 13),
        ("scripts/bootstrap.sh", 14),
        ("scripts/x.sh", 15),
        ("make", 16),
        ("docker", 17),
    ]
    assert jobs["release"]["indirect"] == [
        {"command": "make", "line": 3},
        {"command": "build.sh", "line": 4},
    ]


def test_indirect_list_is_capped_and_marks_truncation(tmp_path):
    steps = "".join(f"      - run: make step{index}\n" for index in range(150))
    workflow = f"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"

    inventory = api.ci_inventory(_repo(tmp_path, {".github/workflows/ci.yml": workflow}))

    assert len(_jobs(inventory)["build"]["indirect"]) == 100
    assert inventory["truncated"] is True
