from __future__ import annotations

import json

import pytest

from ca9 import api

SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def _repo(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not isinstance(content, str):
            content = json.dumps(content)
        path.write_text(content)
    return root


def _kinds(items):
    return sorted((item["kind"], item.get("package") or item["setting"]) for item in items)


HARDENED = {
    ".npmrc": "; repo install policy\nmin-release-age=7\nignore-scripts=true\n",
    "pnpm-workspace.yaml": (
        "packages:\n  - 'packages/*'\nminimumReleaseAge: 4320\nstrictDepBuilds: true\n"
        "allowBuilds:\n  esbuild: true\n  core-js: false\n"
    ),
    ".yarnrc.yml": 'npmMinimalAgeGate: "3d"\nenableScripts: false\n',
    "bunfig.toml": "[install]\nminimumReleaseAge = 259200\n",
    "pyproject.toml": '[project]\nname = "x"\n[tool.uv]\nexclude-newer = "1 week"\n',
    "pip.conf": "[global]\nuploaded-prior-to = P3D\n",
    ".github/dependabot.yml": (
        "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
        "    schedule: {interval: weekly}\n    cooldown:\n      default-days: 7\n"
    ),
    "renovate.json": {"extends": ["config:best-practices"], "minimumReleaseAge": "3 days"},
    "package.json": {
        "name": "x",
        "packageManager": "pnpm@11.1.0",
        "trustedDependencies": ["sharp"],
    },
    ".github/workflows/ci.yml": (
        "jobs:\n  t:\n    steps:\n"
        f"      - uses: actions/checkout@{SHA}\n"
        f"      - uses: actions/setup-node@{SHA} # v4\n"
        "      - uses: some/action@v2\n"
        "      - uses: ./.github/actions/local\n"
    ),
}


def test_snapshot_reads_each_tool_in_its_own_units(tmp_path):
    snapshot = api.hardening_settings(_repo(tmp_path, HARDENED))

    assert snapshot["schema"] == "ca9.hardening.v1"
    assert snapshot["cooldown"] == {
        "npm_days": 7,
        "pnpm_minutes": 4320,
        "yarn": "3d",
        "bun_seconds": 259200,
        "uv": "1 week",
        "pip": "P3D",
        "dependabot_days": 7,
        "renovate": "3 days",
    }
    assert snapshot["cooldown_minutes"] == {
        "npm_days": 10080,
        "pnpm_minutes": 4320,
        "yarn": 4320,
        "bun_seconds": 4320,
        "uv": 10080,
        "pip": 4320,
        "dependabot_days": 10080,
        "renovate": 4320,
    }
    scripts = snapshot["scripts"]
    assert scripts["npm_ignore_scripts"] is True
    assert scripts["pnpm_strict_dep_builds"] is True
    assert scripts["pnpm_allow_builds"] == ["esbuild"]
    assert scripts["npm12_allow_scripts"] == []
    assert scripts["bun_trusted_dependencies"] == ["sharp"]
    assert scripts["yarn_enable_scripts"] is False
    assert (snapshot["actions"]["pinned"], snapshot["actions"]["unpinned"]) == (2, 1)
    assert snapshot["sources"]["pnpm_minutes"] == "pnpm-workspace.yaml"
    assert snapshot["sources"]["npm_days"] == ".npmrc"
    assert snapshot["status"] == "complete"


def test_pnpm10_keys_in_npmrc_and_package_json(tmp_path):
    _repo(
        tmp_path,
        {
            ".npmrc": "minimum-release-age=1440\nstrict-dep-builds=true\n",
            "package.json": {"pnpm": {"onlyBuiltDependencies": ["esbuild"]}},
            "requirements.txt": "--uploaded-prior-to 2026-10-01T00:00:00Z\nrequests==2.32.3\n",
        },
    )

    snapshot = api.hardening_settings(tmp_path)

    assert snapshot["cooldown"]["pnpm_minutes"] == 1440
    assert snapshot["scripts"]["pnpm_strict_dep_builds"] is True
    assert snapshot["scripts"]["pnpm_only_built_dependencies"] == ["esbuild"]
    assert snapshot["cooldown"]["pip"] == "2026-10-01T00:00:00Z"
    assert snapshot["cooldown_minutes"]["pip"] is None


def test_unhardened_repo_and_missing_root(tmp_path):
    snapshot = api.hardening_settings(tmp_path)
    assert set(snapshot["cooldown"].values()) == {None}
    assert snapshot["actions"]["pinned"] == snapshot["actions"]["unpinned"] == 0
    assert api.hardening_settings(tmp_path / "missing")["status"] == "partial"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({".npmrc": "ignore-scripts=true\n"}, [("cooldown_removed", "npm_days")]),
        ({".npmrc": "min-release-age=7\n"}, [("ignore_scripts_disabled", "npm_ignore_scripts")]),
        (
            {".npmrc": "min-release-age=7\nignore-scripts=false\n"},
            [("ignore_scripts_disabled", "npm_ignore_scripts")],
        ),
        (
            {
                "pnpm-workspace.yaml": "minimumReleaseAge: 60\nstrictDepBuilds: true\nallowBuilds:\n  esbuild: true\n"
            },
            [("cooldown_lowered", "pnpm_minutes")],
        ),
        (
            {
                "pnpm-workspace.yaml": (
                    "minimumReleaseAge: 4320\nstrictDepBuilds: false\nallowBuilds:\n"
                    "  esbuild: true\n  postinstall-evil: true\n  core-js: false\n"
                )
            },
            [
                ("allow_builds_added", "postinstall-evil"),
                ("strict_dep_builds_disabled", "pnpm_strict_dep_builds"),
            ],
        ),
        (
            {"bunfig.toml": "[install]\nminimumReleaseAge = 3600\n"},
            [("cooldown_lowered", "bun_seconds")],
        ),
        (
            {".yarnrc.yml": 'npmMinimalAgeGate: "12h"\nenableScripts: false\n'},
            [("cooldown_lowered", "yarn")],
        ),
        (
            {".yarnrc.yml": 'npmMinimalAgeGate: "3d"\n'},
            [("ignore_scripts_disabled", "yarn_enable_scripts")],
        ),
        ({"pyproject.toml": '[tool.uv]\nexclude-newer = "1 day"\n'}, [("cooldown_lowered", "uv")]),
        ({"pip.conf": "[global]\nuploaded-prior-to = P1D\n"}, [("cooldown_lowered", "pip")]),
        ({"renovate.json": {"minimumReleaseAge": "1 day"}}, [("cooldown_lowered", "renovate")]),
        (
            {
                ".github/dependabot.yml": "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
            },
            [("cooldown_removed", "dependabot_days")],
        ),
        (
            {
                "package.json": {
                    "packageManager": "pnpm@11.1.0",
                    "trustedDependencies": ["sharp", "evil-native"],
                    "allowScripts": {"esbuild": True},
                }
            },
            [("allow_builds_added", "evil-native"), ("allow_scripts_added", "esbuild")],
        ),
        (
            {
                ".github/workflows/ci.yml": HARDENED[".github/workflows/ci.yml"].replace(
                    f"checkout@{SHA}", "checkout@v4"
                )
            },
            [("action_unpinned", "actions")],
        ),
        (
            {
                "pnpm-workspace.yaml": HARDENED["pnpm-workspace.yaml"]
                + "minimumReleaseAgeExclude:\n  - '@acme/*'\n"
            },
            [("cooldown_exclusion_added", "@acme/*")],
        ),
    ],
)
def test_each_weakening_is_reported(tmp_path, changes, expected):
    base = api.hardening_settings(_repo(tmp_path / "base", HARDENED))
    head = api.hardening_settings(_repo(tmp_path / "head", {**HARDENED, **changes}))

    assert _kinds(api.hardening_regressions(base, head)) == expected


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {".npmrc": "min-release-age=14\nignore-scripts=true\n"},
        {"bunfig.toml": "[install]\nminimumReleaseAge = 604800\n"},
        {
            "pnpm-workspace.yaml": "minimumReleaseAge: 4320\nstrictDepBuilds: true\nallowBuilds: {}\n"
        },
        {"package.json": {"packageManager": "pnpm@11.1.0", "trustedDependencies": []}},
        {
            ".github/workflows/ci.yml": HARDENED[".github/workflows/ci.yml"]
            + f"      - uses: new/action@{SHA}\n"
        },
        {".github/workflows/ci.yml": HARDENED[".github/workflows/ci.yml"].replace("@v2", "@v3")},
    ],
)
def test_unchanged_or_stronger_settings_are_quiet(tmp_path, changes):
    base = _repo(tmp_path / "base", HARDENED)
    head = _repo(tmp_path / "head", {**HARDENED, **changes})

    assert api.hardening_regressions(base, head) == []


def test_removal_that_falls_back_to_an_equal_or_longer_default_is_quiet(tmp_path):
    base = {**HARDENED, "pnpm-workspace.yaml": "minimumReleaseAge: 1440\nstrictDepBuilds: true\n"}
    head = {**HARDENED, "pnpm-workspace.yaml": "packages: ['a']\n"}
    small = {
        **HARDENED,
        ".github/dependabot.yml": HARDENED[".github/dependabot.yml"].replace(
            "default-days: 7", "default-days: 2"
        ),
    }
    unset = {
        **HARDENED,
        ".github/dependabot.yml": "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n",
    }

    assert api.hardening_regressions(_repo(tmp_path / "b", base), _repo(tmp_path / "h", head)) == []
    assert (
        api.hardening_regressions(_repo(tmp_path / "s", small), _repo(tmp_path / "u", unset)) == []
    )


def test_pnpm10_removal_of_strict_builds_and_cooldown_is_reported(tmp_path):
    base = {
        "package.json": {"packageManager": "pnpm@10.18.0"},
        "pnpm-workspace.yaml": "minimumReleaseAge: 1440\nstrictDepBuilds: true\n",
    }
    head = {
        "package.json": {"packageManager": "pnpm@10.18.0"},
        "pnpm-workspace.yaml": "packages: ['a']\n",
    }

    items = api.hardening_regressions(_repo(tmp_path / "b", base), _repo(tmp_path / "h", head))

    assert _kinds(items) == [
        ("cooldown_removed", "pnpm_minutes"),
        ("strict_dep_builds_disabled", "pnpm_strict_dep_builds"),
    ]
    assert {item["path"] for item in items} == {"pnpm-workspace.yaml"}


def _failed_sides(items):
    return sorted(item["side"] for item in items if item["kind"] == "check_failed")


def test_unusable_or_partial_snapshots_are_check_failed_never_empty(tmp_path):
    good = _repo(tmp_path / "good", {".npmrc": "min-release-age=7\n"})
    broken = _repo(
        tmp_path / "broken", {".npmrc": "min-release-age=7\n", "pnpm-workspace.yaml": "a: [\n"}
    )

    assert _failed_sides(api.hardening_regressions(tmp_path / "missing", good)) == ["base"]
    missing_head = api.hardening_regressions(good, tmp_path / "missing")
    assert [(item["kind"], item["side"]) for item in missing_head] == [("check_failed", "head")]
    assert _failed_sides(api.hardening_regressions(None, good)) == ["base"]
    assert _failed_sides(api.hardening_regressions(good, 5)) == ["head"]
    assert _failed_sides(api.hardening_regressions({"cooldown": {}}, good)) == ["base"]
    partial = api.hardening_regressions(broken, good)
    assert _failed_sides(partial) == ["base"]
    assert [i["path"] for i in partial if i["kind"] == "check_failed"] == ["pnpm-workspace.yaml"]
    assert _failed_sides(api.hardening_regressions(good, broken)) == ["head"]
    assert api.hardening_regressions(good, good) == []


def test_without_pyyaml_simple_files_still_read_and_dependabot_is_partial(tmp_path, monkeypatch):
    from ca9 import hardening

    monkeypatch.setattr(hardening, "yaml", None)

    snapshot = api.hardening_settings(_repo(tmp_path, HARDENED))

    assert snapshot["cooldown"]["pnpm_minutes"] == 4320
    assert snapshot["scripts"]["pnpm_allow_builds"] == ["esbuild"]
    assert snapshot["cooldown"]["yarn"] == "3d"
    assert snapshot["cooldown"]["dependabot_days"] is None
    assert snapshot["status"] == "partial"


def _regressions(tmp_path, base_files, head_files):
    base = _repo(tmp_path / "base", base_files)
    head = _repo(tmp_path / "head", head_files)
    return _kinds(api.hardening_regressions(base, head))


def _workflow(*uses):
    steps = "".join(f"      - uses: {item}\n" for item in uses)
    return "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n" + steps


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        (
            [{"matchPackageNames": ["*"], "minimumReleaseAge": "0 days"}],
            [("cooldown_removed", "renovate")],
        ),
        (
            [{"matchDatasources": ["npm"], "minimumReleaseAge": None}],
            [("cooldown_removed", "renovate")],
        ),
        (
            [{"matchPackageNames": ["lodash"], "minimumReleaseAge": "0 days"}],
            [("cooldown_exclusion_added", "lodash")],
        ),
        (
            [{"matchPackageNames": ["react"], "minimumReleaseAge": "1 day"}],
            [("cooldown_lowered", "react")],
        ),
        ([{"matchPackageNames": ["react"], "minimumReleaseAge": "14 days"}], []),
        ([{"matchPackageNames": ["react"], "automerge": True}], []),
    ],
)
def test_renovate_package_rules(tmp_path, rules, expected):
    base = {"renovate.json": {"minimumReleaseAge": "3 days"}}
    head = {"renovate.json": {"minimumReleaseAge": "3 days", "packageRules": rules}}

    assert _regressions(tmp_path, base, head) == expected


def test_renovate_rule_that_raised_an_age_and_was_removed(tmp_path):
    rule = {"matchPackageNames": ["@acme/*"], "minimumReleaseAge": "7 days"}
    base = {"renovate.json": {"packageRules": [rule]}}
    head = {"renovate.json": {"packageRules": []}}

    assert _regressions(tmp_path, base, head) == [("cooldown_exclusion_added", "@acme/*")]


DEPENDABOT_ROOT = (
    "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"
    "    cooldown:\n      default-days: 14\n"
)


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (
            "version: 2\nupdates:\n  - package-ecosystem: npm\n    directories: ['/', '/web']\n",
            [("cooldown_removed", "dependabot_days")],
        ),
        (
            "version: 2\nupdates:\n  - package-ecosystem: NPM\n    directories: ['/', '/web']\n"
            "    cooldown: {default-days: 14}\n",
            [],
        ),
        (
            "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: '/'\n"
            "    cooldown: {default-days: 2}\n",
            [("cooldown_lowered", "dependabot_days")],
        ),
    ],
)
def test_dependabot_entries_match_by_covered_directories(tmp_path, head, expected):
    base = {".github/dependabot.yml": DEPENDABOT_ROOT}

    assert _regressions(tmp_path, base, {".github/dependabot.yml": head}) == expected


@pytest.mark.parametrize(
    ("base_directory", "head_directory"),
    [("'/packages/*'", "/packages/a"), ("/packages/a", "'/packages/*'")],
)
def test_dependabot_glob_and_concrete_directories_cover_each_other(
    tmp_path, base_directory, head_directory
):
    base = DEPENDABOT_ROOT.replace("directory: /", f"directory: {base_directory}")
    head = f"version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: {head_directory}\n"

    assert _regressions(
        tmp_path, {".github/dependabot.yml": base}, {".github/dependabot.yml": head}
    ) == [("cooldown_removed", "dependabot_days")]


@pytest.mark.parametrize(
    "head",
    [
        {".github/workflows/ci.yml": _workflow("Actions/Checkout@v4")},
        {
            ".github/workflows/ci.yml": _workflow("./ci/setup"),
            "ci/setup/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n",
        },
        {
            ".github/workflows/ci.yml": _workflow("./ci/outer"),
            "ci/outer/action.yml": "runs:\n  steps:\n    - uses: ./ci/inner\n    - uses: ./ci/outer\n",
            "ci/inner/action.yaml": "runs:\n  steps:\n    - uses: actions/checkout@main\n",
        },
        {".github/workflows/ci.yml": "jobs:\n  t:\n    steps: [{uses: actions/checkout@v4}]\n"},
        {
            ".github/workflows/ci.yml": (
                "x: &co actions/checkout@v4\njobs:\n  t:\n    steps:\n      - uses: *co\n"
            )
        },
    ],
)
def test_unpinned_action_hidden_by_case_composite_or_yaml_shape(tmp_path, head):
    base = {".github/workflows/ci.yml": _workflow(f"actions/checkout@{SHA}")}

    assert ("action_unpinned", "actions") in _regressions(tmp_path, base, head)


def test_local_action_outside_the_repository_is_not_read(tmp_path):
    _repo(tmp_path, {"outside/action.yml": "runs:\n  steps:\n    - uses: actions/checkout@v4\n"})
    repo = _repo(tmp_path / "repo", {".github/workflows/ci.yml": _workflow("./../outside")})

    assert api.hardening_settings(repo)["actions"]["unpinned"] == 0


def test_pnpm11_ignores_pnpm_keys_moved_to_npmrc(tmp_path):
    manager = {"package.json": {"packageManager": "pnpm@11.1.0"}}
    base = {**manager, "pnpm-workspace.yaml": "minimumReleaseAge: 4320\nstrictDepBuilds: true\n"}
    head = {
        **manager,
        ".npmrc": "minimum-release-age=4320\nstrict-dep-builds=true\n",
        "pnpm-workspace.yaml": "onlyBuiltDependencies: [esbuild]\n",
    }

    snapshot = api.hardening_settings(_repo(tmp_path / "snap", head))
    assert snapshot["cooldown"]["pnpm_minutes"] is None
    assert {item["setting"] for item in snapshot["ignored"]} == {
        "minimum-release-age",
        "strict-dep-builds",
        "onlyBuiltDependencies",
    }
    assert snapshot["scripts"]["pnpm_only_built_dependencies"] == []
    assert _regressions(tmp_path, base, head) == [("cooldown_removed", "pnpm_minutes")]


def test_pnpm10_and_undeclared_versions_still_read_npmrc(tmp_path):
    for name, manager in (("ten", {"packageManager": "pnpm@10.18.0"}), ("none", {})):
        files = {"package.json": manager, ".npmrc": "minimum-release-age=1440\n"}
        snapshot = api.hardening_settings(_repo(tmp_path / name, files))
        assert snapshot["cooldown"]["pnpm_minutes"] == 1440


@pytest.mark.parametrize(
    "line",
    [
        "    env:\n      npm_config_ignore_scripts: false\n",
        "    env:\n      NPM_CONFIG_IGNORE_SCRIPTS: 'false'\n",
        "    steps:\n      - run: NPM_CONFIG_IGNORE_SCRIPTS=false npm ci\n",
        "    steps:\n      - run: npm ci --ignore-scripts=false\n",
        "    steps:\n      - run: npm config set ignore-scripts false\n",
        "    env:\n      YARN_ENABLE_SCRIPTS: true\n",
    ],
)
def test_workflow_overrides_that_reenable_install_scripts(tmp_path, line):
    base = {".github/workflows/ci.yml": "jobs:\n  t:\n    runs-on: x\n"}
    head = {".github/workflows/ci.yml": "jobs:\n  t:\n    runs-on: x\n" + line}

    assert _regressions(tmp_path, base, head) == [("ignore_scripts_disabled", "workflow_overrides")]


def test_unchanged_or_commented_workflow_override_is_quiet(tmp_path):
    files = {".github/workflows/ci.yml": "env:\n  npm_config_ignore_scripts: false\njobs: {}\n"}
    moved = {".github/workflows/ci.yml": "jobs: {}\nenv:\n  npm_config_ignore_scripts: false\n"}
    commented = {".github/workflows/ci.yml": "jobs: {}\n# npm_config_ignore_scripts: false\n"}

    assert _regressions(tmp_path / "a", files, moved) == []
    assert _regressions(tmp_path / "b", {".github/workflows/ci.yml": "jobs: {}\n"}, commented) == []


def test_pnpm10_never_built_removal_and_pnpm11_migration(tmp_path):
    ten = {"package.json": {"packageManager": "pnpm@10.18.0"}}
    base = {**ten, "pnpm-workspace.yaml": "neverBuiltDependencies: [a, b]\n"}
    head = {**ten, "pnpm-workspace.yaml": "neverBuiltDependencies: [a]\n"}
    assert _regressions(tmp_path / "removed", base, head) == [("allow_builds_added", "b")]

    old = {
        **ten,
        "pnpm-workspace.yaml": "onlyBuiltDependencies: [esbuild]\nneverBuiltDependencies: [c]\n",
    }
    new = {
        "package.json": {"packageManager": "pnpm@11.1.0"},
        "pnpm-workspace.yaml": "allowBuilds:\n  esbuild: true\n",
    }
    assert _regressions(tmp_path / "migrated", old, new) == []


JOB = "jobs:\n  t:\n    runs-on: x\n"
PINNED_BASE = {
    ".npmrc": "ignore-scripts=true\nmin-release-age=3\n",
    "pnpm-workspace.yaml": "minimumReleaseAge: 4320\n",
    ".yarnrc.yml": 'npmMinimalAgeGate: "3d"\n',
    ".github/workflows/ci.yml": JOB,
}


@pytest.mark.parametrize(
    "line",
    [
        "    steps:\n      - run: npm ci --no-ignore-scripts\n",
        "    steps:\n      - run: npm ci --ignore-scripts false\n",
        "    steps:\n      - run: pnpm install --config.ignore-scripts=false\n",
        "    steps:\n      - run: echo ignore-scripts=false >> .npmrc && npm ci\n",
        "    steps:\n      - run: pnpm config set ignore-scripts false\n",
        "    steps:\n      - run: yarn config set enableScripts true\n",
        "    steps:\n      - run: echo 'enableScripts: true' >> .yarnrc.yml\n",
    ],
)
def test_cli_flag_and_config_write_overrides_reenable_install_scripts(tmp_path, line):
    head = {**PINNED_BASE, ".github/workflows/ci.yml": JOB + line}

    assert _regressions(tmp_path, PINNED_BASE, head) == [
        ("ignore_scripts_disabled", "workflow_overrides")
    ]


@pytest.mark.parametrize(
    ("line", "setting"),
    [
        ("    env:\n      npm_config_min_release_age: 0\n", "npm_days"),
        ("    steps:\n      - run: npm install --min-release-age=0\n", "npm_days"),
        ("    steps:\n      - run: npm ci --min-release-age 1\n", "npm_days"),
        ("    steps:\n      - run: echo min-release-age=0 >> .npmrc\n", "npm_days"),
        ("    steps:\n      - run: pnpm install --config.minimum-release-age=0\n", "pnpm_minutes"),
        ("    env:\n      PNPM_CONFIG_MINIMUM_RELEASE_AGE: 10\n", "pnpm_minutes"),
        ("    env:\n      YARN_NPM_MINIMAL_AGE_GATE: 0\n", "yarn"),
    ],
)
def test_workflow_overrides_that_lower_the_cooldown(tmp_path, line, setting):
    head = {**PINNED_BASE, ".github/workflows/ci.yml": JOB + line}

    items = api.hardening_regressions(
        _repo(tmp_path / "base", PINNED_BASE), _repo(tmp_path / "head", head)
    )

    assert _kinds(items) == [("cooldown_lowered", setting)]
    assert items[0]["path"] == ".github/workflows/ci.yml" and items[0]["line"] >= 4


@pytest.mark.parametrize(
    "line",
    [
        "    steps:\n      - run: npm ci --ignore-scripts\n",
        "    steps:\n      - run: npm ci --ignore-scripts=true\n",
        "    steps:\n      - run: echo ignore-scripts=true >> .npmrc\n",
        "    steps:\n      # - run: npm ci --no-ignore-scripts\n",
        "    env:\n      npm_config_min_release_age: 7\n",
        "    steps:\n      - run: npm ci --min-release-age=3\n",
    ],
)
def test_overrides_that_keep_or_raise_the_hardening_are_quiet(tmp_path, line):
    head = {**PINNED_BASE, ".github/workflows/ci.yml": JOB + line}

    assert _regressions(tmp_path, PINNED_BASE, head) == []


def test_cooldown_override_without_a_base_cooldown_or_already_in_base_is_quiet(tmp_path):
    override = JOB + "    env:\n      npm_config_min_release_age: 0\n"
    bare = {".github/workflows/ci.yml": JOB}

    assert _regressions(tmp_path / "a", bare, {".github/workflows/ci.yml": override}) == []
    already = {**PINNED_BASE, ".github/workflows/ci.yml": override}
    assert _regressions(tmp_path / "b", already, already) == []


def test_new_unpinned_action_in_a_fully_pinned_repository_is_reported(tmp_path):
    base = {
        ".github/workflows/ci.yml": _workflow(
            f"actions/checkout@{SHA}", f"actions/setup-node@{SHA}"
        )
    }
    added = {
        ".github/workflows/ci.yml": _workflow(
            f"actions/checkout@{SHA}", f"actions/setup-node@{SHA}", "someone/setup-tool@v1"
        )
    }
    pinned_add = {
        ".github/workflows/ci.yml": _workflow(
            f"actions/checkout@{SHA}", f"someone/setup-tool@{SHA}"
        )
    }
    mixed = {".github/workflows/ci.yml": _workflow(f"actions/checkout@{SHA}", "other/tool@v2")}
    mixed_added = {
        ".github/workflows/ci.yml": _workflow(
            f"actions/checkout@{SHA}", "other/tool@v2", "someone/setup-tool@v1"
        )
    }

    items = api.hardening_regressions(
        _repo(tmp_path / "base", base), _repo(tmp_path / "head", added)
    )

    assert _kinds(items) == [("action_unpinned", "actions")]
    assert "someone/setup-tool" in items[0]["detail"]
    assert _regressions(tmp_path / "p", base, pinned_add) == []
    assert _regressions(tmp_path / "m", mixed, mixed_added) == []
