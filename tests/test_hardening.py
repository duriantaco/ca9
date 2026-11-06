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


def test_bad_input_never_raises():
    assert api.hardening_regressions(None, 5) == []
    assert (
        api.hardening_regressions({"cooldown": "x", "scripts": [1]}, {"actions": {"refs": [3]}})
        == []
    )


def test_without_pyyaml_simple_files_still_read_and_dependabot_is_partial(tmp_path, monkeypatch):
    from ca9 import hardening

    monkeypatch.setattr(hardening, "yaml", None)

    snapshot = api.hardening_settings(_repo(tmp_path, HARDENED))

    assert snapshot["cooldown"]["pnpm_minutes"] == 4320
    assert snapshot["scripts"]["pnpm_allow_builds"] == ["esbuild"]
    assert snapshot["cooldown"]["yarn"] == "3d"
    assert snapshot["cooldown"]["dependabot_days"] is None
    assert snapshot["status"] == "partial"
