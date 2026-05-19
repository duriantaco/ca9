#!/usr/bin/env python3
"""Build a local ca9 supply-chain demo fixture.

The generated files are intentionally local and inert. They are shaped like package
artifacts so ca9 can exercise hash verification, safe unpacking, static artifact
analysis, dependency-confusion policy, and license policy without contacting a
package index or executing dependency code.
"""

from __future__ import annotations

import hashlib
import shutil
import textwrap
import zipfile
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ARTIFACT_DIR = BASE_DIR / "artifacts"
REPO_DIR = BASE_DIR / "repo"


@dataclass(frozen=True)
class DemoPackage:
    name: str
    version: str
    license_expression: str
    files: dict[str, str]

    @property
    def dist_name(self) -> str:
        return self.name.replace("-", "_")

    @property
    def wheel_name(self) -> str:
        return f"{self.dist_name}-{self.version}-py3-none-any.whl"


DEMO_PACKAGES = (
    DemoPackage(
        name="acme-internal",
        version="1.0.0",
        license_expression="MIT",
        files={
            "acme_internal/__init__.py": "__version__ = '1.0.0'\n",
        },
    ),
    DemoPackage(
        name="startup-hook",
        version="1.0.0",
        license_expression="MIT",
        files={
            "startup_hook/__init__.py": "__version__ = '1.0.0'\n",
            "startup_hook.pth": (
                'import os; os.system("curl https://example.invalid/ca9-demo >/dev/null 2>&1")\n'
            ),
        },
    ),
    DemoPackage(
        name="license-risk",
        version="1.0.0",
        license_expression="AGPL-3.0-only",
        files={
            "license_risk/__init__.py": "__version__ = '1.0.0'\n",
        },
    ),
)


def main() -> None:
    reset_generated_dirs()
    artifacts = {package.name: build_wheel(package) for package in DEMO_PACKAGES}
    write_demo_repo(artifacts)
    print(f"Generated demo repository: {REPO_DIR}")
    print("Run:")
    print("  bash run_demo.sh")


def reset_generated_dirs() -> None:
    for path in (ARTIFACT_DIR, REPO_DIR):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)


def build_wheel(package: DemoPackage) -> dict[str, str | int]:
    wheel_path = ARTIFACT_DIR / package.wheel_name
    dist_info = f"{package.dist_name}-{package.version}.dist-info"
    metadata = textwrap.dedent(
        f"""\
        Metadata-Version: 2.3
        Name: {package.name}
        Version: {package.version}
        Summary: ca9 local supply-chain demo fixture
        License-Expression: {package.license_expression}
        """
    )
    wheel_metadata = textwrap.dedent(
        """\
        Wheel-Version: 1.0
        Generator: ca9-demo
        Root-Is-Purelib: true
        Tag: py3-none-any
        """
    )

    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for relative_path, content in package.files.items():
            wheel.writestr(relative_path, content)
        wheel.writestr(f"{dist_info}/METADATA", metadata)
        wheel.writestr(f"{dist_info}/WHEEL", wheel_metadata)
        wheel.writestr(f"{dist_info}/RECORD", "")

    digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    return {
        "url": wheel_path.as_uri(),
        "hash": f"sha256:{digest}",
        "size": wheel_path.stat().st_size,
    }


def write_demo_repo(artifacts: dict[str, dict[str, str | int]]) -> None:
    (REPO_DIR / "README.md").write_text(
        textwrap.dedent(
            """\
            # ca9 supply-chain demo repo

            This generated fixture is intentionally synthetic and safe. It contains
            a `fyn.lock` with local wheel artifacts that demonstrate three blocking
            dependency-security findings:

            - an internal-looking package resolving from PyPI
            - a wheel with suspicious `.pth` startup code
            - a dependency with a denied AGPL license expression
            """
        )
    )

    package_blocks = [
        textwrap.dedent(
            """\
            [[package]]
            name = "demo-app"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [
              { name = "acme-internal" },
              { name = "startup-hook" },
              { name = "license-risk" },
            ]
            """
        )
    ]
    for package in DEMO_PACKAGES:
        artifact = artifacts[package.name]
        package_blocks.append(
            textwrap.dedent(
                f"""\
                [[package]]
                name = "{package.name}"
                version = "{package.version}"
                source = {{ registry = "https://pypi.org/simple" }}
                wheels = [
                  {{ url = "{artifact["url"]}", hash = "{artifact["hash"]}", size = {artifact["size"]} }},
                ]
                """
            )
        )

    fyn_lock = "version = 1\n\n" + "\n".join(package_blocks)
    (REPO_DIR / "fyn.lock").write_text(fyn_lock)


if __name__ == "__main__":
    main()
