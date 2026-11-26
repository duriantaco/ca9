"""Compare ca9's Python scan selections with an independent offline uv export."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from ca9.scanner import resolve_scan_inventory

# These commits have uv.lock and no other root lockfiles or requirements files.
# Ravage also needs both member manifests for uv to locate its workspace.
CASES = {
    "skylos": ("7b579b132ea47e8034a590d01538fbfeb424f7dc", ()),
    "ravage": (
        "00866cffde679f8788c0a5f06512bdf6c764f533",
        ("packages/ravage/pyproject.toml", "packages/schemas/pyproject.toml"),
    ),
}


def compare(name: str, checkout: Path, uv: str, root: Path) -> dict:
    import tomllib

    commit, members = CASES[name]
    git = ["git", "-C", str(checkout)]
    revision = subprocess.check_output(
        [*git, "rev-parse", "--verify", f"{commit}^{{commit}}"], text=True
    ).strip()
    if revision != commit:
        raise ValueError(f"{name}: expected {commit}, got {revision}")
    project = root / name
    for source in ("pyproject.toml", "uv.lock", *members):
        path = project / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(subprocess.check_output([*git, "show", f"{revision}:{source}"]))

    command = [
        uv,
        "export",
        "--project",
        str(project),
        "--frozen",
        "--offline",
        "--no-default-groups",
        "--no-dev",
        "--all-packages",
        "--no-emit-workspace",
        "--no-hashes",
        "--no-annotate",
        "--format",
        "requirements.txt",
        "--python",
        sys.executable,
        "--no-python-downloads",
        "--cache-dir",
        str(root / "uv-cache"),
    ]
    environment = {k: v for k, v in os.environ.items() if not k.startswith("UV_")}
    export = subprocess.check_output(command, env=environment, text=True)
    expected = set()
    for line in export.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        req = Requirement(line)
        if not req.marker or req.marker.evaluate():
            specs = list(req.specifier)
            if len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
                raise ValueError(f"{name}: uv returned a requirement without an exact pin: {line}")
            expected.add((canonicalize_name(req.name), specs[0].version))

    with (project / "pyproject.toml").open("rb") as handle:
        extras = tomllib.load(handle).get("project", {}).get("optional-dependencies", {})
    declared_optional = {
        canonicalize_name(Requirement(req).name) for group in extras.values() for req in group
    }
    scan = resolve_scan_inventory(project)
    selected = {(canonicalize_name(package), version) for package, version in scan.packages}
    missing = sorted(expected - selected)
    extra = sorted(selected - expected)
    unexpected = [pin for pin in extra if pin[0] not in declared_optional]
    return {
        "repo": f"duriantaco/{name}",
        "commit": commit,
        "reference_packages": len(expected),
        "matched_packages": len(expected & selected),
        "missing": missing,
        "extra": extra,
        "unexpected_extra": unexpected,
        "unresolved": scan.unresolved_dependencies,
        "warnings": scan.warnings,
        "pass": bool(expected)
        and not (missing or unexpected or scan.unresolved_dependencies or scan.warnings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for repo in CASES:
        parser.add_argument(
            f"--{repo}",
            type=Path,
            required=True,
            help=f"Local {repo} checkout containing the pinned commit",
        )
    parser.add_argument("--uv", default="uv", help="Path to uv (defaults to uv on PATH)")
    parser.add_argument("--output", type=Path, help="Write JSON to this file (defaults to stdout)")
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error("use Python 3.12 to match the Ravage lock's requires-python constraint")
    with tempfile.TemporaryDirectory(prefix="ca9-uv-benchmark-") as tmp:
        cases = [compare(repo, getattr(args, repo), args.uv, Path(tmp)) for repo in CASES]
    report = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "uv": subprocess.check_output([args.uv, "--version"], text=True).strip(),
        "pass": all(case["pass"] for case in cases),
        "cases": cases,
    }
    payload = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(payload)
    else:
        sys.stdout.write(payload)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
