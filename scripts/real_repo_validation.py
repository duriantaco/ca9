from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Case:
    name: str
    repo_url: str
    commit: str
    min_inventory_packages: int = 0
    min_scan_results: int = 0
    required_scan_warning: str | None = None
    forbid_unreachable_verdicts: bool = False


CASES: tuple[Case, ...] = (
    Case(
        name="flask",
        repo_url="https://github.com/pallets/flask.git",
        commit="954f5684e4841aad84a8eec7ace7b81a0d3f6831",
        min_inventory_packages=6,
    ),
    Case(
        name="django-rest-framework",
        repo_url="https://github.com/encode/django-rest-framework.git",
        commit="7433faa98f27c200e34c04586c20024d4d6aa935",
        min_inventory_packages=1,
        required_scan_warning="skipped declared package",
    ),
    Case(
        name="safedep-vet",
        repo_url="https://github.com/safedep/vet.git",
        commit="d4491496daec6f445803a039524ddab714be01b2",
        required_scan_warning="no declared dependencies",
    ),
    Case(
        name="pintrace",
        repo_url="https://github.com/dw763j/PinTrace.git",
        commit="04b343779b49faf1691823a225858ef93c52c747",
        min_inventory_packages=10,
        min_scan_results=1,
        forbid_unreachable_verdicts=True,
    ),
)


def run(cmd: list[str], cwd: Path | None = None, allowed_exit_codes: set[int] | None = None) -> str:
    allowed = allowed_exit_codes or {0}
    result = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode not in allowed:
        rendered = " ".join(cmd)
        raise RuntimeError(
            f"{rendered} exited {result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout + result.stderr


def checkout_case(case: Case, repos_dir: Path) -> Path:
    repo_dir = repos_dir / case.name
    if repo_dir.exists():
        shutil.rmtree(repo_dir)

    repo_dir.mkdir(parents=True)
    run(["git", "init", "-q"], cwd=repo_dir)
    run(["git", "remote", "add", "origin", case.repo_url], cwd=repo_dir)
    run(["git", "fetch", "--depth", "1", "origin", case.commit], cwd=repo_dir)
    run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], cwd=repo_dir)
    actual = run(["git", "rev-parse", "HEAD"], cwd=repo_dir).strip()
    if actual != case.commit:
        raise RuntimeError(f"{case.name}: expected {case.commit}, checked out {actual}")
    return repo_dir


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def verdict_counts(results: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        verdict = result.get("verdict", "unknown")
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def validate_case(case: Case, repo_dir: Path, output_dir: Path) -> dict:
    case_out = output_dir / case.name
    case_out.mkdir(parents=True, exist_ok=True)
    inventory_path = case_out / "inventory.json"
    scan_path = case_out / "scan.json"

    run(
        [
            sys.executable,
            "-m",
            "ca9.cli",
            "inventory",
            "--repo",
            str(repo_dir),
            "-f",
            "json",
            "-o",
            str(inventory_path),
        ]
    )
    scan_log = run(
        [
            sys.executable,
            "-m",
            "ca9.cli",
            "scan",
            "--repo",
            str(repo_dir),
            "--no-auto-coverage",
            "-f",
            "json",
            "-o",
            str(scan_path),
        ],
        allowed_exit_codes={0, 1, 2},
    )

    inventory = load_json(inventory_path)
    scan = load_json(scan_path)
    failures: list[str] = []
    inventory_summary = inventory.get("summary", {})
    scan_summary = scan.get("summary", {})
    scan_results = scan.get("results", [])
    scan_warnings = scan.get("warnings", [])

    inventory_packages = int(inventory_summary.get("packages", 0))
    scan_total = int(scan_summary.get("total", 0))

    if inventory_packages < case.min_inventory_packages:
        failures.append(
            f"expected at least {case.min_inventory_packages} inventory packages, got {inventory_packages}"
        )
    if scan_total < case.min_scan_results:
        failures.append(f"expected at least {case.min_scan_results} scan results, got {scan_total}")
    if case.required_scan_warning and not any(
        case.required_scan_warning in warning for warning in scan_warnings
    ):
        failures.append(f"missing scan warning containing {case.required_scan_warning!r}")
    if any("fell back to installed environment packages" in warning for warning in scan_warnings):
        failures.append("scan used ambient environment fallback without opt-in")
    if case.forbid_unreachable_verdicts:
        unreachable = [
            result
            for result in scan_results
            if result.get("verdict") in {"unreachable_static", "unreachable_dynamic"}
        ]
        if unreachable:
            ids = ", ".join(result.get("id", "unknown") for result in unreachable[:5])
            failures.append(f"unexpected unreachable verdict(s): {ids}")

    return {
        "name": case.name,
        "repo_url": case.repo_url,
        "commit": case.commit,
        "inventory_summary": inventory_summary,
        "scan_summary": scan_summary,
        "scan_warnings": scan_warnings,
        "scan_verdict_counts": verdict_counts(scan_results),
        "scan_packages": sorted({result.get("package", "") for result in scan_results}),
        "scan_log": scan_log.strip().splitlines(),
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real-repo ca9 validation cases.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/ca9-real-repo-validation"),
        help="Directory for cloned repos and JSON artifacts.",
    )
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    repos_dir = output_dir / "repos"
    artifacts_dir = output_dir / "artifacts"
    repos_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    summaries = []
    all_failures: list[str] = []
    for case in CASES:
        repo_dir = checkout_case(case, repos_dir)
        summary = validate_case(case, repo_dir, artifacts_dir)
        summaries.append(summary)
        for failure in summary["failures"]:
            all_failures.append(f"{case.name}: {failure}")

    result = {
        "schema_version": "ca9.real_repo_validation.v1",
        "case_count": len(CASES),
        "pass": not all_failures,
        "failures": all_failures,
        "cases": summaries,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

    return 1 if all_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
