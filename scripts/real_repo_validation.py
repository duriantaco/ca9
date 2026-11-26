from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from ca9.scanner import resolve_scan_inventory

FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/triage_benchmark"


@dataclass(frozen=True)
class Case:
    name: str
    repo_url: str
    commit: str
    min_inventory_packages: int = 0
    min_scan_results: int = 0
    required_scan_warning: str | None = None
    expected_scan_status: str = "complete"


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
        expected_scan_status="partial",
    ),
    Case(
        name="safedep-vet",
        repo_url="https://github.com/safedep/vet.git",
        commit="d4491496daec6f445803a039524ddab714be01b2",
        required_scan_warning="no declared dependencies",
        expected_scan_status="partial",
    ),
    Case(
        name="docker-compose",
        repo_url="https://github.com/docker/compose.git",
        commit="5becea4ca9f68875334c92f191a13482bcd6e5cf",
        min_inventory_packages=10,
        min_scan_results=1,
    ),
    Case(
        name="flask-release",
        repo_url="https://github.com/pallets/flask.git",
        commit="22d924701a6ae2e4cd01e9a15bbaf3946094af65",
        min_inventory_packages=6,
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
        if (repo_dir / ".git").is_dir():
            head = run(["git", "rev-parse", "HEAD"], cwd=repo_dir).strip()
            changes = run(["git", "status", "--porcelain"], cwd=repo_dir).strip()
            if head == case.commit and not changes:
                return repo_dir
        raise RuntimeError(f"{repo_dir}: use a fresh output directory or a clean pinned checkout")

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
    inventory_path.unlink(missing_ok=True)
    scan_path.unlink(missing_ok=True)

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
    coverage = scan.get("scan_coverage", {})
    if coverage.get("status") != case.expected_scan_status:
        failures.append(
            f"expected {case.expected_scan_status} scan coverage, got {coverage.get('status')}"
        )

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
    selection = None
    if case.name == "docker-compose":
        expected = set()
        for path in sorted(repo_dir.glob("requirements*.txt")):
            for line in path.read_text().splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                req = Requirement(line)
                if req.marker is None or req.marker.evaluate():
                    (pin,) = req.specifier
                    if pin.operator != "==":
                        raise ValueError(f"expected an exact reference pin in {path.name}")
                    expected.add((canonicalize_name(req.name), pin.version))
        selected = {(canonicalize_name(n), v) for n, v in resolve_scan_inventory(repo_dir).packages}
        selection = {
            "reference": len(expected),
            "matched": len(expected & selected),
            "missing": sorted(expected - selected),
            "extra": sorted(selected - expected),
        }
        if selected != expected:
            failures.append("scan selection differs from the applicable Docker Compose pins")
    return {
        "name": case.name,
        "repo_url": case.repo_url,
        "commit": case.commit,
        "inventory_summary": inventory_summary,
        "scan_summary": scan_summary,
        "scan_coverage": coverage,
        "reference_selection": selection,
        "scan_warnings": scan_warnings,
        "scan_verdict_counts": verdict_counts(scan_results),
        "scan_packages": sorted({result.get("package", "") for result in scan_results}),
        "scan_log": scan_log.strip().splitlines(),
        "failures": failures,
    }


def replay_verdicts(case: Case, repo_dir: Path, output_dir: Path) -> list[dict]:
    """Compare strict JSON and OpenVEX against independent package pins and call observations."""
    advisories = {row["id"]: row for row in json.loads((FIXTURES / "advisories.json").read_text())}
    controls = []
    if case.name == "docker-compose":
        pins = (repo_dir / "requirements.txt").read_text().lower().splitlines()
        if not {"pyyaml==5.4.1", "requests==2.24.0", "certifi==2020.6.20"}.issubset(pins):
            raise ValueError(
                "Docker Compose release dependency pins differ from the reviewed inputs"
            )
        controls = [
            ("fixed-release", "GHSA-8q59-q68h-6hv4", "5.4.1", None, "unreachable_static"),
            ("affected-version-only", "GHSA-j8r2-6x86-q33q", "2.24.0", None, "inconclusive"),
            ("conflicting-version", "PYSEC-2024-230", "2020.6.20", None, "inconclusive"),
        ]
    elif case.name == "flask-release":
        lock = (repo_dir / "uv.lock").read_text()
        if 'name = "werkzeug"\nversion = "3.1.5"' not in lock:
            raise ValueError("Flask release lock differs from the reviewed input")
        observed = load_json(FIXTURES / "flask_calls.json")
        if (
            observed["send_file"]["called_safe_join"]
            or not observed["send_from_directory"]["called_safe_join"]
        ):
            raise ValueError("Recorded safe_join call identities differ from the reviewed controls")
        advisory = "GHSA-g6x2-hccm-hh4m"
        controls = [
            ("static-only", advisory, "3.1.5", None, "inconclusive"),
            ("other-routine", advisory, "3.1.5", observed["send_file"], "inconclusive"),
            ("observed-routine", advisory, "3.1.5", observed["send_from_directory"], "reachable"),
        ]
    results = []
    for name, advisory_id, version, coverage, expected in controls:
        expected_vex = {
            "unreachable_static": "not_affected",
            "inconclusive": "under_investigation",
            "reachable": "affected",
        }[expected]
        dest = output_dir / case.name / name
        dest.mkdir(parents=True, exist_ok=True)
        record = advisories[advisory_id]
        package = {**record["affected"][0]["package"], "version": version}
        group = {"package": package, "vulnerabilities": [record]}
        source = {
            "type": "lockfile",
            "path": "uv.lock" if case.name == "flask-release" else "requirements.txt",
        }
        report = dest / "input.json"
        report.write_text(json.dumps({"results": [{"source": source, "packages": [group]}]}))
        cmd = [
            sys.executable,
            "-m",
            "ca9.cli",
            "check",
            str(report),
            "--repo",
            str(repo_dir),
            "--proof-standard",
            "strict",
            "--no-auto-coverage",
        ]
        if coverage:
            path = dest / "coverage.json"
            path.write_text(json.dumps({"files": coverage["files"]}))
            cmd += ["--coverage", str(path)]
        for fmt, filename in (("json", "verdict.json"), ("vex", "vex.json")):
            output = dest / filename
            output.unlink(missing_ok=True)
            run([*cmd, "-f", fmt, "-o", str(output)], allowed_exit_codes={0, 1, 2})
        (finding,) = load_json(dest / "verdict.json")["results"]
        (statement,) = load_json(dest / "vex.json")["statements"]
        actual, actual_vex = finding["verdict"], statement["status"]
        results.append(
            {
                "name": name,
                "advisory": advisory_id,
                "package": package,
                "expected": expected,
                "actual": actual,
                "expected_vex": expected_vex,
                "actual_vex": actual_vex,
                "pass": (actual, actual_vex) == (expected, expected_vex),
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real-repo ca9 validation cases.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/ca9-real-repo-validation"),
        help="Directory for cloned repos and JSON artifacts.",
    )
    parser.add_argument(
        "--replay-only",
        action="store_true",
        help="Run the fixed advisory and coverage controls, skipping live OSV queries.",
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
        if args.replay_only and case.name not in {"flask-release", "docker-compose"}:
            continue
        try:
            repo_dir = checkout_case(case, repos_dir)
            summary = (
                {"name": case.name, "commit": case.commit, "failures": []}
                if args.replay_only
                else validate_case(case, repo_dir, artifacts_dir)
            )
            summary["controls"] = replay_verdicts(case, repo_dir, artifacts_dir)
            summary["failures"].extend(
                row["name"] for row in summary["controls"] if not row["pass"]
            )
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            summary = {
                "name": case.name,
                "commit": case.commit,
                "failures": [str(exc)],
                "status": "error",
            }
        summaries.append(summary)
        for failure in summary["failures"]:
            all_failures.append(f"{case.name}: {failure}")

    controls = [row for summary in summaries for row in summary.get("controls", [])]
    result = {
        "schema_version": "ca9.real_repo_validation.v1",
        "case_count": len(summaries),
        "replay_only": args.replay_only,
        "pass": not all_failures,
        "failures": all_failures,
        "labelled_decisions": {
            "total": len(controls),
            "correct": sum(row["pass"] for row in controls),
            "false_reachable": sum(
                row["actual"] == "reachable" and row["actual"] != row["expected"]
                for row in controls
            ),
            "incorrect_dismissals": sum(
                row["actual_vex"] == "not_affected" and row["actual_vex"] != row["expected_vex"]
                for row in controls
            ),
            "inconclusive": sum(row["actual"] == "inconclusive" for row in controls),
        },
        "cases": summaries,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

    return 1 if all_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
