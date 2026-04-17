from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

SEARCH_PATHS = (
    "coverage.json",
    ".coverage.json",
    "htmlcov/coverage.json",
    ".ca9/coverage.json",
)

PYTEST_TIMEOUT = 300  # 5 minutes


def discover_coverage(repo_path: Path) -> Path | None:
    for relpath in SEARCH_PATHS:
        candidate = repo_path / relpath
        if candidate.is_file():
            return candidate
    return None


def generate_coverage(repo_path: Path) -> Path | None:
    if not shutil.which("pytest"):
        print(
            "ca9: pytest not found -- install pytest and pytest-cov, or pass --coverage manually.",
            file=sys.stderr,
        )
        return None

    output_dir = repo_path / ".ca9"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "coverage.json"
    output_path.unlink(missing_ok=True)

    print("ca9: No coverage data found. Running pytest to generate it...", file=sys.stderr)

    try:
        result = subprocess.run(
            [
                "pytest",
                "--cov",
                "--cov-report",
                f"json:{output_path}",
                "--no-header",
                "-q",
            ],
            cwd=str(repo_path),
            timeout=PYTEST_TIMEOUT,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        print("ca9: pytest timed out after 5 minutes.", file=sys.stderr)
        return None
    except OSError as exc:
        print(f"ca9: Failed to run pytest: {exc}", file=sys.stderr)
        return None

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if detail:
            detail = detail.splitlines()[-1]
            print(f"ca9: pytest failed while generating coverage: {detail}", file=sys.stderr)
        else:
            print("ca9: pytest failed while generating coverage.", file=sys.stderr)
        return None

    if not output_path.is_file():
        print(
            "ca9: pytest ran but did not produce coverage data. Hint: is pytest-cov installed?",
            file=sys.stderr,
        )
        return None

    try:
        json.loads(output_path.read_text())
    except (OSError, json.JSONDecodeError):
        print("ca9: pytest produced an invalid coverage.json file.", file=sys.stderr)
        return None

    print(f"ca9: Coverage data written to {output_path}", file=sys.stderr)
    return output_path


def resolve_coverage(
    explicit_path: Path | None,
    repo_path: Path,
    auto_generate: bool = True,
) -> Path | None:
    if explicit_path is not None:
        return explicit_path

    if not auto_generate:
        return None

    discovered = discover_coverage(repo_path)
    if discovered is not None:
        print(f"ca9: Found coverage data at ./{discovered.relative_to(repo_path)}", file=sys.stderr)
        return discovered

    return generate_coverage(repo_path)
