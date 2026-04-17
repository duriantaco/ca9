from __future__ import annotations

import json
from pathlib import Path

from ca9.analysis.ast_scanner import pypi_to_import_name


def load_coverage(coverage_path: Path) -> dict:
    return json.loads(coverage_path.read_text())


def get_coverage_completeness(coverage_data: dict) -> float | None:
    totals = coverage_data.get("totals")
    if totals and "percent_covered" in totals:
        return totals["percent_covered"]
    return None


def get_covered_files(coverage_data: dict) -> dict[str, list[int]]:
    files: dict[str, list[int]] = {}
    file_data = coverage_data.get("files", {})
    for filepath, info in file_data.items():
        executed = info.get("executed_lines", [])
        if executed:
            files[filepath] = executed
    return files


def is_package_executed(
    package_name: str,
    covered_files: dict[str, list[int]],
) -> tuple[bool, list[str]]:
    import_name = pypi_to_import_name(package_name)
    path_fragment = import_name.replace(".", "/")

    matching_files: list[str] = []

    for filepath in covered_files:
        normalized = filepath.replace("\\", "/").lower()
        if (
            f"site-packages/{path_fragment}/" in normalized
            or f"site-packages/{path_fragment}.py" in normalized
            or (
                "site-packages/" in normalized
                and normalized.endswith(f"/{path_fragment}/__init__.py")
            )
            or ("site-packages/" in normalized and normalized.endswith(f"/{path_fragment}.py"))
        ):
            matching_files.append(filepath)

    return bool(matching_files), matching_files


def is_submodule_executed(
    submodule_paths: tuple[str, ...],
    file_hints: tuple[str, ...],
    covered_files: dict[str, list[int]],
) -> tuple[bool, list[str]]:
    matching_files: list[str] = []

    fragments: list[str] = []
    for submod in submodule_paths:
        fragment = submod.replace(".", "/")
        fragments.append(fragment)

    for filepath in covered_files:
        normalized = filepath.replace("\\", "/").lower()

        for fragment in fragments:
            if (
                f"site-packages/{fragment}/" in normalized
                or f"site-packages/{fragment}.py" in normalized
                or (
                    "site-packages/" in normalized
                    and normalized.endswith(f"/{fragment}/__init__.py")
                )
                or ("site-packages/" in normalized and normalized.endswith(f"/{fragment}.py"))
            ):
                matching_files.append(filepath)
                break
        else:
            for hint in file_hints:
                if normalized.endswith(f"/{hint.lower()}"):
                    matching_files.append(filepath)
                    break

    return bool(matching_files), matching_files


def are_call_sites_covered(
    call_sites: list[tuple[str, int]],
    covered_files: dict[str, list[int]],
) -> tuple[bool | None, int, int]:
    if not call_sites:
        return None, 0, 0

    norm_to_lines: dict[str, set[int]] = {}
    for filepath, lines in covered_files.items():
        norm = filepath.replace("\\", "/")
        norm_to_lines[norm] = set(lines)

    covered_count = 0
    matched_count = 0

    for file_path, line in call_sites:
        norm_path = file_path.replace("\\", "/")

        executed_lines = norm_to_lines.get(norm_path)
        if executed_lines is None:
            for cov_path, lines_set in norm_to_lines.items():
                if cov_path.endswith(norm_path) or norm_path.endswith(cov_path):
                    executed_lines = lines_set
                    break

        if executed_lines is None:
            continue

        matched_count += 1
        if line in executed_lines:
            covered_count += 1

    if matched_count == 0:
        return None, 0, 0

    return covered_count > 0, covered_count, matched_count
