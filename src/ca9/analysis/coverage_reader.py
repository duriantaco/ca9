from __future__ import annotations

import json
import math
import posixpath
from dataclasses import dataclass
from pathlib import Path

from ca9.analysis.ast_scanner import pypi_to_import_name


def load_coverage(coverage_path: Path) -> dict:
    return json.loads(coverage_path.read_text())


def get_coverage_completeness(coverage_data: dict) -> float | None:
    totals = coverage_data.get("totals")
    if isinstance(totals, dict):
        pct = totals.get("percent_covered")
        if type(pct) in (int, float) and 0 <= pct <= 100 and math.isfinite(pct):
            return float(pct)
    return None


@dataclass(frozen=True)
class FileCoverage:
    executed_lines: tuple[int, ...] = ()
    missing_lines: tuple[int, ...] = ()
    # Record validity concerns the supplied metadata, not instrumentation scope.
    record_valid: bool = True


@dataclass(frozen=True)
class CoverageObservation:
    scope: str
    seen: bool | None
    measured_files: tuple[str, ...] = ()
    executed_files: tuple[str, ...] = ()
    unmeasured_targets: tuple[str, ...] = ()


def _valid_lines(value: object) -> bool:
    return isinstance(value, list) and all(type(line) is int and line > 0 for line in value)


def get_measured_files(coverage_data: dict) -> dict[str, FileCoverage]:
    """Retain reported statements, including explicit zero-hit files.

    A report entry is not proof of complete instrumentation. Missing/excluded
    statements must remain distinguishable from a file absent from the report.
    Malformed records cannot establish negative evidence.
    """
    files: dict[str, FileCoverage] = {}
    file_data = coverage_data.get("files", {})
    if not isinstance(file_data, dict):
        return files
    for filepath, info in file_data.items():
        if not isinstance(filepath, str):
            continue
        if not isinstance(info, dict):
            files[filepath] = FileCoverage(record_valid=False)
            continue
        executed = info.get("executed_lines")
        missing = info.get("missing_lines", [])
        excluded = info.get("excluded_lines", [])
        record_valid = all(_valid_lines(lines) for lines in (executed, missing, excluded))
        # A malformed missing/excluded field cannot erase otherwise valid hits.
        # Negative evidence needs every field to be valid, including exclusions.
        executed_lines = tuple(sorted(set(executed))) if _valid_lines(executed) else ()
        files[filepath] = FileCoverage(
            executed_lines=executed_lines,
            missing_lines=tuple(sorted(set(missing) - set(excluded) - set(executed)))
            if record_valid
            else (),
            record_valid=record_valid,
        )
    return files


def get_covered_files(coverage_data: dict) -> dict[str, list[int]]:
    return {
        filepath: list(info.executed_lines)
        for filepath, info in get_measured_files(coverage_data).items()
        if info.executed_lines
    }


def _matches_import_path(filepath: str, import_path: str) -> bool:
    normalized = "/" + posixpath.normpath(filepath.replace("\\", "/")).lower().lstrip("/")
    fragment = import_path.replace(".", "/").lower()
    return f"/site-packages/{fragment}/" in normalized or normalized.endswith(
        f"/site-packages/{fragment}.py"
    )


def observe_coverage(
    package_name: str,
    measured_files: dict[str, FileCoverage],
    submodule_paths: tuple[str, ...] = (),
    file_hints: tuple[str, ...] = (),
) -> CoverageObservation:
    """Describe the affected scope present in this report, not global reachability."""
    import_name = pypi_to_import_name(package_name)
    targets = submodule_paths or (import_name,)
    matched: set[str] = set()
    unmeasured: list[str] = []
    for target in targets:
        target_files = [path for path in measured_files if _matches_import_path(path, target)]
        matched.update(target_files)
        if any(not measured_files[path].record_valid for path in target_files) or not any(
            measured_files[path].executed_lines or measured_files[path].missing_lines
            for path in target_files
        ):
            unmeasured.append(target)

    # A hint can contribute positive evidence only within the affected package.
    # It cannot fill in an unreported target for a negative observation.
    for path in measured_files:
        normalized = path.replace("\\", "/").lower()
        if _matches_import_path(path, import_name) and any(
            normalized.endswith("/" + hint.replace("\\", "/").lower()) for hint in file_hints
        ):
            matched.add(path)

    measured = tuple(
        sorted(
            path
            for path in matched
            if measured_files[path].executed_lines or measured_files[path].missing_lines
        )
    )
    executed = tuple(path for path in measured if measured_files[path].executed_lines)
    if not matched:
        scope = "not_reported"
    elif not measured:
        scope = "no_statements"
    elif unmeasured:
        scope = "partial"
    else:
        scope = "reported"
    return CoverageObservation(
        scope=scope,
        seen=True if executed else None if unmeasured else False,
        measured_files=measured,
        executed_files=executed,
        unmeasured_targets=tuple(unmeasured),
    )


def is_package_executed(
    package_name: str,
    covered_files: dict[str, list[int]],
) -> tuple[bool, list[str]]:
    import_name = pypi_to_import_name(package_name)
    matching_files = [
        filepath
        for filepath, lines in covered_files.items()
        if lines and _matches_import_path(filepath, import_name)
    ]

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

    for filepath, lines in covered_files.items():
        if not lines:
            continue
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
    *,
    missing_files: dict[str, list[int]] | None = None,
) -> tuple[bool | None, int, int]:
    if not call_sites:
        return None, 0, 0

    def normalize(path: str) -> str:
        return posixpath.normpath(path.replace("\\", "/"))

    paths = set(covered_files) | set(missing_files or {})
    norm_to_lines: dict[str, set[int]] = {}
    norm_to_missing: dict[str, set[int]] = {}
    for path in paths:
        normalized = normalize(path)
        norm_to_lines.setdefault(normalized, set()).update(covered_files.get(path, ()))
        norm_to_missing.setdefault(normalized, set()).update((missing_files or {}).get(path, ()))

    covered_count = 0
    matched_count = 0

    for file_path, line in call_sites:
        norm_path = normalize(file_path)
        if norm_path in norm_to_lines:
            matched_path = norm_path
        else:
            candidates = [
                path
                for path in norm_to_lines
                if path.endswith("/" + norm_path) or norm_path.endswith("/" + path)
            ]
            if len(candidates) != 1:
                continue
            matched_path = candidates[0]

        if line in norm_to_lines[matched_path]:
            matched_count += 1
            covered_count += 1
        elif line in norm_to_missing[matched_path]:
            matched_count += 1
        else:
            continue

    if covered_count:
        return True, covered_count, matched_count
    if matched_count != len(call_sites):
        return None, 0, matched_count
    return False, 0, matched_count
