from __future__ import annotations

from pathlib import Path

from ca9.analysis.api_usage import find_api_usage
from ca9.analysis.ast_scanner import (
    collect_imports_from_repo,
    is_package_imported,
    is_submodule_imported,
    pypi_to_import_name,
    resolve_transitive_deps,
)
from ca9.analysis.coverage_reader import (
    get_covered_files,
    is_package_executed,
    is_submodule_executed,
    load_coverage,
)
from ca9.analysis.vuln_matcher import extract_affected_component
from ca9.intel_rules import VulnIntelResolution, resolve_vuln_intel
from ca9.models import (
    AffectedComponent,
    ApiUsageHit,
    Evidence,
    Report,
    Verdict,
    VerdictResult,
    Vulnerability,
)
from ca9.scoring import compute_confidence
from ca9.version import check_version


def collect_evidence(
    vuln: Vulnerability,
    import_name: str,
    repo_imports: set[str],
    transitive_deps: dict[str, str],
    covered_files: dict[str, list[int]] | None,
    component: AffectedComponent | None = None,
    intel: VulnIntelResolution | None = None,
    api_hits: list[ApiUsageHit] | None = None,
) -> Evidence:
    warnings: list[str] = []

    version_result = check_version(vuln.package_version, vuln.affected_ranges)
    version_in_range = version_result.affected
    if version_result.error:
        warnings.append(version_result.error)

    direct = is_package_imported(vuln.package_name, repo_imports)
    if not direct:
        dep_of = transitive_deps.get(vuln.package_name.lower())
    else:
        dep_of = None
    package_imported = direct or dep_of is not None

    if direct:
        dependency_kind = "direct"
    elif dep_of is not None:
        dependency_kind = "transitive"
    else:
        dependency_kind = None

    if component is None:
        component = extract_affected_component(vuln)
    affected_component_source = component.extraction_source
    affected_component_confidence = _confidence_str_to_int(component.confidence)

    submodule_imported: bool | None = None
    has_submodule_info = component.submodule_paths and component.confidence in ("high", "medium")

    if has_submodule_info and package_imported:
        sub_imported, _matched = is_submodule_imported(component.submodule_paths, repo_imports)
        if sub_imported:
            submodule_imported = True
        else:
            has_dotted_imports = any(
                imp.lower().startswith(import_name.lower() + ".") for imp in repo_imports
            )
            if has_dotted_imports:
                submodule_imported = False
            else:
                submodule_imported = None

    coverage_seen: bool | None = None
    coverage_files: tuple[str, ...] = ()

    if covered_files is not None and package_imported:
        if has_submodule_info:
            executed, matching_files = is_submodule_executed(
                component.submodule_paths, component.file_hints, covered_files
            )
        else:
            executed, matching_files = is_package_executed(vuln.package_name, covered_files)
        coverage_seen = executed
        if matching_files:
            coverage_files = tuple(matching_files)
        else:
            coverage_files = ()

    if component.warnings:
        warnings.extend(component.warnings)

    # API-level reachability from intel rules
    api_targets_fqnames: tuple[str, ...] = ()
    api_usage_hits: tuple[ApiUsageHit, ...] = ()
    api_usage_seen: bool | None = None
    api_usage_confidence: int | None = None
    intel_rule_ids: tuple[str, ...] = ()

    if intel and intel.matched_rules:
        intel_rule_ids = tuple(intel.rule_ids)
        if intel.api_targets:
            api_targets_fqnames = tuple(t.fqname for t in intel.api_targets)

        if api_hits is not None:
            api_usage_hits = tuple(api_hits)
            api_usage_seen = len(api_hits) > 0
            if api_hits:
                api_usage_confidence = max(h.confidence for h in api_hits)
        elif intel.api_targets:
            # Had targets but no scan was run (e.g. package not imported)
            api_usage_seen = None

    return Evidence(
        version_in_range=version_in_range,
        dependency_kind=dependency_kind,
        package_imported=package_imported,
        submodule_imported=submodule_imported,
        affected_component_source=affected_component_source,
        affected_component_confidence=affected_component_confidence,
        coverage_seen=coverage_seen,
        coverage_files=coverage_files,
        external_fetch_warnings=tuple(warnings),
        api_targets=api_targets_fqnames,
        api_usage_hits=api_usage_hits,
        api_usage_seen=api_usage_seen,
        api_usage_confidence=api_usage_confidence,
        intel_rule_ids=intel_rule_ids,
    )


def _confidence_str_to_int(confidence: str) -> int:
    return {"high": 80, "medium": 55, "low": 25}.get(confidence, 10)


def derive_verdict(
    vuln: Vulnerability,
    evidence: Evidence,
    import_name: str,
    component,
    dep_of: str | None,
    has_coverage: bool,
) -> VerdictResult:
    if evidence.version_in_range is False:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_STATIC,
            reason=(
                f"'{vuln.package_name}' {vuln.package_version} is outside "
                f"the affected version range"
            ),
            imported_as=import_name,
            affected_component=component,
            evidence=evidence,
        )

    if not evidence.package_imported:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_STATIC,
            reason=(
                f"'{vuln.package_name}' is not imported and not a "
                f"dependency of any imported package"
            ),
            imported_as=import_name,
            affected_component=component,
            evidence=evidence,
        )

    if evidence.dependency_kind == "direct":
        trace = f"'{import_name}' is directly imported"
    else:
        trace = f"'{vuln.package_name}' is a dependency of {dep_of}"

    has_submodule_info = component.submodule_paths and component.confidence in ("high", "medium")

    if has_submodule_info:
        if evidence.submodule_imported is False:
            submod_list = ", ".join(component.submodule_paths)
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_STATIC,
                reason=f"{trace}, but affected submodule {submod_list} is not imported",
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if not has_coverage:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"{trace}, but no coverage data to confirm execution",
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if evidence.coverage_seen:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.REACHABLE,
                reason=(
                    f"{trace} and submodule code was executed "
                    f"in {len(evidence.coverage_files)} file(s)"
                ),
                imported_as=import_name,
                executed_files=list(evidence.coverage_files),
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )
        else:
            submod_list = ", ".join(component.submodule_paths)
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_DYNAMIC,
                reason=(
                    f"{trace}, {submod_list} imported but 0 files executed in tests"
                ),
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

    # API-level reachability can upgrade to REACHABLE even without coverage
    if evidence.api_usage_seen is True:
        api_detail = f"{len(evidence.api_usage_hits)} vulnerable API call(s) found"
        if has_coverage and evidence.coverage_seen:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.REACHABLE,
                reason=f"{trace}, {api_detail}, and code executed in {len(evidence.coverage_files)} file(s)",
                imported_as=import_name,
                executed_files=list(evidence.coverage_files),
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.REACHABLE,
            reason=f"{trace} and {api_detail}",
            imported_as=import_name,
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )

    if not has_coverage:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.INCONCLUSIVE,
            reason=f"{trace}, but no coverage data to confirm execution",
            imported_as=import_name,
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )

    if evidence.coverage_seen:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.REACHABLE,
            reason=(
                f"{trace} and code was executed in {len(evidence.coverage_files)} file(s)"
            ),
            imported_as=import_name,
            executed_files=list(evidence.coverage_files),
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )
    else:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_DYNAMIC,
            reason=f"{trace}, but no code was executed in tests",
            imported_as=import_name,
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )


def analyze(
    vulnerabilities: list[Vulnerability],
    repo_path: Path,
    coverage_path: Path | None = None,
) -> Report:
    repo_imports = collect_imports_from_repo(repo_path)
    transitive_deps = resolve_transitive_deps(repo_imports)

    covered_files: dict[str, list[int]] | None = None
    if coverage_path:
        coverage_data = load_coverage(coverage_path)
        covered_files = get_covered_files(coverage_data)

    # Phase 1: Resolve intel rules for all vulns, collect all API targets
    vuln_intel: dict[str, VulnIntelResolution] = {}
    all_api_targets = []
    seen_fqnames: set[str] = set()

    for vuln in vulnerabilities:
        intel = resolve_vuln_intel(vuln)
        vuln_intel[vuln.id] = intel
        for t in intel.api_targets:
            if t.fqname not in seen_fqnames:
                seen_fqnames.add(t.fqname)
                all_api_targets.append(t)

    # Phase 2: Run API usage scan once for all targets
    hits_by_target: dict[str, list[ApiUsageHit]] = {}
    if all_api_targets:
        all_hits = find_api_usage(repo_path, all_api_targets)
        for hit in all_hits:
            hits_by_target.setdefault(hit.matched_target, []).append(hit)

    # Phase 3: Build evidence and verdicts per vuln
    results: list[VerdictResult] = []

    for vuln in vulnerabilities:
        import_name = pypi_to_import_name(vuln.package_name)
        component = extract_affected_component(vuln)

        intel = vuln_intel.get(vuln.id)

        # Collect API hits for this vuln's targets
        vuln_api_hits: list[ApiUsageHit] | None = None
        if intel and intel.api_targets:
            vuln_api_hits = []
            for t in intel.api_targets:
                vuln_api_hits.extend(hits_by_target.get(t.fqname, []))

        evidence = collect_evidence(
            vuln, import_name, repo_imports, transitive_deps, covered_files,
            component, intel=intel, api_hits=vuln_api_hits,
        )

        if evidence.dependency_kind == "transitive":
            dep_of = transitive_deps.get(vuln.package_name.lower())
        else:
            dep_of = None

        result = derive_verdict(
            vuln, evidence, import_name, component, dep_of,
            has_coverage=covered_files is not None,
        )
        result.confidence_score = compute_confidence(evidence, result.verdict)
        results.append(result)

    if coverage_path:
        coverage_path_str = str(coverage_path)
    else:
        coverage_path_str = None

    return Report(
        results=results,
        repo_path=str(repo_path),
        coverage_path=coverage_path_str,
    )
