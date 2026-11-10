from __future__ import annotations

import sys
from pathlib import Path

from packaging.utils import canonicalize_name

from ca9.advisory import normalize_ecosystem
from ca9.analysis.api_usage import find_api_usage
from ca9.analysis.ast_scanner import (
    collect_imports_from_repo,
    discover_declared_dependencies,
    find_unresolved_imports,
    imports_any_module,
    resolve_optional_dependents,
    resolve_transitive_deps,
)
from ca9.analysis.coverage_reader import (
    FileCoverage,
    are_call_sites_covered,
    get_coverage_completeness,
    get_covered_files,
    get_measured_files,
    load_coverage,
    observe_coverage,
)
from ca9.analysis.import_names import (
    EnvironmentIndex,
    environment_index,
    reset_environment_index,
)
from ca9.analysis.indirect_use import (
    RepoReferences,
    collect_indirect_use_signals,
    scan_repo_references,
)
from ca9.analysis.package_imports import submodules_loaded_by_package
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


def _report_dependency_kind(vuln: Vulnerability) -> str | None:
    if vuln.report_dependency_kind in ("direct", "transitive"):
        return vuln.report_dependency_kind

    if vuln.report_dependency_chain:
        if len(vuln.report_dependency_chain) == 1:
            return "direct"
        return "transitive"

    return None


def _report_dependency_root(vuln: Vulnerability) -> str | None:
    kind = _report_dependency_kind(vuln)
    if kind != "transitive" or not vuln.report_dependency_chain:
        return None
    return vuln.report_dependency_chain[0]


def _apply_proof_standard(result: VerdictResult, proof_standard: str) -> VerdictResult:
    if proof_standard != "strict":
        return result

    evidence = result.evidence
    if evidence is None:
        return result

    adjustment: str | None = None

    if result.verdict == Verdict.UNREACHABLE_STATIC:
        if evidence.version_in_range is False:
            adjustment = None
        elif not evidence.package_imported and evidence.declared_direct_dependency:
            adjustment = (
                "strict proof downgraded this suppression: declared but no import found; "
                "may be used via CLI, plugin, or string-based loading"
            )
        elif evidence.package_imported and evidence.submodule_imported is False:
            adjustment = (
                "strict proof downgraded this suppression because static analysis of the "
                "package's own imports cannot rule out plugins, configuration strings, or "
                "dynamic loading of the affected submodule"
            )
        elif evidence.dependency_graph_source == "environment":
            adjustment = (
                "strict proof downgraded this suppression because the dependency graph "
                "came from the ambient environment rather than the report"
            )
    elif result.verdict == Verdict.UNREACHABLE_DYNAMIC:
        adjustment = (
            "strict proof downgraded this suppression because non-execution in the supplied "
            "tests does not prove unreachability; overall coverage percentage cannot establish "
            "that all affected execution paths were exercised"
        )

    if adjustment is None:
        return result

    return VerdictResult(
        vulnerability=result.vulnerability,
        verdict=Verdict.INCONCLUSIVE,
        reason=f"{result.reason}; {adjustment}",
        imported_as=result.imported_as,
        executed_files=list(result.executed_files),
        dependency_of=result.dependency_of,
        affected_component=result.affected_component,
        evidence=result.evidence,
        original_verdict=result.verdict,
        policy_adjustment=adjustment,
    )


def collect_evidence(
    vuln: Vulnerability,
    import_name: str,
    repo_imports: set[str],
    transitive_deps: dict[str, str],
    dependency_graph_available: bool,
    declared_direct_deps: set[str],
    covered_files: dict[str, list[int]] | None,
    component: AffectedComponent | None = None,
    intel: VulnIntelResolution | None = None,
    api_hits: list[ApiUsageHit] | None = None,
    coverage_completeness: float | None = None,
    threat_intel_data: object | None = None,
    production_observed: bool | None = None,
    production_trace_count: int = 0,
    global_warnings: tuple[str, ...] = (),
    measured_files: dict[str, FileCoverage] | None = None,
    *,
    references: RepoReferences | None = None,
    optional_dependents: dict[str, str] | None = None,
    unresolved_imports: tuple[str, ...] = (),
) -> Evidence:
    warnings: list[str] = list(global_warnings)

    version_result = check_version(vuln.package_version, vuln.affected_ranges)
    version_in_range = version_result.affected
    if version_result.error:
        warnings.append(version_result.error)

    index = environment_index()
    resolution = index.resolve(vuln.package_name)
    import_names = resolution.names
    if import_name not in import_names:
        import_names = (import_name, *import_names)
    unproven_import_mappings: list[str] = []

    vuln_name_key = canonicalize_name(vuln.package_name)
    report_dep_kind = _report_dependency_kind(vuln)
    report_dep_root = _report_dependency_root(vuln)
    direct = imports_any_module(import_names, repo_imports)
    declared_direct_dependency = (
        vuln_name_key in declared_direct_deps or report_dep_kind == "direct"
    )
    report_graph_available = report_dep_kind == "direct" or report_dep_root is not None
    dependency_graph_source = ""
    if not direct:
        if report_dep_root is not None:
            root_resolution = index.resolve(report_dep_root)
            if imports_any_module(root_resolution.names, repo_imports):
                dep_of = report_dep_root
            else:
                dep_of = None
                if not root_resolution.authoritative:
                    unproven_import_mappings.append(report_dep_root)
            dependency_graph_source = "report"
        else:
            dep_of = transitive_deps.get(vuln_name_key)
            if dep_of is not None:
                dependency_graph_source = "environment"
    else:
        dep_of = None
    package_imported = direct or dep_of is not None
    if not package_imported and not resolution.authoritative:
        unproven_import_mappings.insert(0, vuln.package_name)

    if direct:
        dependency_kind = "direct"
    elif dep_of is not None:
        dependency_kind = "transitive"
    else:
        dependency_kind = None

    # The environment graph covers only installed distributions; an imported
    # package missing from the environment hides its own dependencies.
    graph_unresolved: tuple[str, ...] = ()
    environment_graph_complete = dependency_graph_available
    if dependency_graph_available and unresolved_imports and not report_graph_available:
        environment_graph_complete = False
        if not package_imported:
            graph_unresolved = tuple(unresolved_imports)

    if not dependency_graph_source:
        if report_graph_available:
            dependency_graph_source = "report"
        elif dependency_graph_available:
            dependency_graph_source = "environment"

    indirect_use_signals: tuple[str, ...] = ()
    if not package_imported:
        indirect_use_signals = collect_indirect_use_signals(
            vuln.package_name,
            import_names,
            references,
            index,
            optional_dependents,
        )

    if component is None:
        component = extract_affected_component(vuln)
    affected_component_source = component.extraction_source
    affected_component_confidence = _confidence_str_to_int(component.confidence)

    submodule_imported: bool | None = None
    submodule_evidence = ""
    has_submodule_info = component.submodule_paths and component.confidence in ("high", "medium")

    if has_submodule_info and package_imported:
        submodule_imported, submodule_evidence = _submodule_import_evidence(
            vuln,
            import_names,
            component.submodule_paths,
            repo_imports,
            references,
            index,
            app_imports_package=direct,
        )

    coverage_seen: bool | None = None
    coverage_files: tuple[str, ...] = ()
    coverage_scope = "unavailable"
    coverage_measured_files: tuple[str, ...] = ()
    coverage_unmeasured_targets: tuple[str, ...] = ()

    if covered_files is not None:
        # Legacy callers supplying execution alone can establish a positive
        # observation, but cannot reconstruct explicit missing statements.
        measurement = (
            measured_files
            if measured_files is not None
            else {
                path: FileCoverage(executed_lines=tuple(lines))
                for path, lines in covered_files.items()
            }
        )
        observation = observe_coverage(
            vuln.package_name,
            measurement,
            component.submodule_paths if has_submodule_info else (),
            component.file_hints if has_submodule_info else (),
        )
        coverage_seen = observation.seen
        coverage_files = observation.executed_files
        coverage_scope = observation.scope
        coverage_measured_files = observation.measured_files
        coverage_unmeasured_targets = observation.unmeasured_targets
        if observation.unmeasured_targets:
            warnings.append(
                "coverage report lacks executable statement evidence for "
                + ", ".join(observation.unmeasured_targets)
                + "; include the affected code in coverage source and check run/report "
                "omit settings before collecting fresh coverage"
            )

    if component.warnings:
        warnings.extend(component.warnings)

    api_targets_fqnames: tuple[str, ...] = ()
    api_usage_hits: tuple[ApiUsageHit, ...] = ()
    api_usage_seen: bool | None = None
    api_usage_confidence: int | None = None
    api_call_sites_covered: bool | None = None
    intel_rule_ids: tuple[str, ...] = ()

    if intel and intel.matched_rules:
        intel_rule_ids = tuple(intel.rule_ids)
        if intel.api_targets:
            api_targets_fqnames = tuple(t.fqname for t in intel.api_targets)

        if api_hits is not None:
            api_usage_hits = tuple(api_hits)
            call_hits = [h for h in api_hits if h.match_type != "symbol_reference"]
            api_usage_seen = len(call_hits) > 0
            if api_hits:
                api_usage_confidence = max(h.confidence for h in api_hits)

                if covered_files is not None:
                    call_sites = [(h.file_path, h.line) for h in call_hits]
                    sites_covered, _cov_count, _total = are_call_sites_covered(
                        call_sites,
                        covered_files,
                        missing_files={
                            path: list(info.missing_lines)
                            for path, info in (measured_files or {}).items()
                        },
                    )
                    api_call_sites_covered = sites_covered
        elif intel.api_targets:
            api_usage_seen = None

    return Evidence(
        version_in_range=version_in_range,
        dependency_kind=dependency_kind,
        dependency_graph_available=environment_graph_complete or report_graph_available,
        dependency_graph_source=dependency_graph_source,
        declared_direct_dependency=declared_direct_dependency,
        package_imported=package_imported,
        submodule_imported=submodule_imported,
        report_dependency_chain=vuln.report_dependency_chain,
        affected_component_source=affected_component_source,
        affected_component_confidence=affected_component_confidence,
        coverage_seen=coverage_seen,
        coverage_files=coverage_files,
        external_fetch_warnings=tuple(warnings),
        api_targets=api_targets_fqnames,
        api_usage_hits=api_usage_hits,
        api_usage_seen=api_usage_seen,
        api_usage_confidence=api_usage_confidence,
        api_call_sites_covered=api_call_sites_covered,
        intel_rule_ids=intel_rule_ids,
        coverage_completeness_pct=coverage_completeness,
        threat_intel=threat_intel_data,
        production_observed=production_observed,
        production_trace_count=production_trace_count,
        coverage_scope=coverage_scope,
        coverage_measured_files=coverage_measured_files,
        coverage_unmeasured_targets=coverage_unmeasured_targets,
        import_names=import_names,
        import_name_source=resolution.source,
        package_installed=resolution.installed,
        indirect_use_signals=indirect_use_signals,
        unproven_import_mappings=tuple(unproven_import_mappings),
        submodule_evidence=submodule_evidence,
        dependency_graph_unresolved=graph_unresolved,
    )


def _match_submodule(submodule_paths: tuple[str, ...], names: set[str]) -> str | None:
    # Only the target or something beneath it proves the target loads; a parent
    # package import is settled by the package's own import graph instead.
    for submod in submodule_paths:
        target = submod.lower()
        for name in sorted(names):
            lowered = name.lower()
            if lowered == target or lowered.startswith(target + "."):
                return name
    return None


def _submodule_import_evidence(
    vuln: Vulnerability,
    import_names: tuple[str, ...],
    submodule_paths: tuple[str, ...],
    repo_imports: set[str],
    references: RepoReferences | None,
    index: EnvironmentIndex,
    *,
    app_imports_package: bool,
) -> tuple[bool | None, str]:
    matched = _match_submodule(submodule_paths, repo_imports)
    if matched is not None:
        return True, f"'{matched}' is imported"

    string_imports = dict(references.dotted_strings) if references else {}
    matched = _match_submodule(submodule_paths, set(string_imports))
    if matched is not None:
        return True, f"'{matched}' is named as a module string in {string_imports[matched]}"

    if not app_imports_package:
        return None, "it is loaded through a dependent package whose imports were not analyzed"

    installed_version = index.version(vuln.package_name)
    if installed_version is None:
        return None, (
            f"'{vuln.package_name}' source is not installed in the analysis environment, so "
            "the package's own imports of the affected submodule cannot be ruled out"
        )
    if not _same_version(installed_version, vuln.package_version):
        return None, (
            f"installed '{vuln.package_name}' is {installed_version}, not the reported "
            f"{vuln.package_version}, so its source cannot rule out internal imports"
        )

    app_imports = repo_imports | set(string_imports)
    for name in import_names:
        targets = tuple(
            path for path in submodule_paths if path == name or path.startswith(name + ".")
        )
        if not targets:
            continue
        return submodules_loaded_by_package(name, app_imports, targets)
    return None, "the affected submodule is outside the package's import names"


def _same_version(left: str, right: str) -> bool:
    from packaging.version import InvalidVersion, Version

    try:
        return Version(left) == Version(right)
    except InvalidVersion:
        return left == right


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

    if evidence.dependency_kind == "direct":
        trace = f"'{import_name}' is directly imported"
    elif evidence.package_imported:
        trace = f"'{vuln.package_name}' is a dependency of {dep_of}"
    else:
        trace = f"'{vuln.package_name}' was not detected by static import analysis"

    has_submodule_info = component.submodule_paths and component.confidence in ("high", "medium")

    # Observed execution takes precedence over an incomplete static import view.
    # The affected-version check above remains independent of execution evidence.
    if has_coverage and evidence.api_usage_seen is True and evidence.api_call_sites_covered is True:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.REACHABLE,
            reason=f"{trace}, vulnerable API call sites executed in tests",
            imported_as=import_name,
            executed_files=list(evidence.coverage_files),
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )

    if has_coverage and evidence.coverage_seen is True:
        verdict = Verdict.REACHABLE
        if has_submodule_info:
            detail = f"submodule code was executed in {len(evidence.coverage_files)} file(s)"
        elif evidence.api_usage_seen is True:
            detail = f"{len(evidence.api_usage_hits)} vulnerable API call(s) found"
            if evidence.api_call_sites_covered is False:
                # Package execution alone does not establish an affected API call.
                verdict = Verdict.INCONCLUSIVE
                detail += ", but call sites not executed in tests"
            else:
                detail += f", and code executed in {len(evidence.coverage_files)} file(s)"
        else:
            detail = f"code was executed in {len(evidence.coverage_files)} file(s)"
        return VerdictResult(
            vulnerability=vuln,
            verdict=verdict,
            reason=f"{trace} and {detail}",
            imported_as=import_name,
            executed_files=list(evidence.coverage_files),
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )

    if evidence.production_observed is True and (
        not evidence.package_imported or has_submodule_info and evidence.submodule_imported is False
    ):
        # A package-level production observation refutes absence, but does not
        # identify which affected submodule or API executed.
        return _inconclusive_coverage(vuln, evidence, import_name, component, dep_of, trace)

    if not evidence.package_imported:
        if evidence.api_usage_seen is True:
            # A located call into the vulnerable API outweighs a missed import.
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"no import of '{vuln.package_name}' was matched, but "
                    f"{len(evidence.api_usage_hits)} vulnerable API call(s) were found"
                ),
                imported_as=import_name,
                affected_component=component,
                evidence=evidence,
            )

        if evidence.unproven_import_mappings:
            guessed = ", ".join(f"'{name}'" for name in evidence.unproven_import_mappings)
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"no import of '{vuln.package_name}' was found, but the import name for "
                    f"{guessed} was guessed (no installed metadata or curated mapping), so a "
                    "missing import does not prove it is unused"
                ),
                imported_as=import_name,
                affected_component=component,
                evidence=evidence,
            )

        if evidence.indirect_use_signals:
            if evidence.declared_direct_dependency:
                lead = f"'{vuln.package_name}' is declared as a direct dependency with no import"
            else:
                lead = f"'{vuln.package_name}' is not imported"
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"{lead}, but it may be used without an import: "
                    + "; ".join(evidence.indirect_use_signals[:3])
                ),
                imported_as=import_name,
                affected_component=component,
                evidence=evidence,
            )

        if evidence.declared_direct_dependency:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_STATIC,
                reason=f"'{vuln.package_name}' is declared as a direct dependency but never imported",
                imported_as=import_name,
                affected_component=component,
                evidence=evidence,
            )

        if not evidence.dependency_graph_available:
            if evidence.dependency_graph_unresolved:
                missing = ", ".join(evidence.dependency_graph_unresolved[:5])
                reason = (
                    f"'{vuln.package_name}' is not directly imported, but the dependency graph is "
                    f"incomplete because imported modules ({missing}) are not installed in the "
                    "analysis environment"
                )
            else:
                reason = (
                    f"'{vuln.package_name}' is not directly imported, but no dependency graph "
                    f"is available to prove it is unused transitively"
                )
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=reason,
                imported_as=import_name,
                affected_component=component,
                evidence=evidence,
            )

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

    if evidence.api_usage_seen is True:
        api_detail = f"{len(evidence.api_usage_hits)} vulnerable API call(s) found"

        if has_coverage and evidence.api_call_sites_covered is False:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"{trace}, {api_detail}, but call sites not executed in tests",
                imported_as=import_name,
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

    if has_submodule_info:
        if evidence.submodule_imported is False:
            submod_list = ", ".join(component.submodule_paths)
            detail = f"; {evidence.submodule_evidence}" if evidence.submodule_evidence else ""
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_STATIC,
                reason=f"{trace}, but affected submodule {submod_list} is not imported{detail}",
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if not has_coverage:
            if evidence.submodule_imported is None and evidence.submodule_evidence:
                detail = (
                    f"affected submodule {', '.join(component.submodule_paths)} is not "
                    f"imported directly, but {evidence.submodule_evidence}"
                )
            elif evidence.submodule_imported is True and evidence.submodule_evidence:
                detail = f"{evidence.submodule_evidence}, but no coverage data to confirm execution"
            else:
                detail = "but no coverage data to confirm execution"
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"{trace}, {detail}",
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if evidence.coverage_seen is False and evidence.production_observed is not True:
            submod_list = ", ".join(component.submodule_paths)
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_DYNAMIC,
                reason=(f"{trace}; no execution observed in reported statements for {submod_list}"),
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )
        return _inconclusive_coverage(vuln, evidence, import_name, component, dep_of, trace)

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

    if evidence.coverage_seen is False and evidence.production_observed is not True:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_DYNAMIC,
            reason=f"{trace}; no execution observed in the package statements in this coverage report",
            imported_as=import_name,
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )
    return _inconclusive_coverage(vuln, evidence, import_name, component, dep_of, trace)


def _inconclusive_coverage(
    vuln: Vulnerability,
    evidence: Evidence,
    import_name: str,
    component: AffectedComponent,
    dep_of: str | None,
    trace: str,
) -> VerdictResult:
    if evidence.production_observed is True:
        detail = (
            "production traces observed this package; test non-execution cannot establish "
            "its absence, and affected-code execution is unconfirmed"
        )
    else:
        targets = ", ".join(evidence.coverage_unmeasured_targets) or import_name
        detail = (
            f"affected-code measurement for {targets} is {evidence.coverage_scope} "
            "in the coverage report; "
            "include the affected code in coverage source, check omit settings, and collect "
            "fresh coverage; missing measurement cannot establish non-execution"
        )
    return VerdictResult(
        vulnerability=vuln,
        verdict=Verdict.INCONCLUSIVE,
        reason=f"{trace}; {detail}",
        imported_as=import_name,
        dependency_of=dep_of,
        affected_component=component,
        evidence=evidence,
    )


def analyze(
    vulnerabilities: list[Vulnerability],
    repo_path: Path,
    coverage_path: Path | None = None,
    proof_standard: str = "strict",
    scan_capabilities: bool = False,
    trace_exploit_paths: bool = False,
    threat_intel: bool = False,
    otel_traces_path: Path | None = None,
) -> Report:
    # Read installed metadata fresh for each analysis.
    reset_environment_index()
    repo_imports = collect_imports_from_repo(repo_path)
    declared_direct_deps = discover_declared_dependencies(repo_path)
    transitive_deps, dependency_graph_available = resolve_transitive_deps(repo_imports)
    references = scan_repo_references(repo_path)
    optional_dependents = resolve_optional_dependents(repo_imports)
    unresolved_imports = (
        find_unresolved_imports(repo_path, repo_imports) if dependency_graph_available else ()
    )
    analysis_warnings: list[str] = []

    covered_files: dict[str, list[int]] | None = None
    measured_files: dict[str, FileCoverage] | None = None
    coverage_completeness: float | None = None
    if coverage_path:
        coverage_data = load_coverage(coverage_path)
        covered_files = get_covered_files(coverage_data)
        measured_files = get_measured_files(coverage_data)
        coverage_completeness = get_coverage_completeness(coverage_data)

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

    hits_by_target: dict[str, list[ApiUsageHit]] = {}
    if all_api_targets:
        all_hits = find_api_usage(repo_path, all_api_targets)
        for hit in all_hits:
            hits_by_target.setdefault(hit.matched_target, []).append(hit)

    threat_intel_data: dict[str, object] = {}
    if threat_intel:
        try:
            from ca9.threat_intel import fetch_threat_intel_batch

            cve_ids = [v.id for v in vulnerabilities if v.id.startswith("CVE-")]
            threat_intel_data = fetch_threat_intel_batch(cve_ids, project_root=repo_path)
        except Exception as exc:
            analysis_warnings.append(f"threat intelligence enrichment unavailable: {exc}")

    otel_modules: dict[str, int] | None = None
    if otel_traces_path:
        try:
            from ca9.analysis.otel_reader import load_otel_traces

            otel_modules = load_otel_traces(otel_traces_path)
        except Exception as exc:
            analysis_warnings.append(f"production trace ingestion unavailable: {exc}")

    results: list[VerdictResult] = []

    for vuln in vulnerabilities:
        normalized_ecosystem = normalize_ecosystem(vuln.ecosystem)
        if normalized_ecosystem != "pypi":
            rendered_ecosystem = normalized_ecosystem or "unknown"
            results.append(
                VerdictResult(
                    vulnerability=vuln,
                    verdict=Verdict.INCONCLUSIVE,
                    reason=(
                        "ca9 reachability analysis currently supports Python/PyPI packages; "
                        f"{rendered_ecosystem} package reachability was not evaluated"
                    ),
                )
            )
            continue

        import_names = environment_index().resolve(vuln.package_name).names
        import_name = import_names[0]
        component = extract_affected_component(vuln)

        intel = vuln_intel.get(vuln.id)

        vuln_api_hits: list[ApiUsageHit] | None = None
        if intel and intel.api_targets:
            vuln_api_hits = []
            for t in intel.api_targets:
                vuln_api_hits.extend(hits_by_target.get(t.fqname, []))

        ti_data = threat_intel_data.get(vuln.id) if threat_intel_data else None

        prod_observed: bool | None = None
        prod_count = 0
        if otel_modules is not None:
            for mod, count in otel_modules.items():
                if imports_any_module(import_names, {mod}):
                    prod_observed = True
                    prod_count += count
            if prod_observed is None:
                prod_observed = False

        evidence = collect_evidence(
            vuln,
            import_name,
            repo_imports,
            transitive_deps,
            dependency_graph_available,
            declared_direct_deps,
            covered_files,
            component,
            intel=intel,
            api_hits=vuln_api_hits,
            coverage_completeness=coverage_completeness,
            threat_intel_data=ti_data,
            production_observed=prod_observed,
            production_trace_count=prod_count,
            global_warnings=tuple(analysis_warnings),
            measured_files=measured_files,
            references=references,
            optional_dependents=optional_dependents,
            unresolved_imports=unresolved_imports,
        )

        if evidence.dependency_kind == "transitive":
            dep_of = _report_dependency_root(vuln)
            if dep_of is None:
                dep_of = transitive_deps.get(canonicalize_name(vuln.package_name))
        else:
            dep_of = None

        result = derive_verdict(
            vuln,
            evidence,
            import_name,
            component,
            dep_of,
            has_coverage=covered_files is not None,
        )
        result = _apply_proof_standard(result, proof_standard)

        if ti_data is not None:
            result.threat_intel = ti_data

        result.confidence_score = compute_confidence(evidence, result.verdict)
        results.append(result)

    if scan_capabilities:
        warning = _attach_blast_radius(results, repo_path)
        if warning:
            analysis_warnings.append(warning)

    if trace_exploit_paths:
        try:
            from ca9.analysis.exploit_path import build_and_trace

            build_and_trace(repo_path, results)
            for r in results:
                if r.exploit_paths:
                    r.confidence_score = compute_confidence(r.evidence, r.verdict, result=r)
        except Exception as exc:
            warning = f"exploit path tracing unavailable: {exc}"
            analysis_warnings.append(warning)
            print(f"ca9: {warning}", file=sys.stderr)

    if coverage_path:
        coverage_path_str = str(coverage_path)
    else:
        coverage_path_str = None

    return Report(
        results=results,
        repo_path=str(repo_path),
        coverage_path=coverage_path_str,
        proof_standard=proof_standard,
        warnings=analysis_warnings,
    )


def _attach_blast_radius(results: list[VerdictResult], repo_path: Path) -> str | None:
    from ca9.capabilities.models import BlastRadius, CapabilityHit
    from ca9.capabilities.risk import assess_blast_radius_risk
    from ca9.capabilities.scanner import scan_capabilities as _scan_caps

    try:
        cap_hits = _scan_caps(repo_path)
    except Exception as exc:
        warning = f"capability scan unavailable: {exc}"
        print(f"ca9: {warning}", file=sys.stderr)
        return warning
    if not cap_hits:
        return None

    hits_by_file: dict[str, list[CapabilityHit]] = {}
    global_hits: list[CapabilityHit] = []

    for hit in cap_hits:
        if hit.name in ("exec.shell", "db.read", "db.write") or hit.asset_ref.startswith(
            "mcp_server:"
        ):
            global_hits.append(hit)
        if hit.source_file:
            hits_by_file.setdefault(hit.source_file, []).append(hit)

    for result in results:
        if result.verdict != Verdict.REACHABLE:
            continue

        matched: list[CapabilityHit] = list(global_hits)

        for exec_file in result.executed_files:
            normalized = _normalize_path_for_match(exec_file)
            for file_key, file_hits in hits_by_file.items():
                normalized_key = _normalize_path_for_match(file_key)
                if _paths_match(normalized, normalized_key):
                    matched.extend(file_hits)

        seen: set[tuple[str, str]] = set()
        unique: list[CapabilityHit] = []
        for hit in matched:
            key = (hit.name, hit.scope)
            if key not in seen:
                seen.add(key)
                unique.append(hit)

        if unique:
            risk = assess_blast_radius_risk(unique)
            result.blast_radius = BlastRadius(
                capabilities=tuple(sorted({h.name for h in unique})),
                details=tuple(unique),
                risk_level=risk.level,
                risk_reasons=tuple(risk.reasons),
            )
    return None


def _normalize_path_for_match(path: str) -> str:
    path = path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    return path


def _paths_match(exec_path: str, cap_path: str) -> bool:
    if exec_path == cap_path:
        return True

    if len(exec_path) > len(cap_path):
        longer, shorter = exec_path, cap_path
    else:
        longer, shorter = cap_path, exec_path

    if longer.endswith(shorter):
        pos = len(longer) - len(shorter)
        if pos == 0 or longer[pos - 1] == "/":
            return True

    return False
