# Changelog

All notable changes to ca9 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-26

### Added

- **GitHub Action** - reusable `duriantaco/ca9` composite action for `scan` and `check` workflows, SARIF upload, OpenVEX/action-plan artifacts, accepted risks, baselines, and optional fail-on-findings enforcement.
- **Accepted-risk policy files** - TOML/JSON exceptions with optional version, owner, reason, and expiry fields.
- **Baseline and new-only gating** - `--baseline` and `--new-only` options for gating only newly reachable or inconclusive findings.
- **Markdown and HTML reports** - `--format markdown` and `--format html` for PR comments, build artifacts, and human review.
- **Dependency inventory improvements** - Pipfile/Pipfile.lock support, requirements constraint pinning, and `pyproject.toml` optional dependency parsing.
- **Reachability hints** - statically recoverable dynamic import detection plus Typer command and Celery task entry point detection.
- **Release automation** - manual GitHub release workflow with SemVer validation, version bumping, changelog guard, package build, GitHub release creation, and PyPI trusted publishing.
- **SEO and integration docs** - dedicated pages for OSV, Snyk, Dependabot, Trivy, pip-audit, SARIF, OpenVEX, SBOM, MCP, CI/CD, proof standards, and positioning.
- **Structured docs metadata** - SoftwareApplication and SoftwareSourceCode JSON-LD for the documentation site.
- **Benchmarks and release checklist scaffolding** - reproducible benchmark methodology and release/growth checklist pages.

### Changed

- Expanded PyPI metadata with project URLs and security/search keywords.
- Updated public docs and README to reflect current parser support, CLI options, output formats, exit codes, and optional integrations.
- Wired CLI, SARIF, OpenVEX, and docs structured data to the package version.
- Documented that policy overlays produce filtered reports and summarize ignored findings in warnings.

### Fixed

- Corrected repository and documentation URLs to `duriantaco/ca9`.
- Added warnings for `--new-only` without a usable baseline and for empty accepted-risk files.
- Removed stale documentation claims about supported formats and dependency footprint.

## [0.1.4] - 2026-03-08

### Added

- **MCP server** — `ca9-mcp` exposes ca9 as an MCP tool server with `check_reachability`, `scan_dependencies`, `check_coverage_quality`, and `explain_verdict` tools. Install with `pip install ca9[mcp]`.
- **API call site coverage** — when coverage data is available, ca9 now checks whether specific vulnerable API call sites were executed in tests, not just whether the package was executed.
- **Coverage completeness weighting** — confidence scoring now factors in overall test coverage percentage. High coverage (80%+) makes dynamic absence signals more trustworthy; low coverage reduces their weight.
- **Coverage completeness in evidence** — `coverage_completeness_pct` field added to the Evidence model, surfaced in JSON/SARIF output.
- 34 new tests (349 total).

### Changed

- **Verdict precision for API calls** — when vulnerable API calls are found but call sites are not executed in tests, verdict is now INCONCLUSIVE instead of REACHABLE.
- **Code cleanup** — removed inline ternary expressions across parsers, scanner, CLI, and report modules for readability.
- **Removed AI-generated comments** — stripped redundant phase comments and docstrings from engine.

### Fixed

- **Dead code in `_api_usage_boost`** — ternary assignment was immediately overwritten by an identical if/else block.
- **Report column width** — deduplicated repeated if/else blocks for table column width calculation.

## [0.1.3] - 2026-03-04

### Added

- **Vulnerability intelligence layer** — 21 curated rules across 6 packages (Django, Jinja2, PyYAML, requests, urllib3, Werkzeug) mapping advisories to 46 vulnerable API targets.
- **API-level reachability** — AST-based scanner detects actual calls to vulnerable functions/classes/methods, not just package imports. Resolves aliased imports, attribute chains, and `from X import Y` patterns.
- **API evidence in verdicts** — JSON/SARIF output now includes `api_targets`, `api_usage_seen`, `api_usage_hits` (with file, line, snippet), and `intel_rule_ids`.
- **API-driven verdict upgrades** — finding vulnerable API calls can upgrade a verdict to REACHABLE even without coverage data.
- **API-aware confidence scoring** — API usage boosts reachable confidence (+10–15), strengthens unreachable when no usage found (+8), penalizes contradictions.
- 46 new tests (315 total).
- **Evidence model** — every verdict now carries structured evidence (version range, import status, dependency kind, coverage, affected component source/confidence).
- **Confidence scoring** — verdict-aware 0-100 confidence score. Signals boost or penalize depending on whether they support the verdict direction.
- **Affected component inference** — commit analysis, curated mappings, regex extraction, and class name resolution each produce confidence-scored component matches.
- **OSV caching** — vulnerability details cached to `~/.cache/ca9/osv/` with 24h TTL. Commit file lists cached to `~/.cache/ca9/commits/` with 7-day TTL.
- **Concurrent OSV fetches** — `ThreadPoolExecutor` for parallel vulnerability detail lookups (`--max-osv-workers`, default 8).
- **Offline mode** — `--offline` flag returns results from cache only, no network requests.
- **`--refresh-cache`** — clears OSV cache before fetching.
- **`--show-confidence`** — display confidence score in table output.
- **`--show-evidence-source`** — display evidence extraction source in table output.
- **SARIF fingerprints** — stable `ca9/v1` fingerprints based on `(vuln_id, package, version, verdict)`.
- **SARIF/JSON evidence** — confidence score and full evidence object included in SARIF properties and JSON output.
- **GitHub token support** — `GITHUB_TOKEN` env var for commit fetch rate limit mitigation.
- 55 new tests (260 total).

### Changed

- **PEP 440 version parsing** — replaced naive tuple-based comparison with `packaging.version.Version`. Handles pre-releases, post-releases, dev releases, epochs, and local versions correctly.
- **Parser deduplication** — widened dedupe key from `vuln_id` to `(vuln_id, package_name, package_version)`. Same CVE across different packages is now preserved.
- **Engine refactored to evidence-first** — `collect_evidence()` gathers all signals into an Evidence object, `derive_verdict()` applies deterministic policy on evidence.
- **Bare import no longer over-claims submodule reachability** — `import requests` sets `submodule_imported=None` (unknown) instead of `True`.
- **Commit fetch warnings propagated** — GitHub fetch failures now flow into `Evidence.external_fetch_warnings` and degrade confidence scores.
- **Confidence scoring is verdict-directional** — `package_imported=True` boosts REACHABLE confidence but penalizes UNREACHABLE, and vice versa. Same for `version_in_range`, `coverage_seen`, `submodule_imported`.

### Fixed

- **Python 3.11 f-string syntax error** — ditto marks in table grouping used backslashes inside f-strings, which is only valid in 3.12+.
- **Linting errors** — unused imports, Yoda conditions, non-idiomatic conditionals.
- **Duplicate `extract_affected_component()` call** — was computed twice per vulnerability (once in `collect_evidence`, once in `analyze`). Now computed once and passed through.
- **`--offline` was a no-op** — `_query_from_cache_only()` was a stub. Now scans cache directory and matches cached vulns to requested packages.
- **Version ranges without `introduced` skipped silently** — ranges missing the introduced field were dropped entirely.

## [0.1.1] - 2026-03-02

### Added

- **CI/CD exit codes** — `0` clean, `1` reachable CVEs found, `2` inconclusive only.
- **SARIF 2.1.0 output** — `--format sarif` for GitHub Security tab integration.
- **`.ca9.toml` config file** — auto-discovered from CWD upward, sets default CLI options.
- **Trivy parser** — `ca9 check trivy.json` now works out of the box.
- **pip-audit parser** — `ca9 check pip-audit.json` now works out of the box.
- 42 new tests (205 total).

## [0.1.0] - 2026-02-26

### Added

- **Core verdict engine** with four-state decision tree: `REACHABLE`, `UNREACHABLE_STATIC`, `UNREACHABLE_DYNAMIC`, `INCONCLUSIVE`.
- **Static analysis** via AST import tracing — scans all `.py` files in a repo and checks whether vulnerable packages are imported.
- **Dynamic analysis** via coverage.py JSON data — checks whether vulnerable package code was actually executed during tests.
- **Snyk parser** — parses `snyk test --json` output (single-project and multi-project formats).
- **Dependabot parser** — parses GitHub Dependabot alerts JSON (API export format).
- **Auto-detection** of SCA report format — no need to specify which tool generated the report.
- **PyPI-to-import name mapping** for ~30 common packages with mismatched names (Pillow/PIL, PyYAML/yaml, scikit-learn/sklearn, etc.).
- **CLI** (`ca9` command) with table and JSON output formats, file output, and coverage data support.
- **Protocol-based parser architecture** — new SCA formats can be added without modifying existing code.
- **Zero runtime dependencies** for library core (stdlib only). CLI requires `click`.
- **59 tests** covering parsers, AST scanner, coverage reader, engine verdicts, CLI, and edge cases.
