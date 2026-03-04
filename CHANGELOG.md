# Changelog

All notable changes to ca9 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-03-04

### Added

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
