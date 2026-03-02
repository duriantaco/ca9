# Changelog

All notable changes to ca9 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
