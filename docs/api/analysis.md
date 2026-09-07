# ca9.analysis

The analysis subpackage contains three modules for static analysis, dynamic analysis, and affected component extraction.

---

## ca9.analysis.ast_scanner

Static import analysis using Python's AST module.

### `pypi_to_import_name(package_name) -> str`

Converts a PyPI package name to its Python import name.

```python
pypi_to_import_name("beautifulsoup4")  # "bs4"
pypi_to_import_name("pyyaml")          # "yaml"
pypi_to_import_name("my-package")      # "my_package"
```

Uses a built-in mapping of ~30 common mismatches. Falls back to replacing hyphens with underscores.

### `collect_imports_from_source(source) -> set[str]`

Parses a Python source string and returns all imported module names.

```python
collect_imports_from_source("import os\nfrom pathlib import Path")
# {'os', 'pathlib'}
```

### `collect_imports_from_repo(repo_path) -> set[str]`

Scans all `.py` files in a repository and returns all imported module names. Skips virtual environments, caches, and other non-project directories.

### `is_package_imported(package_name, repo_imports) -> bool`

Checks if a PyPI package is imported anywhere in the repository.

### `is_submodule_imported(submodule_paths, repo_imports) -> tuple[bool, str | None]`

Checks if any of the given submodule paths are imported. Returns `(is_imported, matched_import)`.

### `resolve_transitive_deps(repo_imports) -> dict[str, str]`

Maps transitive dependency package names to the root packages that bring them in.

```python
resolve_transitive_deps({"flask", "jinja2"})
# {'markupsafe': 'jinja2', 'werkzeug': 'flask', 'itsdangerous': 'flask'}
```

---

## ca9.analysis.coverage_reader

Dynamic analysis using coverage.py JSON data.

### `load_coverage(coverage_path) -> dict`

Loads and returns the raw coverage JSON data.

### `get_covered_files(coverage_data) -> dict[str, list[int]]`

Extracts a mapping of `{filename: [executed_line_numbers]}` from coverage data.
Zero-hit files are excluded from this execution-only view. An absent file is not
evidence that it was measured or could not execute.

### `get_measured_files(coverage_data) -> dict[str, FileCoverage]`

Preserves reported executed and missing statements, including explicit zero-hit
files. Excluded lines do not count as missing statements. Empty or malformed
records cannot establish non-execution.

### `observe_coverage(package_name, measured_files, submodule_paths=(), file_hints=()) -> CoverageObservation`

Returns affected-target scope, observed execution, matching statement files, and
targets without usable statement evidence. `seen` is `True` for observed execution,
`False` for scoped non-execution, and `None` for insufficient measurement. A
`reported` scope does not attest to complete instrumentation or source identity.
See [measurement evidence](../guide/coverage.md#measurement-evidence).

### `are_call_sites_covered(call_sites, covered_files, *, missing_files=None) -> tuple[bool | None, int, int]`

Returns `(observed_execution, executed_count, measured_count)`. A positive result
requires at least one unambiguously matched executed call-site line. A negative
result requires explicit missing-line evidence for every requested call site.
Partial, excluded, or ambiguous measurement otherwise returns `None`. Supplying
execution-only data without `missing_files` cannot establish a negative result.

### `is_package_executed(package_name, covered_files) -> tuple[bool, list[str]]`

Checks if any file from the given package was executed. Returns `(was_executed, matching_files)`.

### `is_submodule_executed(submodule_paths, file_hints, covered_files) -> tuple[bool, list[str]]`

Checks if files matching the given submodule paths or file hints were executed. Returns `(was_executed, matching_files)`.

---

## ca9.analysis.vuln_matcher

Extracts affected components from CVE metadata.

### `extract_affected_component(vuln) -> AffectedComponent`

Main entry point. Tries four strategies in order and returns the first match:

| Priority | Strategy | Confidence | Method |
|---|---|---|---|
| 0 | Commit analysis | high | Fetches changed files from GitHub commits |
| 1 | Curated mappings | high | Regex patterns for known packages |
| 2 | Regex extraction | medium | Backtick-quoted dotted paths in descriptions |
| 2.5 | Class name resolution | medium | Resolves CamelCase names via AST |
| — | Fallback | low | Empty submodule paths |

Always returns an `AffectedComponent` — never `None`.
