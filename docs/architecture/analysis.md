# Analysis Pipeline

ca9 uses several analysis modules that feed into the verdict engine. Static imports, dependency relationships, coverage data, affected component extraction, API usage rules, OpenTelemetry traces, and exploit path tracing are all normalized into structured evidence.

## Static Analysis — AST Scanner

**Module:** `ca9.analysis.ast_scanner`

The AST scanner performs static import tracing using Python's `ast` module.

### Import collection

```python
from ca9.analysis.ast_scanner import collect_imports_from_repo

imports: set[str] = collect_imports_from_repo(Path("."))
# {'flask', 'requests', 'jinja2', 'jinja2.sandbox', 'os', 'sys', ...}
```

Scans all `.py` files recursively, skipping common non-project directories (venvs, `__pycache__`, `site-packages`, etc.).

ca9 also records statically recoverable dynamic imports:

```python
import importlib
from importlib import import_module

importlib.import_module("requests.sessions")
import_module("django.contrib.admin")
__import__("yaml")
```

Dynamic import expressions that depend on runtime variables are not treated as proof.

### Package import checking

```python
from ca9.analysis.ast_scanner import is_package_imported

is_package_imported("jinja2", imports)  # True
is_package_imported("django", imports)  # False
```

Handles PyPI-to-import name mismatches (e.g., `beautifulsoup4` → `bs4`, `pyyaml` → `yaml`) via a built-in mapping of ~30 common packages.

### Submodule import checking

```python
from ca9.analysis.ast_scanner import is_submodule_imported

found, match = is_submodule_imported(["jinja2.sandbox"], imports)
# (True, "jinja2.sandbox")
```

Three matching rules:

1. **Exact match** — `jinja2.sandbox` matches `jinja2.sandbox`
2. **Narrower** — `jinja2.sandbox.SandboxedEnvironment` matches `jinja2.sandbox`
3. **Broader** — `jinja2` matches `jinja2.sandbox` (conservative; the parent module is imported)

### Transitive dependency resolution

```python
from ca9.analysis.ast_scanner import resolve_transitive_deps

transitive: dict[str, str] = resolve_transitive_deps(imports)
# {'markupsafe': 'jinja2', 'werkzeug': 'flask', ...}
```

Maps transitive dependencies back to the root package that brings them in. Uses `importlib.metadata` to walk the dependency tree.

---

## Dynamic Analysis — Coverage Reader

**Module:** `ca9.analysis.coverage_reader`

Reads `coverage.json` (from `coverage json`) and checks whether package code was executed.

### Loading coverage

```python
from ca9.analysis.coverage_reader import load_coverage, get_covered_files

data = load_coverage(Path("coverage.json"))
covered: dict[str, list[int]] = get_covered_files(data)
# {'/path/to/site-packages/flask/app.py': [1, 2, 5, 10, ...], ...}
```

### Package execution check

```python
from ca9.analysis.coverage_reader import is_package_executed

executed, files = is_package_executed("flask", covered)
# (True, ['/path/to/site-packages/flask/app.py', ...])
```

### Submodule execution check

```python
from ca9.analysis.coverage_reader import is_submodule_executed

executed, files = is_submodule_executed(
    ["jinja2.sandbox"],
    ["jinja2/sandbox.py"],
    covered,
)
```

Maps dotted module paths to filesystem patterns (e.g., `jinja2.sandbox` → `site-packages/jinja2/sandbox/`).

---

## Affected Component Extraction — Vuln Matcher

**Module:** `ca9.analysis.vuln_matcher`

Extracts the specific submodule affected by a CVE from its metadata. Uses four strategies in priority order:

### Strategy 0: Commit analysis (high confidence)

Fetches changed files from GitHub commit URLs found in CVE references. Maps file paths back to Python module paths.

```
Reference: https://github.com/pallets/jinja2/commit/abc123
→ Changed files: jinja2/sandbox.py
→ Affected component: jinja2.sandbox
```

### Strategy 1: Curated mappings (high confidence)

Regex patterns for well-known packages (Django, Werkzeug, Jinja2, PyYAML, urllib3). Maps CVE description keywords to specific submodules.

```
Package: django, description contains "admin"
→ Affected component: django.contrib.admin
```

### Strategy 2: Regex extraction (medium confidence)

Extracts backtick-quoted dotted paths from CVE descriptions.

```
Description: "A vulnerability in `jinja2.sandbox.SandboxedEnvironment`..."
→ Affected component: jinja2.sandbox
```

### Strategy 2.5: Class name resolution (medium confidence)

Finds CamelCase class names in descriptions and resolves them to modules by scanning the package source with AST.

```
Description: "Flaw in SandboxedEnvironment allows..."
→ AST scan finds class SandboxedEnvironment in jinja2/sandbox.py
→ Affected component: jinja2.sandbox
```

### Fallback (low confidence)

If no strategy produces a match, returns an empty component with `confidence="low"`. The verdict engine falls back to package-level analysis.

---

## Vulnerable API Usage

**Module:** `ca9.analysis.api_usage`

Curated intelligence rules can identify vulnerable functions, classes, methods, or modules for specific CVEs. ca9 scans first-party code for those targets and records call-site evidence.

When coverage data is available, ca9 also checks whether the vulnerable API call sites executed during tests.

---

## Runtime And Path Evidence

Additional optional analyzers can enrich verdicts:

- `ca9.analysis.otel_reader` reads OTLP JSON exports to identify package modules observed in production traces.
- `ca9.analysis.entry_points`, `call_graph`, and `exploit_path` support path tracing from application entry points to vulnerable API call sites.
- Entry point detection supports Flask routes, FastAPI routes and routers, Django URL views, Click commands, Typer commands, Celery tasks, and `if __name__ == "__main__"` blocks.
