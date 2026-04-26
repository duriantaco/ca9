# ca9.scanner

OSV.dev integration for scanning declared repository dependencies or installed packages.

## `scan_repository()`

```python
def scan_repository(
    repo_path: Path,
    offline: bool = False,
    refresh_cache: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> tuple[list[Vulnerability], ScanInventory]
```

Resolves dependency inventory for a repository, queries OSV.dev for known vulnerabilities, and returns both the vulnerabilities and inventory metadata.

The inventory resolver prefers declared repository dependencies. If no resolvable dependency inventory is found, it falls back to installed packages in the current Python environment.

Supported inventory sources include `requirements*.txt`, nested `-r` requirement files, constraints used to pin declared requirements, `pyproject.toml` dependencies and optional dependencies, Poetry metadata, `uv.lock`, `poetry.lock`, `Pipfile`, and `Pipfile.lock`.

## `scan_installed()`

```python
def scan_installed() -> list[Vulnerability]
```

Scans all installed packages for known vulnerabilities via OSV.dev.

Combines `get_installed_packages()` and `query_osv_batch()` into a single call.

**Returns:** List of `Vulnerability` objects found.

---

## `get_installed_packages()`

```python
def get_installed_packages() -> list[tuple[str, str]]
```

Returns a list of `(name, version)` tuples for all packages installed in the current Python environment. Uses `importlib.metadata`.

---

## `query_osv_batch()`

```python
def query_osv_batch(
    packages: list[tuple[str, str]],
    offline: bool = False,
    refresh_cache: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> list[Vulnerability]
```

Queries the [OSV.dev batch API](https://osv.dev/docs/) for vulnerabilities affecting the given packages.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `packages` | `list[tuple[str, str]]` | List of `(name, version)` tuples |
| `offline` | `bool` | Use cached OSV details only |
| `refresh_cache` | `bool` | Clear cached OSV details before querying |
| `max_workers` | `int` | Concurrent OSV detail fetches |

**Returns:** List of `Vulnerability` objects with full details (severity, version ranges, references).

**Behavior:**

1. Sends a batch query to `https://api.osv.dev/v1/querybatch`
2. For each result, fetches full vulnerability details from `https://api.osv.dev/v1/vulns/{id}`
3. Extracts severity (supports GHSA severity, CVSS v3.x scoring)
4. Parses affected version ranges (ECOSYSTEM type only)
5. Collects reference URLs

---

## Helper functions

### `resolve_scan_inventory(repo_path) -> ScanInventory`

Returns package inventory and warning metadata for the target repository.

### `_extract_severity(osv_vuln) -> str`

Extracts severity from OSV vulnerability data. Priority:

1. `database_specific.github_reviewed_at` → uses `database_specific.severity`
2. CVSS v3.x vector in `severity` array → computes score
3. Falls back to `"unknown"`

### `_compute_cvss3_base_score(vector) -> float | None`

Computes a CVSS v3.x base score from a vector string per the CVSS specification.

### `_cvss_to_level(score) -> str`

Maps a numeric CVSS score to a severity level:

| Score | Level |
|---|---|
| 9.0 – 10.0 | `critical` |
| 7.0 – 8.9 | `high` |
| 4.0 – 6.9 | `medium` |
| 0.1 – 3.9 | `low` |
