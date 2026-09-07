# Dynamic Analysis with Coverage

Dynamic analysis uses [coverage.py](https://coverage.readthedocs.io/) data to identify execution observed during your tests. ca9 distinguishes code with reported statements from code absent from the report. Non-execution during those tests does not prove unreachability across other inputs or environments.

## Why it matters

Static analysis tells you *if* a package is imported. Dynamic analysis tells you *if that code actually ran*. This distinction matters:

- A package might be imported but only used in a code path your tests don't exercise
- A vulnerable submodule might exist in an imported package but never be called
- Transitive dependencies might be installed but never loaded at runtime

## Generating coverage data

### Step 1: Run tests with coverage

```bash
pip install coverage
coverage run -m pytest
```

### Step 2: Export as JSON

```bash
coverage json
```

This creates `coverage.json` in the current directory.

!!! important
    ca9 reads the **JSON** format from coverage.py, not the XML or HTML formats. Make sure to use `coverage json`.

Check that the report includes the affected dependency. A report limited to application code cannot establish whether dependency code was exercised. Configure coverage.py's `source` to include the relevant packages or directories, and check measurement and reporting `omit` settings. Specifying `source` also lets coverage.py report eligible files that were never executed. See [coverage.py's source configuration](https://coverage.readthedocs.io/en/latest/source.html).

### Step 3: Pass to ca9

```bash
ca9 check snyk-report.json --coverage coverage.json
# or
ca9 scan --coverage coverage.json
```

## How ca9 uses coverage data

The coverage JSON contains executed, missing, and excluded line numbers for each reported file. ca9 retains explicit zero-hit files with missing statements and uses the report for:

1. **Package-level check** — Did *any* file from the package execute?
    - Matches installed package paths such as `site-packages/package_name/` or `site-packages/package_name.py`
2. **Submodule-level check** — Did the *specific vulnerable submodule* execute?
    - Maps dotted paths to module files or package directories (e.g., `jinja2.sandbox` → `site-packages/jinja2/sandbox.py`)
    - File hints can contribute execution evidence within the affected package
3. **API call-site check** — When API usage is known, does the report explicitly mark a matched call-site line as executed or missing?

Valid execution hits remain usable even when another field in the same record is
malformed. Malformed records leave negative measurement scope incomplete; they
cannot turn observed execution into non-execution. Positive affected-code
execution also takes precedence over static import absence. Package-only
production observations prevent absence-based suppression without proving that a
specific affected API executed.

An empty entry, an excluded-only entry, or a missing target cannot establish non-execution. Coverage of a neighboring module cannot fill that gap. An overall percentage describes the supplied report; even 100% does not establish that affected code was included.

## Measurement evidence

JSON reports include these fields in each finding's `evidence`:

| Field | Meaning |
|---|---|
| `coverage_scope` | How the affected targets are represented in the report; see below |
| `coverage_measured_files` | Matching files with usable executed or missing statements |
| `coverage_unmeasured_targets` | Affected targets lacking usable statement evidence |
| `coverage_seen` | `true` when execution was observed; `false` when every selected target has statement evidence but no execution was observed; `null` when measurement is insufficient and no execution was observed |

| `coverage_scope` | Meaning |
|---|---|
| `unavailable` | No coverage report was supplied, or runtime evidence was not evaluated for this finding |
| `not_reported` | No usable file records match the affected targets |
| `no_statements` | Matching records contain no usable executed or missing statements |
| `partial` | Some affected targets lack statement evidence |
| `reported` | Each selected affected target has matching statement evidence |

`reported` does **not** attest to complete instrumentation, every file within a package, or matching source/build identity. ca9 does not currently verify source revision or build attestations for coverage reports. Positive execution evidence can coexist with `partial` scope; missing evidence cannot cancel an observed execution.

## Verdicts with and without coverage

For an imported package with no independent static resolution:

| Runtime evidence | `strict` (default) | `balanced` |
|---|---|---|
| No coverage report | `INCONCLUSIVE` | `INCONCLUSIVE` |
| Affected scope missing, partial, empty, or excluded-only; no execution observed | `INCONCLUSIVE` | `INCONCLUSIVE` |
| Affected statements explicitly reported, no execution observed | `INCONCLUSIVE` | `UNREACHABLE (dynamic)` may be retained as a scoped heuristic |
| Affected code observed executing | `REACHABLE` | `REACHABLE` |

`strict` keeps test non-execution inconclusive regardless of the overall coverage percentage. `balanced` can retain a dynamic verdict for local triage when the relevant statement evidence is present. Its meaning is limited to non-execution observed in the supplied report and tests. It is not proof that the vulnerability cannot be reached. See [proof standards](proof-standards.md).

OpenVEX exports dynamic verdicts as `under_investigation` under both standards; test non-execution never becomes `not_affected`.

## Tips for better results

- **Include the affected code** — check `coverage_scope` and resolve unmeasured targets before interpreting non-execution
- **Include integration tests** — unit tests with heavy mocking may not trigger real dependency code
- **Collect fresh reports** — generate coverage for the source and dependency versions being reviewed; ca9 does not attest that identity
- **Preserve CI artifacts** — retain the coverage report and test configuration so observations remain reviewable
