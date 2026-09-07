---
title: Proof Standards
description: How ca9 strict and balanced proof standards affect Python CVE reachability verdicts and CI suppression safety.
---

# Proof Standards

ca9 can run with two proof standards: `strict` and `balanced`.

Use `strict` when ca9 output will suppress alerts, block releases, or feed a security review. Use `balanced` when you are exploring reachability locally and want fewer inconclusive results.

## Strict

```bash
ca9 check snyk-report.json --repo . --proof-standard strict
```

`strict` is the default. It downgrades weak suppressions to `INCONCLUSIVE` when ca9 cannot prove the dependency graph or dynamic evidence strongly enough.

Examples:

- A transitive dependency relationship comes only from the ambient Python environment.
- Test coverage records no execution of affected code, even when statements are explicitly reported and the overall percentage is 100%.

Test non-execution remains `INCONCLUSIVE`: exercising one set of tests cannot establish unreachability across other inputs or environments. Overall coverage percentages do not change this decision.

## Balanced

```bash
ca9 check snyk-report.json --repo . --proof-standard balanced
```

`balanced` can retain `UNREACHABLE (dynamic)` as a scoped heuristic when the relevant affected scope has explicit statement evidence and no execution was observed. That verdict describes the supplied report and tests; it does not establish that the code cannot execute. It is useful for local triage and identifying where additional tests would help.

Missing, partial, empty, or excluded-only affected scope cannot justify a dynamic suppression under either standard. Positive execution evidence remains relevant even when other targets are missing. The [coverage guide](coverage.md) explains the `coverage_scope`, `coverage_measured_files`, and `coverage_unmeasured_targets` evidence fields.

The `reported` scope means each selected affected target has statement evidence. It does not assert complete instrumentation or matching source/build identity. Source revision and build attestation checks are not implemented.

OpenVEX exports all dynamic verdicts as `under_investigation`, including balanced results. Changing proof standards cannot turn test non-execution into a `not_affected` statement.

## Recommendation

For CI gates, start with:

```bash
ca9 check report.json --repo . --coverage coverage.json --proof-standard strict -f sarif -o ca9.sarif
```

For local investigation, use:

```bash
ca9 check report.json --repo . --coverage coverage.json --proof-standard balanced --show-confidence -v
```

## Policy overlays

Proof standards decide how ca9 classifies evidence. Accepted-risk and baseline options decide which findings affect a gate.
Policy overlays are applied before output. Ignored accepted risks and baseline findings do not affect exit codes, but they remain visible in `ignored_results`, Markdown/HTML ignored-finding sections, and SARIF suppressed results.

```bash
ca9 check report.json --repo . \
  --proof-standard strict \
  --accepted-risks accepted-risks.toml \
  --baseline ca9-baseline.json \
  --new-only
```

Accepted risks require an active `expires` date when provided. Expired or invalid exceptions are ignored and reported as warnings.
