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
- Coverage exists, but total coverage is below the strict threshold.
- Coverage data does not include completeness totals.

## Balanced

```bash
ca9 check snyk-report.json --repo . --proof-standard balanced
```

`balanced` keeps more `UNREACHABLE` verdicts when the evidence points that way. It is useful for triage, demos, and finding where better coverage or dependency manifests would improve confidence.

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
Policy overlays are applied before output, so ignored accepted risks and baseline findings are removed from the generated report and summarized as warnings.

```bash
ca9 check report.json --repo . \
  --proof-standard strict \
  --accepted-risks accepted-risks.toml \
  --baseline ca9-baseline.json \
  --new-only
```

Accepted risks require an active `expires` date when provided. Expired or invalid exceptions are ignored and reported as warnings.
