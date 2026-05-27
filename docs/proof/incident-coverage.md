---
title: Incident Replay Coverage
description: Current ca9 coverage against recent real supply-chain and GitHub token compromise incidents.
---

# Incident Replay Coverage

ca9 now has a neutral replay harness for recent real incidents:

```bash
python scripts/incident_replay.py --strict --format table
```

The harness uses local fixtures under `tests/fixtures/incidents/`. It does not call live
advisory APIs, install packages, import package code, or execute workflow snippets. A
`gap` result is intentional evidence of an unsupported attack surface, not a detection
claim.

## Current Matrix

| Incident class | Current status | Inventory | Malware advisory | Workflow | Source handling |
|---|---:|---:|---:|---:|---|
| PyPI import-time dropper | partial | pass | pass | not applicable | fixture metadata |
| npm SDK package compromise | partial | pass | pass | not applicable | fixture metadata |
| npm package compromise through Actions/OIDC | partial | pass | pass | pass | fixture metadata |
| GitHub token/codebase exfiltration | partial | not applicable | not applicable | pass | fixture metadata |

Summary for this commit: `0 covered`, `4 partial`, `0 gap`.

## What The Results Mean

- `pass`: current ca9 code detects the fixture evidence through an implemented path.
- `partial`: ca9 detects at least one relevant signal, but misses another signal required
  to make a reliable security decision.
- `gap`: ca9 does not currently cover that attack surface.
- `not applicable`: the incident does not exercise that check.

## Known Gaps

The PyPI import-time dropper case is partial because ca9 can inventory the pinned PyPI
package from `fyn.lock` and classify the GHSA malicious-package advisory as blocking
malware. ca9 still needs import-time Python malware analysis to prove whether importing
the package could execute the dropper.

The npm package compromise cases are partial because ca9 now parses `package-lock.json`
inventory and can classify malicious npm advisories, but it does not yet parse
`pnpm-lock.yaml` or `yarn.lock` and does not inspect npm lifecycle/install-time malware.

The Actions/OIDC compromise case now exercises the GitHub Actions workflow scanner for
`pull_request_target`, OIDC token scope, broad write permissions, mutable action refs,
cache trust boundaries, and source-clone commands. It remains partial because package
provenance and npm tarball/lifecycle analysis are separate surfaces.

The GitHub token/codebase exfiltration case is partial because ca9 can now flag risky
workflow permissions and source-clone commands, but the reported incident was a stolen
GitHub token and codebase exfiltration event, not a dependency CVE or package reachability
case. Full prevention still requires identity, access, audit-log, and incident-response
controls outside ca9.

## Promotion Rule

When ca9 gains a new detector, update the relevant fixture expectation only after the
fixture proves the detector handles the incident evidence. Every public claim should map
to at least one replay fixture or real-repo validation entry.
