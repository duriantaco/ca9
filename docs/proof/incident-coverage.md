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

| Incident | Current status | Inventory | Malware advisory | Workflow | Source |
|---|---:|---:|---:|---:|---|
| Mistral PyPI `mistralai==2.4.6` import-time dropper | partial | pass | gap | not applicable | [Mistral advisory](https://docs.mistral.ai/resources/security-advisories), [GHSA-wx9m-wx4f-4cmg](https://github.com/advisories/GHSA-wx9m-wx4f-4cmg) |
| Mistral npm SDK package compromise | gap | gap | gap | not applicable | [Mistral advisory](https://docs.mistral.ai/resources/security-advisories) |
| TanStack npm supply-chain compromise | gap | gap | gap | gap | [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem), [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx) |
| Grafana GitHub token/codebase exfiltration | gap | not applicable | not applicable | gap | [The Hacker News](https://thehackernews.com/2026/05/grafana-github-token-breach-led-to.html), [BleepingComputer](https://www.bleepingcomputer.com/news/security/grafana-says-stolen-github-token-let-hackers-steal-codebase/amp/) |

Summary for this commit: `0 covered`, `1 partial`, `3 gap`.

## What The Results Mean

- `pass`: current ca9 code detects the fixture evidence through an implemented path.
- `partial`: ca9 detects at least one relevant signal, but misses another signal required
  to make a reliable security decision.
- `gap`: ca9 does not currently cover that attack surface.
- `not applicable`: the incident does not exercise that check.

## Known Gaps

Mistral PyPI is partial because ca9 can inventory the pinned PyPI package from `fyn.lock`,
but a GHSA malicious-package advisory is not currently classified as blocking malware
unless it also uses a `MAL-*` or `PYSEC-MAL-*` identifier. ca9 also needs import-time
Python malware analysis to prove whether `import mistralai` could execute the dropper.

Mistral npm and TanStack npm are gaps because ca9 does not yet parse `package-lock.json`,
`pnpm-lock.yaml`, or `yarn.lock`; does not query OSV/GHSA dynamically by npm ecosystem in
the `vet --malware-query` path; and does not inspect npm lifecycle/install-time malware.

TanStack also needs GitHub Actions analysis for `pull_request_target`, cache trust
boundaries, OIDC token scope, mutable action refs, and publish provenance. Package
provenance alone would not have been enough because the malicious packages carried trusted
publisher provenance.

Grafana is a gap because the reported incident was a stolen GitHub token and codebase
exfiltration event, not a dependency CVE or package reachability case. A future workflow
scanner can catch risky permissions and token exposure patterns, but full prevention also
requires identity, access, audit-log, and incident-response controls outside ca9.

## Promotion Rule

When ca9 gains a new detector, update the relevant fixture expectation only after the
fixture proves the detector handles the incident evidence. Every public claim should map
to at least one replay fixture or real-repo validation entry.
