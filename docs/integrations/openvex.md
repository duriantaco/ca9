---
title: OpenVEX Output For Python CVE Reachability
description: Generate and diff OpenVEX exploitability statements from ca9 Python CVE reachability analysis.
---

# OpenVEX

ca9 can generate OpenVEX statements from reachability verdicts.

```bash
ca9 check snyk-report.json --repo . -f vex -o openvex.json
```

Verdict mapping:

| ca9 verdict | OpenVEX status |
|---|---|
| `REACHABLE` | `affected` |
| `UNREACHABLE (static)` | `not_affected` |
| `UNREACHABLE (dynamic)` | `under_investigation` |
| `INCONCLUSIVE` | `under_investigation` |

Test non-execution is limited to the supplied report and test inputs. It cannot justify a `not_affected` statement. Strict mode therefore keeps such results inconclusive; balanced mode can retain a scoped dynamic heuristic, but OpenVEX still emits `under_investigation` with no `justification`. The original ca9 verdict and explanation remain in the statement's `ca9` metadata.

Coverage evidence is preserved in `ca9.evidence_summary`, including `coverage_scope`, `coverage_measured_files`, and `coverage_unmeasured_targets`. A `reported` scope records the presence of statement evidence for each selected affected target; it does not attest to complete instrumentation or matching source/build identity. See [coverage analysis](../guide/coverage.md) and [proof standards](../guide/proof-standards.md).

Accepted-risk and baseline findings are still emitted as OpenVEX statements with `ca9.policy_ignored` metadata, so downstream review can see the finding even though it did not affect ca9's exit code.

## Continuous VEX

Compare previous and current OpenVEX output:

```bash
ca9 vex-diff --base previous.openvex.json --head current.openvex.json
```

`vex-diff` exits non-zero when vulnerabilities become affected or newly require attention.
