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
| `UNREACHABLE (dynamic)` | `not_affected` |
| `INCONCLUSIVE` | `under_investigation` |

Accepted-risk and baseline findings are still emitted as OpenVEX statements with `ca9.policy_ignored` metadata, so downstream review can see the finding even though it did not affect ca9's exit code.

## Continuous VEX

Compare previous and current OpenVEX output:

```bash
ca9 vex-diff --base previous.openvex.json --head current.openvex.json
```

`vex-diff` exits non-zero when vulnerabilities become affected or newly require attention.
