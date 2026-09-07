---
title: Dependency Update Review
description: Compare npm lockfile updates using verified release artifacts, lifecycle declarations, and bounded static behavior observations.
---

# Dependency update review

`ca9 review` explains what changed in an npm dependency update. It compares two
v2/v3 `package-lock.json` files, keeps separate installed occurrences and dependency
chains, and inspects the release artifacts for changed dependencies. Package code
is never executed.

```bash
git show main:package-lock.json > /tmp/base-package-lock.json
ca9 review --base /tmp/base-package-lock.json --head package-lock.json
ca9 review --base /tmp/base-package-lock.json --head package-lock.json \
  -f json -o dependency-review.json
```

`--base` and `--head` accept file paths. They do not accept Git refs. The Markdown
report is suitable for a PR comment; JSON preserves all observations, including
unchanged ones, in the `ca9.dependency-review.v1` schema.

## What the comparison covers

The report identifies added, removed, and changed package occurrences, including
aliases and source changes. For changed occurrences, it downloads the base and
head registry tarballs, verifies their lockfile integrity hashes, safely unpacks
them, and compares package declarations and supported static observations.

Reviewable changes include lifecycle hooks, module format (`type`), executable and
startup entry points, dependency declarations, and package-code findings from
ca9's existing rules. Executable declarations include `bin`, `directories.bin`,
and declarations in bundled package manifests. Implicit native install hooks
respect `gypfile: false`.
Observations are compared independently of the package version and source line
number, so a release bump alone does not turn every existing finding into a new
alert. Removed observations remain visible without becoming new-risk alerts.
Code observations include a bounded readable preview and a digest of their full
normalized evidence. JavaScript whitespace and comments are normalized; arbitrary
rewrites, quote changes, and automatic semicolon insertion are not treated as
proven equivalent.

Each observation has a status (`added`, `removed`, `changed`, `unchanged`, or
`uninspectable`) and an action (`info`, `review`, or `block`). A new install hook
requires review. New blocking package-code findings or failed artifact integrity
checks can block. Existing observations remain available as context.

Unchanged lockfile occurrences are counted without downloading their artifacts.
The result covers the update; it is not a fresh audit of every installed package.
An unchanged workspace or unsupported artifact does not by itself make another
package's update incomplete. Malformed lock metadata or unresolved dependency chains
still leave the overall comparison incomplete.

## Incomplete evidence

A missing artifact, unsupported source, missing or invalid integrity evidence,
or unsupported relevant file cannot establish that a behavior disappeared or
that no behavior was added. The report records inspection gaps and keeps those
comparisons incomplete.

Known executable targets are resolved relative to their declaring package.
Simple local Node lifecycle commands can be inspected; external tools, shell
expansion, and command chains leave explicit gaps. A declared `prepare` hook is
reported separately from hooks run during registry-package installation.

Manifest declarations and executable-code inspection have separate completeness.
For example, verified manifests can establish that an install hook was added even
when a native file remains uninspectable. The overall report still stays
incomplete. Invalid manifest metadata cannot establish an added or removed
declaration.

To inspect lockfile changes without downloading artifacts:

```bash
ca9 review --base /tmp/base-package-lock.json --head package-lock.json \
  --no-scan-artifacts
```

Changed artifact behavior remains unknown in this mode. It does not produce a
complete behavior comparison merely because the metadata looks ordinary.

Only HTTPS artifacts from `https://registry.npmjs.org` are trusted by default.
Additional artifact origins require an explicit option; redirects must remain
within the trusted origins too:

```bash
ca9 review --base /tmp/base-package-lock.json --head package-lock.json \
  --trusted-registry https://packages.example.org \
  --cache-dir .ca9-artifacts
```

This option adds an HTTPS origin, including its port when present; it does not
trust arbitrary URLs from a lockfile. Artifact downloads and extraction are
bounded. The cache avoids repeated downloads, and cached artifacts still require
the recorded integrity verification.
Verification requires valid SHA-256, SHA-384, or SHA-512 SRI. When multiple
algorithms are recorded, the strongest supported algorithm must match. SHA-1-only
entries remain uninspectable.

Report displays redact URL credentials and query/fragment values, including URLs
in artifact dependency declarations. Original values are compared before display
redaction; JSON includes value identity digests when hidden differences would
otherwise make before/after values look identical. This is URL redaction, not a
general secret scan of package source.

## Library API

```python
from pathlib import Path
from ca9.review import review_lockfiles

report = review_lockfiles(
    Path("base-package-lock.json"),
    Path("package-lock.json"),
    cache_dir=Path(".ca9-artifacts"),
)
payload = report.to_dict()
exit_code = report.exit_code
```

## Decisions and CI

| Decision | Exit code | Meaning |
|---|---:|---|
| `pass` | `0` | Comparison is complete within the declared scope, with no new observations requiring review or blocking. |
| `review` | `1` | Complete comparison found new changes requiring review. |
| `block` | `1` | A blocking observation takes precedence, including when other evidence is incomplete. |
| `incomplete` | `2` | Evidence gaps prevent a complete comparison, including when some known changes need review. |

Invalid input also exits `2`. A `pass` is a bounded comparison result. It is not a
claim of JavaScript semantic equivalence, absence of malicious behavior, or
package safety. ca9 does not run the packages or resolve arbitrary dynamic code;
obfuscated code and native binaries can exceed its inspection scope.

This feature lives in ca9's dependency and artifact analysis layer. It does not
require Skylos or change application-code reachability analysis.
