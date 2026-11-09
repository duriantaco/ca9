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

## Upgrade review API

`ca9.api.review_upgrades` is the per-pair engine Skylos calls. It takes
`{"ecosystem", "name", "old", "new"}` pairs for npm and PyPI, diffs the two published
artifacts with deterministic static rules and returns the behaviours the new release
adds as `block`, `warn` and `info` deltas (`{"kind", "path", "line", "snippet",
"detail"}`), with a receipt. It never raises.

The downloaded artifacts are deleted after the review. Two opt-in options return the
code a reviewer needs to judge a delta, for example an AI second opinion on a `warn`.
Both are off by default; without them the output is byte-identical to a call that does
not know them.

```python
from ca9 import api

report = api.review_upgrades(
    [{"ecosystem": "pypi", "name": "requests", "old": "2.32.3", "new": "2.32.4"}],
    options={"context_lines": 20, "identity_diff_bytes": 50_000},
)
```

| Option | Range (default) | Adds |
|---|---|---|
| `context_lines` | 0-200 (0) | `context` (string) on every `block` and `warn` delta in a text file of the package |
| `identity_diff_bytes` | 0-200000 (0) | `identity_diff` (string) and `identity_diff_truncated` (bool) on a result with a `publisher_change` or `provenance_dropped` delta in `block`, `warn` or `info` |

`context` holds unified-diff hunks of the delta's file between the old and new
artifact, within `context_lines` lines of the delta's `line` (the file's first change
when `line` is null):

```text
@@ -14,3 +14,3 @@
 const v14 = 14;
-const v15 = 15;
+const cp = require('node:child_process');
 const v16 = 16;
```

A file the new release adds, and every file of a first release, is shown as `+` lines
under an `@@ -0,0 +a,b @@` header. Deltas in binary files or files over 32 MB, and
registry-metadata or lockfile deltas, have no `context`. A context is at most 8 KB and
the contexts of one result are at most 64 KB together: contexts that fit an equal share
stay whole and the others share the rest. A cut context keeps the delta's line in the
middle and ends with the line `... (truncated)`; a very long line (minified code) is
shown in part.

`identity_diff` is for releases where the only signal is a new publisher or missing
provenance. It is a unified diff, with `--- a/<path>` and `+++ b/<path>` headers and
three lines of context, of every changed `.js`, `.mjs`, `.cjs`, `.ts`, `.py`, `.pth`,
`.json`, `.sh`, `.toml` and `.cfg` file (so `setup.py` and `package.json` too) between
the compared artifacts, including added and removed files. Binary files and lockfiles
are skipped. Files with the smallest change come first, so small edits are not crowded
out by large rebuilt files; the text stops at `identity_diff_bytes` bytes and
`identity_diff_truncated` is true when a file or part of one was left out.

All text comes from the package files. Control, bidi and other invisible characters are
removed (tabs stay, other whitespace becomes a space). A CR, U+2028 or U+2029 inside a
line is shown as `\r`, ` ` or ` `, so code after a hidden line break cannot
pass for part of a comment. Nothing else is changed: URLs and strings in the code are
not redacted.

Values that are not integers in range are listed in the receipt's `invalid_options`
and ignored, which makes the receipt incomplete, as for the other options. When either
option is passed, the receipt has `context_lines` with the value applied (0 when it was
rejected or not given), so a caller can tell that the engine supports these options.

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
