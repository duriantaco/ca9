<p align="center">
  <img src="https://raw.githubusercontent.com/duriantaco/ca9/main/assets/ca9.png" alt="ca9 - evidence-backed Python package security" width="400">
</p>

<h1 align="center">ca9</h1>

<p align="center"><strong>Local, evidence-backed supply-chain defense for open-source packages.</strong></p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://mozilla.org/MPL/2.0/"><img src="https://img.shields.io/badge/license-MPL--2.0-blue.svg" alt="License: MPL-2.0"></a>
  <a href="https://pypi.org/project/ca9/"><img src="https://img.shields.io/badge/pypi-ca9-orange.svg" alt="PyPI"></a>
  <a href="#zero-heavy-dependencies"><img src="https://img.shields.io/badge/minimal--deps-brightgreen.svg" alt="Minimal Dependencies"></a>
  <img src="https://img.shields.io/badge/Skylos-A%2B%20%2899%29-brightgreen" alt="Skylos A+ (99)">
</p>

---

## What You Get

ca9 is the supply-chain engine behind the dependency and install checks in
[Skylos](https://github.com/duriantaco/skylos). Skylos calls ca9's library API
(`ca9.api`) to decide whether a package is malicious, too new, confused with an
internal name, installed from a mutable or untrusted source, or published
without the provenance its earlier releases had. The ca9 CLI keeps working on
its own: everything below runs without Skylos.

ca9 tells you whether your dependency supply chain is safe enough to ship, and
helps stop unsafe packages before they run.

Use it when you want to:

- **Know what you have:** build a local package inventory from manifests,
  lockfiles, artifacts, SBOM inputs, and declared dependency evidence.
- **Know what is risky:** flag malicious packages, vulnerable packages,
  unreachable/noisy CVEs, untrusted registries, dependency-confusion risk,
  missing hashes, suspicious artifacts, bad licenses, Git/URL dependencies, and
  install-script risk.
- **Know what to do:** get evidence-backed decisions such as block, warn,
  investigate, suppress, upgrade, remove, pin, rotate credentials, or verify
  manually.
- **Prevent risky installs:** enforce package policy in CI or local installs so
  known malware, untrusted registries, and secret-exposing install scripts can
  be stopped before package code executes. `ca9 run` supports lockfile-backed
  `npm ci`, local pip requirements/constraints files, and explicit npm/pip
  package specs.

The core commands are meant to be plain:

```bash
ca9 vet .
ca9 protect .
ca9 scan --repo .
ca9 inventory --repo . -f json
ca9 feed status
ca9 run -- npm ci
```

Runtime preflight uses the same package evidence and policy:

```bash
ca9 run -- npm ci
ca9 run -- pip install -r requirements.txt
ca9 run -- npm install <package>
ca9 run -- python -m pip install <package>
```

Skylos answers "is this repo, PR, or code change risky?" and uses ca9 for the
package part of that answer. ca9 answers "is this package supply chain risky,
and should this dependency be allowed?", whether Skylos or the ca9 CLI asks.

## The problem

Your SCA tool (Snyk, Dependabot, Trivy, pip-audit, OSV, or another scanner) flags every CVE in your dependency tree. You get 60 alerts. Your team scrambles. But many of those CVEs are in code your application **never imports, never calls, and never executes**.

You're patching vulnerabilities in functions you don't use, in packages you didn't know you had, in code paths your app will never reach.

That's wasted engineering time. That's alert fatigue. That's how real vulnerabilities get ignored.

## What ca9 does

ca9 is a local-first supply-chain defense layer for open-source packages. Today,
its strongest path turns CVE alerts into evidence-backed fix, suppress, or
investigate decisions. Its inventory and vetting path normalizes packages,
artifacts, lockfile evidence, registries, licenses, malware advisories, and
dependency edges so ca9 can grow beyond CVE-only reachability without making any
resolver or package manager a required dependency.

It takes your CVE list and answers one question per vulnerability: **is this code actually reachable from your application?**

```bash
pip install ca9[cli]
ca9 scan --repo . --coverage coverage.json
```

For package inventory and supply-chain evidence, ca9 can read project manifests
natively and uses `fyn.lock` or npm `package-lock.json` when present:

```bash
ca9 inventory --repo . -f json
ca9 vet --repo . -f json
```

For agentic triage, ca9 can normalize SARIF from tools such as CodeQL or Semgrep
into a `ca9.evidence.v1` evidence report:

```bash
ca9 ingest-sarif codeql.sarif --repo . -f json
```

```
CVE ID               Package   Severity  Verdict
--------------------------------------------------------------
GHSA-cpwx-vrp4-4pq7  Jinja2    high      REACHABLE
GHSA-frmv-pr5f-9mcr  Django    critical  UNREACHABLE (static)
GHSA-mrwq-x4v8-fh7p  Pygments  medium    INCONCLUSIVE
--------------------------------------------------------------
Illustrative verdicts: reachable, statically unreachable, or requiring more evidence
```

Strict mode keeps test non-execution inconclusive. Every finding retains its
evidence and an explanation of what is still unknown.

## How it works

ca9 combines repository evidence with advisory metadata to determine whether vulnerable code is reachable:

**1. Static analysis (AST import tracing)** — Parses every Python file in your repo and traces `import` statements. If a vulnerable package is never imported, it's unreachable.

**2. Dependency inventory** — Uses declared dependencies, report metadata, local package metadata, `fyn.lock`, and npm `package-lock.json` when available to separate direct, transitive, imported, and unused packages.

**3. Dynamic analysis (coverage.py)** — Checks whether vulnerable code was actually *executed* during your test suite. A package might be imported but the specific vulnerable function might never be called.

**4. Advisory normalization** — Preserves source, aliases, CWE/CPE IDs, timestamps, and cache freshness where input data provides them, so evidence can be traced back to the alert.

```
For each CVE:
  Is the affected version installed or declared?
  ├── NO  → UNREACHABLE (static)
  └── YES → Is the package, affected submodule, or known vulnerable API used?
      ├── NO, with enough graph/import evidence → UNREACHABLE (static)
      ├── YES, and runtime/coverage confirms execution → REACHABLE
      ├── YES, but affected execution is unobserved or unmeasured → INCONCLUSIVE (strict)
      └── Not enough evidence → INCONCLUSIVE
```

ca9's default **strict** mode does not treat test non-execution as proof of
unreachability, even at 100% overall coverage. Balanced mode can retain a scoped
dynamic heuristic when explicit statement evidence exists. OpenVEX exports that
heuristic as `under_investigation`. Every verdict includes an evidence trail and
a confidence score explaining the decision.

## Where ca9 fits

ca9 does not replace every specialized scanner. It gives developers and security
teams one local command surface for package supply-chain evidence, risk decisions,
and audit outputs. Existing SCA tools can still provide advisory input; ca9 adds
reachability, package inventory, artifact evidence, and policy decisions.

| | ca9 | Alert-only SCA output | Hosted reachability platforms |
|---|---|---|---|
| **Local analysis** | Runs in your repo/CI | Varies | Often requires source upload or hosted project import |
| **Direct OSV scan** | Yes — `ca9 scan` queries OSV.dev directly | Not always | Varies |
| **SCA report parsing** | Snyk, Dependabot, Trivy, Grype, OSV-Scanner, pip-audit | Native to each tool | Platform-specific |
| **Package inventory** | Native manifests plus optional `fyn.lock` and npm `package-lock.json` artifacts, registries, and dependency edges | Varies | Varies |
| **Supply-chain vetting** | Malware advisories, registry trust, artifact hashes, package age with local feeds, source-only risk, dependency confusion, workflow risk, and license policy | Varies | Varies |
| **Protection posture** | One local `ca9 protect` report for install-workflow coverage, feed state, exception hygiene, package policy, and Actions trust boundaries | Varies | Varies |
| **Static + dynamic evidence** | Imports, dependency graph, coverage, API usage | Usually package-level alerts | Varies by vendor and integration |
| **Open outputs** | JSON, SARIF, OpenVEX, Markdown, HTML, remediation, action plan | Vendor-specific | Platform-specific |
| **Confidence/evidence trail** | Structured evidence per verdict | Limited | Varies |
| **Runtime prevention** | `ca9 run` preflight and scoped npm/PyPI metadata gateways for lockfile-backed npm installs, pip requirements/constraints, and direct npm/pip specs | Varies | Varies |

**Use ca9 when you want an open, local package supply-chain defense layer for
inventory, CVE triage, package vetting, CI gates, SARIF upload, OpenVEX
generation, SBOM enrichment, and install-time enforcement for supported npm and
pip workflows.**

## Current capability snapshot

| Surface | Current capability |
|---|---|
| CVE reachability | Parses Snyk, Dependabot, Trivy, Grype, OSV-Scanner, and pip-audit reports; scans OSV directly; combines static import evidence, dependency graph evidence, optional coverage, vulnerable API rules, threat intel, accepted risks, and baselines. Non-Python report findings remain explicitly inconclusive. |
| Inventory | Reads Python manifests and requirements files (including `--hash` pins, bare `git+`/URL/local-path lines, and whether `--index-url` is exclusive or `--extra-index-url`/`--find-links` merge indexes), `fyn.lock`, and npm `package-lock.json` v2/v3 with full dependency graphs, registries, artifact URLs, hashes, and npm SRI integrity; `uv.lock`, `poetry.lock`, and `Pipfile.lock` currently contribute versions for declared direct dependencies only. |
| Vetting | Gates untrusted registries, dependency confusion, missing hashes, direct URL/Git/mutable sources, local feed malware, optional OSV malware queries, package age, workflow risk, artifact code heuristics, and license policy. |
| Protection posture | `ca9 protect` detects dependency workflows, validates enforceable npm locks and pip requirements, reports unsupported managers, feed readiness, expired exceptions, package-policy decisions, and local GitHub Actions risks in table, JSON, Markdown, or SARIF. |
| Artifact analysis | Hash-verifies and safely unpacks Python wheels/sdists and npm tarballs (lockfile artifacts, local sdist/wheel requirement paths, and pinned PyPI requirements resolved through the PyPI JSON API); scans Python startup/install/import-time behavior and npm lifecycle, encoded execution, credential exfiltration, and wallet/network API hijacking patterns without executing package code. |
| Dependency update review | `ca9 review` compares npm v2/v3 lockfiles and verified release artifacts, highlights new lifecycle hooks, entry points, dependencies, and static observations, and reports incomplete comparisons explicitly. |
| Runtime prevention | Supports lockfile-backed `ca9 run -- npm ci`, local `-r` requirements and `-c` constraints, plus direct `npm install ...`, `npm i ...`, `pip install ...`, and `python -m pip install ...` specs; checks policy before execution; strips or blocks secrets; mediates npm/PyPI metadata through loopback gateways when a feed is available. |
| Feeds and audit | Installs `ca9.feed.v1` package-intelligence bundles into `~/.cache/ca9/feed`; verifies snapshot hashes; records redacted runtime audit JSONL including preflight decisions, feed use, gateway use, denied versions/links, and child process exit. |

## Real-world results

These historical results predate the stricter coverage-scope rules. Current
strict-mode results can include more inconclusive findings where earlier runs
used test non-execution to suppress alerts.

### Django REST Framework — 37 CVEs, 19% noise

A focused library that genuinely uses most of its deps. Even here, ca9 found 7 CVEs in packages that are installed but never imported (redis, sentry-sdk, pip):

```
$ ca9 scan --repo /path/to/drf -v

GHSA-g92j-qhmh-64v2  sentry-sdk  low       UNREACHABLE (static)
                      -> 'sentry-sdk' is not imported and not a dependency of any imported package
GHSA-8fww-64cx-x8p5  redis       high      UNREACHABLE (static)
                      -> 'redis' is not imported and not a dependency of any imported package
...
Total: 37  |  Reachable: 0  |  Unreachable: 7  |  Inconclusive: 30
```

### Flask app with bloated deps — 61 CVEs, 59% noise

A Flask app that imports 4 packages but has 19 pinned in `requirements.txt` (Django, tornado, Pygments added "just in case"):

```
$ ca9 scan --repo demo/ --coverage demo/coverage.json

Total: 61  |  Reachable: 25  |  Unreachable: 36  |  Inconclusive: 0

59% of flagged CVEs are unreachable — only 25 of 61 require action
```

Django alone brought 21 CVEs that were pure noise.

**The pattern:** ca9's value scales with how bloated your dependency list is — which in enterprise codebases is typically *very*.

## Quick start

### Scan repository dependency versions (no SCA tool needed)

```bash
pip install ca9[cli]
ca9 scan --repo .
```

This resolves exact dependency versions from the target repository and queries
[OSV.dev](https://osv.dev). ca9 does not use the ambient Python environment unless
you explicitly pass `--allow-env-fallback`, which keeps CI scans tied to repository
evidence. No Snyk, no Dependabot, no config files.

### Inspect package inventory and lockfile evidence

```bash
ca9 inventory --repo . -f json
```

When `fyn.lock` or npm `package-lock.json` is present, ca9 reads it directly and includes
package versions, direct/transitive dependency edges, dependency groups, artifact URLs,
hashes or integrity values, registries, and source evidence. If there is no lockfile, ca9
falls back to native Python manifest readers for `pyproject.toml`, `requirements*.txt`,
`Pipfile`, `uv.lock`, and `poetry.lock`.

### Check whether dependency installs are protected

```bash
ca9 protect --repo .
ca9 protect --repo . -f json -o ca9-protect.json
ca9 protect --repo . -f sarif -o ca9-protect.sarif
```

`ca9 protect` is a read-only, local posture check. It detects package-manager
workflows, validates npm v2/v3 locks and pip requirements/constraints entry
points, reports which installs `ca9 run` can enforce, checks local feed readiness
and exception expiry, evaluates package-policy findings, and scans local GitHub
Actions workflows by default. Missing enforceable locks and blocking policy
decisions exit `1`; unsupported managers and other review items are warnings.
Use `--no-scan-workflows` when the report should cover dependency posture only.

### Review behavior changes in a dependency update

```bash
git show main:package-lock.json > /tmp/base-package-lock.json
ca9 review --base /tmp/base-package-lock.json --head package-lock.json
ca9 review --base /tmp/base-package-lock.json --head package-lock.json -f json
```

ca9 compares changed npm dependency occurrences using hash-verified registry
tarballs, without executing package code. The report highlights changes to
lifecycle hooks, executable and startup declarations, dependencies, and supported
static observations. Existing observations do not become new alerts merely
because a package version or source line number changes. Missing artifacts and
inspection gaps remain explicit; a pass covers only the declared comparison
scope. See the [dependency review guide](docs/guide/dependency-review.md).

### Run supply-chain risk checks

```bash
ca9 vet --repo .
ca9 vet --repo . --malware-query
ca9 vet --repo . --scan-publisher-changes
ca9 vet --repo . --scan-artifacts
ca9 vet --repo . --scan-workflows
ca9 vet --repo . --internal-package 'acme-*' --private-index https://packages.acme.internal/simple
ca9 vet --repo . --deny-license AGPL-3.0 --deny-license GPL-3.0
```

`ca9 vet` evaluates the normalized package inventory for local supply-chain risk signals:
untrusted package indexes, missing artifact hashes, missing artifact metadata,
source-only install risk, mutable package sources, package-age policy, and known
malware from the installed local feed.

Requirements lines that install from a source rather than an index are named
packages, not parse errors: `git+https://host/repo@ref#egg=name` is a Git
dependency (the evidence says whether `ref` is a full 40-hex commit), a bare
archive URL is a direct-URL dependency (name and version from `#egg=` or the
file name; the evidence says whether a usable `--hash` pins it), and a local
`./vendor/pkg-1.0.tar.gz` is a path dependency whose archive `--scan-artifacts`
inspects. A Git ref that is a branch, tag, or short id, or a URL without a hash,
is reported as mutable at medium severity; a full commit or a hash pin lowers
it to low.

`--index-url` alone makes one index serve every package (exclusive).
`--extra-index-url` and `--find-links` merge indexes: pip takes the best version
from any of them, so a package matching `--internal-package` in a merged setup
is critical dependency confusion (high when transitive) even when the extra
index is a configured `--private-index`. Public packages in a merged setup are
not attributed to the private index, and each untrusted index in the set is
still reported. With `--malware-query`, ca9 also queries
OSV for known malicious-package advisories such as `MAL-*`, `PYSEC-MAL-*`, and
malware-labeled GHSA/OSV records across PyPI and npm. With `--scan-workflows`,
ca9 checks GitHub Actions workflows for risky token scopes, OIDC write access,
`pull_request_target` trust-boundary patterns, mutable action refs, cache trust
boundaries, source-clone commands, encoded shell execution, cloud metadata
probing, and broad credential-file harvest patterns. Direct dependencies from
untrusted indexes, known malicious packages, too-new package versions, and
high-risk workflow patterns are blocking findings; weaker local signals are
warnings or investigation items.

With `--scan-publisher-changes`, ca9 queries public npm registry metadata for
direct, locked npm dependencies. It warns when a new publisher released a stable
version after at least 180 days without a release, within the last 365 days, and
the locked version belongs to that publisher's later releases. Verified npm
trusted publishing and publishers who maintain another package with at least
100,000 weekly downloads are exempt. This is a review signal, not a malware
verdict. The same scan blocks a provenance regression: the locked version has
no registry attestation (`dist.attestations`) and no trusted publisher, while
at least one of the five stable releases published before it on the same
release line (major, or `0.minor`) had one. A first release on a new line is
compared with the releases before it. A release on a line that never had
provenance is still flagged when newer lines published before it had it; the
evidence marks that `line: "newer"` because a hand-published backport looks the
same. Packages that never published with provenance are not flagged. The check
requires network access and cannot be combined with `--offline`.

With `--scan-artifacts`, ca9 downloads only lockfile artifacts with hashes by
default, verifies the hash, safely unpacks Python wheels/sdists and npm tarballs
without executing code, and runs GuardDog-style static heuristics for suspicious
`.pth` startup execution, install-time `setup.py` execution, startup
customization hooks, credential/network exfiltration, import-time risky
behavior, silent process execution, encoded payload execution, npm lifecycle
script execution, npm encoded execution, npm credential exfiltration, and npm
code that replaces browser wallet methods (`ethereum`/`solana` request or sign)
or overrides the global `fetch`/`XMLHttpRequest` from obfuscated names or next
to crypto-address patterns, the shape of the September 2025 chalk/debug wallet
drainer, which had no install script. A polyfill that only assigns `fetch` when
it is missing stays quiet. Pinned PyPI requirements without a lockfile are
resolved through the PyPI JSON API when PyPI is the only index: ca9 picks the
pure-Python wheel, else the sdist, and with `--hash` pins only a pinned file.
Unhashed requirements still need `--allow-unhashed-downloads`, and names
matching `--internal-package` are never looked up on PyPI.

Lockfile URLs are treated as untrusted input. ca9 fetches only `https` URLs on
public registries or on `--trusted-index`/`--private-index` hosts, never
follows redirects to other kinds of address, and refuses hosts that resolve to
loopback, private, or link-local addresses unless they are a configured
`--private-index`. Local artifact paths are read only inside the vetted
repository or a directory passed with `--local-artifact-root`. Refused URLs are
reported as `artifact_untrusted_url` findings. Each archive is unpacked only in
the format its type implies (npm tarballs and sdists as tar, wheels as zip);
bytes that parse as both are blocked as `artifact_ambiguous_archive`. Entry
counts, total size, and expansion ratio are capped, and downloads are verified
before they enter the cache. `sha1`/`md5`-only integrity is accepted as weak
evidence (`artifact_weak_integrity`) rather than reported as a mismatch. Files
too large to scan fully are reported as uninspected instead of being skipped
silently.

### Configure package policy

Use `ca9.toml` when a project needs explicit supply-chain policy:

```toml
[mode]
default = "block" # off, warn, block, strict
offline = "warn"

[registries]
allow = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
deny = []
custom_requires_approval = true

[malware]
enabled = true
fail_closed = false

[package_age]
enabled = false
minimum_hours = 48
exclusions = []

[[exceptions]]
policy_id = "ca9.package_age"
ecosystem = "pypi"
package = "example-package"
version = "1.2.*"
action = "warn"
owner = "platform-security"
reason = "Validated emergency release"
expires = 2026-08-01
```

Validate and inspect the effective policy before using it in CI:

```bash
ca9 policy validate --policy ca9.toml
ca9 policy explain --policy ca9.toml
ca9 vet --repo . --policy ca9.toml
```

The policy controls whether ca9 passes, warns, or blocks package supply-chain
findings. CLI flags such as `--trusted-index`, `--private-index`, and
`--internal-package` can still be used for one-off runs. Exceptions are matched
by policy ID and optional ecosystem/package/version globs, require an owner,
reason, and expiry date, and are recorded in decision evidence. Expired
exceptions do not apply. Known-malware decisions (`ca9.malware`) cannot be
overridden.

**Policy trust.** ca9 merges built-in defaults, your user policy
(`~/.config/ca9/policy.toml`), and `CA9_POLICY`, and trusts all of them. A
`ca9.toml` that ca9 merely *finds* in the working directory is treated as
untrusted repository content: it can tighten the policy (raise the mode, add
denied registries, enable checks) but every setting that would relax it — a
lower mode, a disabled check, a wider `registries.allow`, a lower
`minimum_hours`, new exceptions — is ignored with a warning naming the key.
This stops a cloned repository or a pull request from switching ca9 off. To
trust a repository policy, pass it explicitly with `--policy ca9.toml` or set
`CA9_POLICY=ca9.toml`. `ca9 policy explain` lists any ignored settings.

Install package-intelligence feed data when you want deterministic offline
package-age or package-malware decisions:

```bash
ca9 feed update
ca9 feed update --require-attestation
ca9 feed update --from ./ca9-feed.json
ca9 feed status --policy ca9.toml
```

`ca9 feed update` without `--from` resolves `--from`, then `CA9_FEED_URL`, then
the built-in default feed URL on the project's published `feed` branch. Use
`--from` or `CA9_FEED_URL` to select a local or alternate hosted bundle.
`--require-attestation` verifies the downloaded bundle with `gh attestation
verify`, requiring a signature from `.github/workflows/feed.yml` running on
`refs/heads/main` (exact certificate identity and source ref, GitHub-hosted
runner), and installs nothing unless that passes (a missing `gh` fails too). The GitHub Action runs it before `protect`.

The hosted feed is published every hour. Its OSV malware data is rebuilt every 6
hours and copied forward unchanged in between; `ca9 feed status` shows when it was
built (`OSV data built`), and a bundle expires 7 days after that time. Every hour a
sentinel job also reviews new releases of the most downloaded npm and PyPI packages
with ca9's static upgrade review and publishes the ones that look malicious in the
optional `npm-suspicious` and `pypi-suspicious` datasets, often before they reach OSV.
These are flags from a static review, not confirmed reports; reviewed false positives
are listed in `sentinel/allow.json`. The [supply-chain guide](docs/guide/supply-chain.md)
describes both and how to report a false positive.

Feed sources must be `https://` URLs or local paths. Downloads are capped at
256 MiB, snapshots dated more than a day in the future are rejected, and a
snapshot is never treated as fresh for more than 30 days after it was built.
Installing a snapshot older than the one already installed is refused as a
possible rollback unless you pass `--allow-downgrade`.

When the feed is missing, `vet`, `protect`, `scripts audit`, and `ca9 run` say
so on every run instead of passing silently. When it has expired, ca9 still
matches packages against the stale snapshot and warns how old it is. Set
`[malware].fail_closed = true` to block instead. Only records with an OSV
`MAL-` identifier, explicit malicious-package metadata, or CWE-506 "Embedded
Malicious Code" count as malware; ordinary vulnerability advisories are never
reported as malicious packages. Records that only give bounded version ranges
(such as `@solana/web3.js` 1.95.6 to 1.95.8) ship in the optional
`*-malware-ranges` datasets and match only versions inside a range.

Package-age release times come from the feed when it has them and otherwise
from registry metadata (npm packument `time`; for PyPI the newest upload among
a release's non-yanked files, so a file added to an old release makes it new),
cached under `~/.cache/ca9/release-times/`. `ca9 run` holds versions younger
than 24 hours by default and names an older version to use; a trusted policy
turns that off with `package_age.enabled = false` or
`package_age.minimum_hours = 0`, while a discovered repository `ca9.toml` can
only raise the hold. When a release time cannot be read (registry outage,
unparseable time, npm packument over 64 MiB) the default hold only warns.
`vet` and `protect` check package age only when policy enables it.

### Audit install scripts for npm v12 allowlists

npm v12 became the `latest`/GA release on July 8, 2026. It skips dependency
lifecycle scripts unless the package is approved in your project's `allowScripts`
allowlist (pnpm ≥10 has a similar model). Instead of `npm approve-scripts --all`,
audit the script-bearing packages with evidence first:

```bash
ca9 scripts audit .
ca9 scripts audit . --emit commands
```

The audit requires a readable npm v2/v3 `package-lock.json`. Missing, malformed,
unsupported, or unmaterializable script-bearing lock entries are hard errors, not
empty results. Each lockfile occurrence is audited independently, including two
occurrences with the same name and version at different install paths. Local
workspace packages are excluded; external or out-of-root file sources remain visible
as `review` findings.

ca9 checks `preinstall`, `install`, and `postinstall`, plus `prepare` for
non-registry dependencies. A version-matched `node_modules` manifest can supply hook
text, but the package's registry policy identity comes from trusted lockfile source
evidence, not package-controlled manifest fields. Offline or incomplete evidence
remains `review`.

Malware findings and explicitly denied registries produce `deny`; custom
registries requiring approval are not fetched and remain `review`. If a malware
feed configured as fail-closed is unavailable, the audit suppresses approvals and
exits `1`. Whole-command native-build shapes such as `node-gyp rebuild` remain
`review` even after clean analysis of a hash-verified artifact: the package artifact
alone cannot prove which executable will run or fully establish GYP/build provenance.
`--allow-unhashed-downloads` permits investigation of an unhashed artifact, but does
not make that artifact verified approval evidence. v1 is intentionally
deny/review-oriented and does not promise a reachable automatic approval path.

`--emit commands` accounts for npm applying a package-name command to every installed
occurrence of that name. A deny in any occurrence wins; otherwise, any reviewed
occurrence suppresses approval. Before emitting a command, ca9 requires trusted npm
policy identity and version evidence and an exact match between every audited locked
occurrence and the installed `node_modules` tree. Approval commands use the explicit
pinning form `npm approve-scripts <name> --allow-scripts-pin`. Missing or mismatched
evidence produces a comment instead of a command. The generated `#` comments work in
POSIX shells and PowerShell. ca9 never edits the allowlist or executes a generated
command. Exit codes are `1` for a denial or global blocker, `2` when review findings
remain, and `0` when neither is present.

Scripts-audit options:

```
-r, --repo DIRECTORY            Project directory (alternative to DIRECTORY)
-f, --format [table|json]       Report format  [default: table]
--emit [report|commands]        Audit report or guarded npm command lines
-o, --output PATH               Write output to a file instead of stdout
--policy PATH                   ca9 package, registry, and malware policy TOML
--offline                       Skip downloads; unverified packages remain review
--allow-unhashed-downloads      Allow tarball fetch without lockfile integrity
--max-artifact-mb N             Positive max artifact download size  [default: 100]
```

The positional `DIRECTORY` and `--repo` accept directories only. `--emit commands`
uses comment-and-command text output and cannot be combined with `--format json`.

### Run installs through ca9

Use `ca9 run` when you want ca9 to preflight an install before package code can
execute:

```bash
ca9 run -- npm ci
ca9 run -- npm install express@4.18.2
ca9 run -- npm i @scope/pkg@1.2.3
ca9 run -- python -m pip install requests==2.31.0
ca9 run -- pip install requests==2.31.0
ca9 run -- pip install -r requirements.txt -c constraints.txt
```

`npm ci` and its clean-install aliases are checked against every exact non-project
version in `package-lock.json`, including transitive dependencies. Each entry's
`resolved` tarball URL must name that same package and version. A missing,
unreadable, or unsupported lockfile, or an `npm-shrinkwrap.json` (which npm
would prefer over the checked lock), blocks before npm starts. Zero-argument
`npm install` runs the same lockfile check and is blocked only when the project
has no v2/v3 `package-lock.json`; anything npm resolves fresh still goes
through the npm gateway. `npm install <pkg>` checks the requested packages
plus the project lockfile. Direct npm and pip registry package specs remain
supported, including `npm:` aliases, which are checked as the real package.

npm specs that npm would fetch from somewhere other than the registry —
`https:` tarballs, `git+`/`github:`/`gist:` and `user/repo` specs, `file:`/
`link:` paths, and local `.tgz` files — are blocked, as are pip local archives,
paths, and PEP 508 `name @ url` references. npm commands that install or
execute packages but are not analyzed yet (`npm update`, `npm exec`/`npx`,
`npm init`/`create`, `npm rebuild`, `npm dedupe`, `install-test`, `cit`) are
blocked rather than passed through. Leading global options such as
`npm --silent install`, `pip -q install`, and `python3 -I -m pip install` are
parsed, and `pip3`/`python3` are recognized. Local pip requirement and constraint files are
parsed recursively before pip starts; includes resolve relative to their
containing file and must remain inside the repository. Exact pins and hashes are
retained as evidence, constraints refine declared requirements, and
constraint-only packages are not treated as requested installs. Remote
requirements, direct URLs, editable/local paths, extra indexes, find-links, and
other package managers are blocked instead of being guessed. Explicit
registry/index command options and npm/pip registry environment variables are
checked against policy; alternate pip sources such as extra indexes and find-links
are blocked until multi-source mediation is implemented.

`ca9 run` checks the local package feed for known malware and package age,
detects secret-bearing environment variables, strips or blocks secrets according
to policy, executes the child command only when allowed, preserves the child
exit code, and writes a redacted audit event stream. Secrets are detected by
name (`*_TOKEN`, `*_PASSWORD`, `*_CREDENTIALS`, `NODE_AUTH_TOKEN`,
`CI_JOB_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_*`, `SSH_AUTH_SOCK`, and similar) and
by value (URLs with embedded passwords, JWTs, known token prefixes). When
stripping is enabled, GitHub Actions file-command variables (`GITHUB_ENV`,
`GITHUB_PATH`, `GITHUB_OUTPUT`, …) are removed too, so install scripts cannot
persist changes into later steps. Environment stripping is defense in depth,
not a sandbox: install scripts still run as your user and can read files such
as `~/.npmrc` or cloud credential files. The audit log is created with mode
0600, redacts registry auth tokens and credential-bearing URLs, and a failed log
write never blocks or masks the child's exit code. SIGINT/SIGTERM are forwarded
to the child, and a child killed by signal N makes ca9 exit with 128+N. Release
times missing from the local feed are read from registry metadata. When
package-age policy is enabled and neither knows a release time, pip preflight
warns by default and blocks when `[mode].offline` is `block` or `strict`; npm
unknown release times are deferred to the npm gateway. Under the built-in 24-hour
default an unknown release time only warns.

For npm and pip installs, `ca9 run` can also start child-process-scoped loopback
gateways when a local feed is available. The npm gateway fetches upstream
metadata, hides versions denied by policy, recomputes `dist-tags` (choosing the
highest remaining stable version for `latest`), denies tarball downloads for
denied versions, refuses cross-host or non-https upstream redirects, and leaves
upstream bytes unchanged when nothing is denied. The PyPI gateway
filters Simple API wheel and sdist links denied by policy through `PIP_INDEX_URL`.
Both gateways bind only to `127.0.0.1`, reject proxy-style absolute URLs, and
clear child-process package-manager config sources that would bypass the
loopback gateway. A requirements-file index is retained as upstream policy
evidence, while ca9 appends the loopback index as the final child option so it
cannot bypass mediation. Gateway rewrites and applied package exceptions are
recorded in the runtime audit log.

### Add CI shims

For GitHub Actions, install opt-in package-manager shims after ca9 is available
in the job:

```bash
ca9 setup ci install
ca9 doctor ci
```

`ca9 setup ci install` writes `npm`, `npx`, `pip`, `pip3`, `python`, and
`python3` shims under the ca9 cache and appends that directory to
`$GITHUB_PATH`. The npm shim skips leading global options to find the
subcommand: read-only and project-script commands (`npm run`, `npm test`,
`npm ls`, `npm view`, …) go straight to the real npm, and every other command —
every install alias, `update`, `exec`, `init`, unknown commands — goes through
`ca9 run`, which checks it or blocks it. `npx` always routes through `ca9 run`.
The pip shims route `install`, `download`, `wheel`, and unknown commands; the
python shims route `-m pip` after any interpreter flags. `ca9 run` resolves the
real package manager itself, so nested installs started by lifecycle scripts go
back through the shims without recursion. `ca9 doctor ci` fails when another
directory earlier on `PATH` shadows a shim — for example after a later
`actions/setup-node` or `setup-python` step — so run it after your toolchain
setup steps.

### Add local shell shims

For local opt-in interception, print the managed shell block first:

```bash
ca9 setup shell --print
```

Install only when you are ready to edit the selected shell profile:

```bash
ca9 setup shell --install
ca9 doctor shell
ca9 teardown shell
```

`ca9 setup shell --install` writes the same shims under
`~/.cache/ca9/bin` and adds a ca9-owned block to your shell profile. Every edit
creates a backup first. `ca9 teardown shell` removes only the ca9-managed block;
it does not remove arbitrary matching PATH lines.

### Replay real incident fixtures

```bash
python scripts/incident_replay.py --strict --format table
```

ca9 keeps real incident fixtures for npm package compromise, PyPI import-time malware,
and GitHub-token compromise scenarios. The current matrix is intentionally honest:
malware advisories and workflow-risk patterns are covered where fixtures prove them, while
npm/Python artifact heuristics, import-time malware, and identity/audit-log surfaces remain
partial.

For dependency-confusion controls, use `--internal-package` with one or more private
package name patterns and `--private-index` for the indexes those packages are allowed to
resolve from. For license policy, use `--deny-license`; ca9 reads wheel/sdist metadata and
blocks denied direct dependencies while warning or investigating weaker cases.

### Screenshot-ready supply-chain demo

Use the local demo fixture when you need a report screenshot or a JSON artifact without
depending on a live suspicious repository:

```bash
bash demo/supply_chain/run_demo.sh
```

The fixture generates a `fyn.lock` with local, hash-pinned wheel artifacts and then runs
`ca9 vet` with artifact scanning, dependency-confusion policy, and denied-license policy.
The underlying gate exits `1` because the findings are intentionally blocking; the wrapper
still writes `demo/supply_chain/ca9-vet.json` for screenshots and CI artifact examples.

```
ca9 supply-chain report for .../demo/supply_chain/repo
Packages: 4 | Edges: 3 | Findings: 3 | Block: 3 | Warn: 0
Artifact scans: 3 | Skipped artifacts: 0

Findings:
  [BLOCK] dependency_confusion critical acme-internal@1.0.0
    Possible dependency confusion for acme-internal
  [BLOCK] python-startup-pth-exec critical startup-hook@1.0.0
    Python startup file executes suspicious code in startup-hook
  [BLOCK] denied_license high license-risk@1.0.0
    Denied license for license-risk
```

### Add dynamic analysis for better results

```bash
coverage run --source=.,$(python -c "import site; print(site.getsitepackages()[0])") -m pytest
coverage json -o coverage.json
ca9 scan --repo . --coverage coverage.json
```

ca9 never runs your test suite unless you ask it to. Pass `--auto-coverage`
(or set `auto_coverage = true` in `.ca9.toml`, or `auto-coverage: true` in the
GitHub Action) to let `check` and `scan` discover existing coverage data or
generate it by running pytest. `--no-auto-coverage` is still accepted and is
now the default behavior.

### Analyze an existing SCA report

```bash
ca9 check snyk.json --repo . --coverage coverage.json
ca9 check dependabot.json --repo .
```

Format is auto-detected. Supports **Snyk**, **Dependabot**, **Trivy**, **Grype**,
**OSV-Scanner**, and **pip-audit**:

```bash
ca9 check snyk.json --repo .
ca9 check dependabot.json --repo .
ca9 check trivy.json --repo .
ca9 check grype.json --repo .
ca9 check osv-scanner.json --repo .
ca9 check pip-audit.json --repo .
```

## Verdicts

| Verdict | What it means | What to do |
|---------|---------------|------------|
| `REACHABLE` | Evidence shows the vulnerable package, component, or known API is reachable | **Fix this** |
| `UNREACHABLE (static)` | ca9 has evidence the vulnerable code cannot load: the package (identified by its real import names) is never imported, not even transitively, and nothing suggests it is used without an import | Suppress with confidence |
| `UNREACHABLE (dynamic)` | Balanced-mode heuristic: no execution observed in reported affected statements | Review the observation's scope; it is not proof of unreachability |
| `INCONCLUSIVE` | Evidence is insufficient, including missing measurement or strict-mode test non-execution | Inspect evidence gaps and review manually |

ca9 treats a false `UNREACHABLE` as the dangerous mistake, so it only reports
one when it can show absence. Import names come from installed package metadata
(RECORD/`top_level.txt`) or a curated map — `GitPython` is `git`, `grpcio` is
`grpc` — and a package whose import name is only guessed stays `INCONCLUSIVE`.
A declared dependency that is never imported is `INCONCLUSIVE` in strict mode,
and in balanced mode whenever something suggests indirect use: plugin entry
points, a command it installs that the repository invokes (Makefile,
Dockerfile, Procfile, shell scripts, CI workflows, config files), its name in
a string literal or config file (`BeautifulSoup(x, "lxml")`, Django
`INSTALLED_APPS`, database URLs), being an optional extra of an imported
package, or being a known server, driver, or engine. "Affected submodule not
imported" suppresses only when the installed package's own imports never load
that submodule. OpenVEX output uses `vulnerable_code_not_present` for versions
outside the affected range, `component_not_present` for packages absent from
the environment and every dependency source, and
`vulnerable_code_not_in_execute_path` otherwise. Because of these rules, the
historical noise-reduction figures above are upper bounds; current runs report
more findings as `INCONCLUSIVE`.

## Evidence and confidence

Every verdict is backed by structured evidence. Use `--show-confidence` to see scores in table output, or inspect the `evidence` object in JSON/SARIF output.

| Signal | What it checks |
|--------|----------------|
| `advisory` | Advisory source, ecosystem, aliases, CWE/CPE IDs, and cache freshness metadata when available. |
| `version_in_range` | Is the installed version within the affected range (PEP 440)? |
| `package_imported` | Is the package imported anywhere in the repo? |
| `submodule_imported` | Is the specific vulnerable submodule imported? |
| `coverage_seen` | Execution observed (`true`), reported non-execution (`false`), or unknown (`null`) |
| `coverage_scope` | Whether affected targets have usable statement evidence in the report |
| `coverage_measured_files` / `coverage_unmeasured_targets` | Matching statement records and targets still lacking them |
| `api_call_sites_covered` | Were specific vulnerable API call sites executed in tests? |
| `coverage_completeness_pct` | Overall test coverage percentage, retained as context; it does not establish dependency measurement or strengthen absence confidence |
| `affected_component_source` | How was the vulnerable component identified (commit analysis, curated mapping, regex, class scan)? |

Confidence scoring is **verdict-directional** — evidence that supports the verdict boosts the score, evidence that contradicts it lowers it. A high confidence UNREACHABLE is different from a high confidence REACHABLE.

| Bucket | Score | Meaning |
|--------|-------|---------|
| High | 80-100 | Strong evidence supports the verdict |
| Medium | 60-79 | Moderate evidence, reasonable certainty |
| Low | 40-59 | Weak evidence, treat with caution |
| Weak | 0-39 | Very little evidence, manual review recommended |

## CLI reference

```
ca9 scan [OPTIONS]              Scan repository dependency versions via OSV.dev
ca9 check SCA_REPORT [OPTIONS]  Analyze a supported SCA JSON report
ca9 inventory [PATH] [OPTIONS]  Show normalized package inventory
ca9 protect [PATH] [OPTIONS]    Report dependency-install protection posture
ca9 review --base FILE --head FILE  Review npm dependency behavior changes
ca9 vet [PATH] [OPTIONS]        Run package supply-chain risk checks
ca9 run [OPTIONS] -- COMMAND    Preflight and run supported package-manager installs
ca9 scripts audit [DIRECTORY]   Audit dependency install scripts for npm allowlists
ca9 policy validate [OPTIONS]   Validate ca9 package policy
ca9 policy explain [OPTIONS]    Show effective ca9 package policy
ca9 feed status [OPTIONS]       Show local package feed cache status
ca9 feed update [OPTIONS]       Install a package intelligence feed snapshot
ca9 setup ci [print|install]    Print or install CI package-manager shims
ca9 setup shell [OPTIONS]       Print or install local shell package-manager shims
ca9 doctor ci [OPTIONS]         Check CI shim installation
ca9 doctor shell [OPTIONS]      Check local shell shim installation
ca9 teardown shell [OPTIONS]    Remove ca9-managed shell profile block

Common options:
  -r, --repo PATH                  Path to the project repository  [default: .]
  -c, --coverage PATH              Path to coverage.json for dynamic analysis
  -f, --format [table|json|sarif|vex|remediation|action-plan|markdown|html]
                                      Output format  [default: table]
  -o, --output PATH                Write output to file instead of stdout
  -v, --verbose                    Show reasoning trace for each verdict
  --auto-coverage                  Discover or generate coverage (runs pytest); off by default
  --show-confidence                Show confidence score in table output
  --show-evidence-source           Show evidence extraction source in table output
  --proof-standard [strict|balanced]
                                      Proof policy for suppressions
  --capabilities                   Attach AI capability blast radius
  --runtime-context PATH           Deployment-aware severity adjustment
  --trace-paths                    Trace exploit paths
  --threat-intel                   Enrich with EPSS and CISA KEV data
  --otel-traces PATH               Production runtime evidence from OTLP JSON
  --accepted-risks PATH            Accepted-risk TOML/JSON file
  --baseline PATH                  Previous ca9 JSON report for new-only gating
  --new-only                       Only gate on new reachable/inconclusive findings

Scan-only options:
  --offline                        Use only cached OSV data, no network requests
  --refresh-cache                  Clear OSV cache before fetching
  --allow-env-fallback             Use installed package versions when repo versions cannot be resolved
  --max-osv-workers N              Max concurrent OSV detail fetches  [default: 8]

Inventory-only options:
  -f, --format [table|json]         Output format  [default: table]

Vet-only options:
  --policy PATH                   ca9 package policy TOML
  --trusted-index URL               Trusted package index; repeatable
  --private-index URL               Private index allowed for internal packages
  --internal-package PATTERN        Internal package glob, e.g. acme-*; repeatable
  --malware-query                   Query OSV for known malicious packages
  --scan-publisher-changes          Query npm for publisher handovers and provenance regressions
  --scan-artifacts                  Hash-verify, unpack, and statically inspect artifacts
  --scan-workflows                  Scan GitHub Actions workflow risk patterns
  --allow-unhashed-downloads        Allow artifact downloads without lockfile hashes
  --max-artifact-mb N               Max artifact download size  [default: 100]
  --local-artifact-root DIR         Extra directory local lockfile artifacts may be read from
  --deny-license ID                 Denied license identifier; repeatable
  --require-known-license           Warn when artifact metadata has no known license
  --offline                         Use cached OSV data for malware query; incompatible with publisher checks

Policy-only options:
  --policy PATH                   ca9 package policy TOML
  -f, --format [table|json]       Output format for policy explain

Feed-only options:
  --from PATH_OR_URL              Feed bundle https URL, JSON file, or snapshot directory
  --allow-downgrade               Install a snapshot older than the installed one
  --policy PATH                   ca9 package policy TOML for status/offline behavior
  -f, --format [table|json]       Output format

Run-only options:
  --policy PATH                   ca9 package policy TOML
  --dry-run                       Run preflight only; do not execute the child command
  --audit-log PATH                Runtime audit JSONL path  [default: ~/.cache/ca9/audit.jsonl]
  -f, --format [table|json]       Output format; use --dry-run for JSON pass decisions

CI setup options:
  --shim-dir PATH                 Directory for npm, pip, and python shims
  -f, --format [table|json]       Output format for setup install or doctor

Shell setup options:
  --print                         Print the managed shell block without editing
  --install                       Install shims and edit the selected profile
  --profile PATH                  Shell profile to install, check, or teardown
  --shim-dir PATH                 Directory for npm, pip, and python shims
  -f, --format [table|json]       Output format for install, doctor, or teardown

Exit codes:
  0  No blocking findings for the selected command
  1  Blocking findings or command/policy errors
  2  Reachability scan produced inconclusive-only CVE results
```

### Config file

Create a `.ca9.toml` in your project root to set defaults:

```toml
repo = "src"
coverage = "coverage.json"
format = "json"
verbose = true
accepted_risks = "accepted-risks.toml"
baseline = "ca9-baseline.json"
new_only = true
```

Config is auto-discovered from the current directory upward. CLI flags override config values.
Accepted-risk and baseline options keep ignored findings visible in report output while excluding them from exit-code decisions.

### Caching and offline mode

ca9 caches OSV vulnerability details (`~/.cache/ca9/osv/`, 24h TTL), GitHub
commit file lists (`~/.cache/ca9/commits/`, 7-day TTL), and package
intelligence feeds (`~/.cache/ca9/feed/`) to reduce network dependence and make
CI runs deterministic. Runtime preflight writes redacted audit events to
`~/.cache/ca9/audit.jsonl` by default.

```bash
ca9 scan --repo . --offline           # use cached data only, no network
ca9 scan --repo . --refresh-cache     # clear cache and re-fetch
ca9 feed update                       # use default feed URL or CA9_FEED_URL
ca9 feed update --from ./ca9-feed.json # install local package intelligence
ca9 feed status --policy ca9.toml      # verify freshness and offline policy
```

Package feeds use schema `ca9.feed.v1` and include four datasets:
`pypi-malware`, `npm-malware`, `pypi-releases`, and `npm-releases`, plus the
optional `pypi-malware-ranges` and `npm-malware-ranges`. Feed status
verifies SHA-256 content hashes before using cached data. Missing or stale feeds
warn or block according to `[mode].offline`; tampered feeds always block.

Runtime audit events use schema `ca9.run.ledger.v1`. The JSONL stream records
session start/end, command observation, package requests, decisions, feed use,
offline fallback, gateway use, gateway-denied versions/links, secret names
detected/stripped, and child process start/exit. ca9 logs secret names, never
secret values, and redacts URL credentials and Authorization-like text.

Set `GITHUB_TOKEN` to avoid GitHub API rate limits when ca9 fetches commit data for affected component analysis:

```bash
export GITHUB_TOKEN=ghp_...
ca9 check snyk.json --repo .
```

### fyn integration

ca9 does not require fyn. If a repository has `fyn.lock` or npm `package-lock.json`,
`ca9 inventory` parses it natively and treats it as high-fidelity package evidence. This
gives ca9 exact resolved versions, direct/transitive edges, groups, artifact hashes or
integrity values, artifact URLs, and source registries without shelling out to package
manager CLIs.

`ca9 vet` builds on that evidence for local supply-chain checks. For example, a direct
dependency resolved from a non-trusted index is treated as risky, and an internal package
matching `--internal-package` is blocked if it resolves outside the configured
`--private-index` values.

When `--scan-artifacts` is enabled, fyn's artifact URLs and hashes let ca9 verify and
inspect resolved wheels/sdists before applying malicious-package heuristics. npm
`package-lock.json` entries likewise provide tarball URLs and SRI integrity for npm
artifact scanning. This path does not install packages or execute package code. The same
artifact metadata powers license checks through `--deny-license` and
`--require-known-license`.

Future ca9 commands can use fyn as an optional provider for dependency-path and lock-diff
context, but absence of fyn should not break scans or CI gates.

## MCP server

ca9 ships an MCP server so LLM-powered tools (Claude Code, Cursor, etc.) can run reachability analysis directly.

```bash
pip install ca9[mcp]
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "ca9": {
      "command": "ca9-mcp"
    }
  }
}
```

Available tools:

| Tool | What it does |
|------|-------------|
| `check_reachability` | Analyze a supported SCA report, including Grype and OSV-Scanner JSON |
| `scan_dependencies` | Scan repository dependency versions via OSV.dev |
| `check_coverage_quality` | Assess how reliable your coverage data is |
| `explain_verdict` | Deep-dive a specific CVE's verdict with full evidence |
| `generate_vex` | Generate OpenVEX exploitability statements |
| `generate_remediation_plan` | Generate prioritized remediation actions |
| `scan_capabilities` | Scan AI capabilities and emit an AI-BOM |
| `check_blast_radius` | Attach capability blast radius to reachable CVEs |
| `trace_exploit_path` | Trace paths to vulnerable API call sites |
| `lookup_threat_intel` | Look up EPSS and CISA KEV data |
| `enrich_sbom` | Enrich CycloneDX or SPDX SBOM JSON |

## Library usage

```python
import json
from pathlib import Path
from ca9.parsers.snyk import SnykParser
from ca9.engine import analyze

data = json.loads(Path("snyk.json").read_text())
vulns = SnykParser().parse(data)

report = analyze(
    vulnerabilities=vulns,
    repo_path=Path("./my-project"),
    coverage_path=Path("coverage.json"),
)

for result in report.results:
    print(f"{result.vulnerability.id}: {result.verdict.value} (confidence: {result.confidence_score})")
    print(f"  reason: {result.reason}")
    if result.evidence:
        print(f"  source: {result.evidence.affected_component_source}")
```

### Supply-chain API

`ca9.api` is the stable interface Skylos uses. It takes plain package dicts, so a
caller can reuse its own inventory:

```python
from ca9 import api

result = api.evaluate_packages(
    [
        {"ecosystem": "pypi", "name": "acme-billing", "version": "2.0.0", "direct": True,
         "registry": "https://pypi.acme.internal/simple", "registry_mode": "merged",
         "source_kind": "registry", "file": "requirements.txt", "line": 2},
    ],
    options={"internal_packages": ["acme-*"],
             "private_registries": ["https://pypi.acme.internal/simple"]},
)
result["findings"]  # dependency_confusion, CRITICAL, block
result["receipt"]   # checked, lookups, cache_hits, skipped reasons, complete
```

`api.API_VERSION` is `1`. `evaluate_packages` never raises on malformed input;
it skips bad entries and counts them in the receipt. Network checks (release
age, npm provenance) run only with `network: True` and stop at `max_lookups`.
`api.check_provenance`, `api.check_release_age`, and `api.malware_matches`
expose the single checks, and `api.feed_status` reports whether the malware feed
is ready, stale, missing, or tampered, and when its OSV data was built.
`api.suspicious_matches` matches exact versions against the sentinel's
suspicious-release datasets offline, and `api.refresh_feed` updates the installed
feed only when it is older than `max_age_hours` (6 by default), within a time limit,
without raising. Names matching `internal_packages`, or
hosted only on a private registry, are never sent to a public registry for the
release-age or provenance lookups.

### Dated EPSS and CISA KEV context

ca9 0.9.0 adds the optional `api.threat_context` capability. It is separate
from reachability analysis: calling it does not change confidence, severity,
remediation priority, or a policy decision. Existing `analyze(threat_intel=True)`
remains an explicit legacy scoring option. Its object adapter now uses the same
dated lookup and reports per-provider status/dates in JSON, SARIF and VEX.
Only current, validated positives qualify for its existing confidence/priority
boost; stale, missing, malformed and undated observations never qualify.
Ordinary analysis keeps threat intelligence disabled.

```python
context = api.threat_context(
    ["CVE-2021-44228", "CVE-2020-28500"],
    project_root="/path/to/repository",
    timeout=15.0,
)
# Cache-only lookup: api.threat_context(ids, network=False)
```

The result is `{"schema_version": 1, "cves": [...]}`. Each sorted, deduplicated
canonical `cve_id` has `epss` (`status`, `score`, `percentile`, `score_date`,
`retrieved_at`) and `kev` (`status`, `in_catalog`, `date_added`, `due_date`,
`catalog_date`, `retrieved_at`). Status is `current`, `stale`, or `unknown`.
Unknown values are JSON `null`; an actual EPSS zero remains `0.0`. KEV absence
is `false` only with a validated current complete catalog; unavailable or stale
absence is unknown. A cached positive remains visible as stale after an outage.

Calls accept up to 16 valid CVEs (sorted before truncation), send only CVE IDs
to FIRST's EPSS API and download CISA's public KEV catalog. Both use fixed HTTPS
hosts, certificate verification, no redirects, a shared maximum 15-second
request/read budget, a 5-second socket timeout, and response size limits (256 KiB
for EPSS, 8 MiB for KEV). No repository files or package names are sent.
Provider dates and per-record retrieval times must both be within 7 days for
`current`; future dates are rejected (future KEV remediation due dates are valid).
Cached data is refreshed after 24 hours. A failed refresh does not extend its
age and marks retained evidence stale.

The separate `risk-context-v1.json` cache lives under
`~/.cache/ca9/threat_intel/` or `CA9_CACHE_DIR`. Reads and atomic replacements
reject symlinks; files are bounded and newly created files use mode 0600.
Pass `project_root` to ignore a cache directory inside scanned source.
Undated legacy cache files are ignored, and failed refreshes never rewrite age.
An unavailable cache never prevents a network lookup or creates a negative result.
Platforms lacking safe descriptor-relative, no-follow file primitives use network
lookups without a disk cache. A bounded pair of daemon transports enforces the
caller deadline even while platform DNS resolution is blocked; a late connection
does not send an HTTP request after its deadline.

Rollout: publish ca9 0.9.0 before consumers require this capability. API version
remains `1` because this is additive. Consumers supporting earlier ca9 releases
must check `callable(getattr(api, "threat_context", None))` and represent missing
support as unknown rather than calling the legacy scoring option.

`api.review_upgrades` diffs the old and new published artifacts of each dependency
upgrade and returns the behaviours the new release adds as `block`, `warn` and
`info` deltas (`{"kind", "path", "line", "snippet", "detail"}`). The artifacts are
deleted after the review, so two opt-in options return the code a reviewer (for
example an AI second opinion on a warn) needs to read. Both are off by default, and
without them the output is unchanged:

```python
report = api.review_upgrades(
    [{"ecosystem": "npm", "name": "left-pad", "old": "1.3.0", "new": "1.3.1"}],
    options={"context_lines": 20, "identity_diff_bytes": 50_000},
)
result = report["results"][0]
result["warn"][0]["context"]       # diff hunks of that file around the delta's line
result.get("identity_diff")        # only after publisher_change or provenance_dropped
result.get("identity_diff_truncated")
report["receipt"]["context_lines"]  # 20: this engine supports the options
```

| Option | Range (default) | Adds |
|---|---|---|
| `context_lines` | 0-200 (0) | `context` on every `block` and `warn` delta in a text file: unified-diff hunks of that file between the old and new artifact within that many lines of the delta's line, `+` lines for a new file and for first releases. At most 8 KB per delta and 64 KB per result; a cut context keeps the delta line in the middle and ends with `... (truncated)`. Binary files, files over 32 MB and registry-metadata or lockfile deltas get none. |
| `identity_diff_bytes` | 0-200000 (0) | On a result with a `publisher_change` or `provenance_dropped` delta (any level): `identity_diff`, a unified diff of every changed text code file (`.js .mjs .cjs .ts .py .pth .json .sh .toml .cfg`, binaries and lockfiles skipped), smallest change first, at most that many bytes, and `identity_diff_truncated`. |

The text is the package's own. Control, bidi and other invisible characters are
removed (tabs stay), a CR, U+2028 or U+2029 inside a line is shown as `\r`,
` ` or ` `, and nothing else is changed. Values that are not integers in
range are listed in the receipt's `invalid_options` and ignored. When either option is
passed, the receipt carries `context_lines` with the value applied.

## Zero heavy dependencies

ca9's core library depends on `packaging` for PEP 440/version normalization and uses the
Python standard library for TOML parsing on Python 3.11+. On Python 3.10, `tomli` is used
for lockfile parsing. The `click` package is optional — only needed if you use the CLI.
This means you can embed ca9 in CI pipelines, security toolchains, or other Python tools
without pulling in a large dependency tree.

## Limitations

- Static analysis traces `import` statements, constant-string `importlib.import_module`/`__import__` calls, dotted module strings, and `importlib.metadata` dependency trees. Imports built from runtime values are not detected.
- Import names and dependency graphs come from the Python environment ca9 runs in. Run ca9 from the project's virtualenv for the most precise results; packages that are not installed there fall back to a curated name map and otherwise stay `INCONCLUSIVE`.
- Coverage quality directly impacts dynamic analysis. If your tests don't exercise a code path, ca9 can't detect it dynamically.
- Transitive dependency resolution requires packages to be installed. Without installed deps, ca9 falls back to direct-import-only checking.
- Runtime install enforcement covers lockfile-backed `npm ci` and `npm install`,
  direct `npm install` / `npm i` / `npm add` registry specs, and `pip install` /
  `python -m pip install` with registry specs or local requirements and
  constraints files. Lock-backed preflight requires `package-lock.json` version
  2 or 3; `npm-shrinkwrap.json` is blocked. yarn, pnpm, bun, uv, poetry, pipx,
  `npx`/`npm exec`, `npm update`, direct URLs, git specs, local paths, and
  alternate pip sources such as extra indexes and find-links are blocked or not
  mediated. When an npm lifecycle script runs a nested `npm install` under the
  gateway, the nested install sees the loopback registry and may be blocked.
- Environment stripping is defense in depth, not a sandbox. Install scripts that
  ca9 allows still run as your user and can read credential files on disk.
- The default hosted feed is published hourly (OSV malware data rebuilt every 6
  hours), and local bundles or `CA9_FEED_URL` can override it. Installed feeds only
  change when you run `ca9 feed update` or call `api.refresh_feed`. Feed availability
  still depends on GitHub hosting/network access.
- Suspicious-release entries come from a static review of popular packages' new
  releases and can be wrong; ca9's own `vet`, `protect` and `run` do not act on them
  yet.
- The feed builder ships malware data and empty releases datasets (kept so older
  clients still load the bundle). Release age comes from registry metadata
  instead, so it needs network access the first time each package is checked.
- Feed integrity is hash-verified locally, and `ca9 feed update` refuses
  insecure URLs and rollbacks. Published `latest.json` bundles carry a GitHub
  artifact attestation that `ca9 feed update --require-attestation` checks with
  `gh`; without the flag no signature is checked.
- OSV malware records with explicit affected versions are emitted per version, and
  whole-package records (no versions, or a range from `introduced: "0"` with no
  upper bound) are emitted name-only. Bounded ranges are kept verbatim in the
  `*-malware-ranges` datasets (and also as versions when OpenSSF origin metadata
  lists them); withdrawn records are skipped.
- Artifact heuristics catch common Python and npm malware patterns, but they are
  static signatures, not sandboxed dynamic malware analysis. Maintainer hijack,
  typosquatting, Sigstore/SLSA signature verification, PyPI (PEP 740) provenance,
  yanked metadata, and repository takeover signals still need richer external
  intelligence. The npm provenance check compares attestation presence across
  releases; it does not verify the attestation signatures.
- Python CVE reachability is implemented; npm support is inventory, package-policy,
  artifact, and runtime evidence, not JavaScript reachability analysis.

## Development

```bash
git clone https://github.com/duriantaco/ca9.git
cd ca9
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## License

[MPL-2.0](LICENSE)
