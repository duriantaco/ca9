---
title: Supply-Chain Vetting
description: Use ca9 inventory and ca9 vet to inspect Python/npm package inventory, lockfile evidence, malicious package behavior, dependency confusion, artifact integrity, and license policy.
---

# Supply-Chain Vetting

`ca9 vet` is the broader package-security command. It builds on normalized inventory and
checks dependency risk beyond CVE reachability.

The current implementation is intentionally local-first:

- fyn is optional; ca9 reads `fyn.lock` natively when present.
- npm projects can be inventoried from `package-lock.json`.
- package code is never installed, imported, or executed.
- artifact downloads are explicit and hash-verified by default.
- installed package-intelligence feeds are used locally for malware and package-age policy.
- OSV malware advisory queries are opt-in.
- Real incident replay fixtures track current coverage and gaps.

## Incident Replay

Replay recent real incidents against ca9's current supported surfaces:

```bash
python scripts/incident_replay.py --strict --format table
```

The fixtures live in `tests/fixtures/incidents/` and currently cover May 2026 npm package
compromise, PyPI import-time malware, and GitHub token/codebase exfiltration patterns. See
`docs/proof/incident-coverage.md` for the current matrix.

## Demo Fixture

For a screenshot-ready report, run the local supply-chain fixture:

```bash
bash demo/supply_chain/run_demo.sh
```

The fixture generates a `fyn.lock` with local hash-pinned wheels and shows three blocking
findings: dependency confusion, suspicious `.pth` startup execution, and a denied license.
It also writes `demo/supply_chain/ca9-vet.json` for docs or CI artifact screenshots.

```text
ca9 supply-chain report for .../demo/supply_chain/repo
Packages: 4 | Edges: 3 | Findings: 3 | Block: 3 | Warn: 0
Artifact scans: 3 | Skipped artifacts: 0
```

## Inventory

Inspect the normalized package inventory:

```bash
ca9 inventory --repo . -f json
```

When a repository has `fyn.lock` or npm `package-lock.json`, inventory includes:

- resolved package names and versions
- direct/transitive/project dependency kind
- dependency edges
- groups, markers, extras, and npm dependency classes where available
- artifact URLs, hashes/integrity values, upload times, sizes, and registries
- source evidence for each package and edge

Without lockfiles, ca9 falls back to native Python manifest readers for `pyproject.toml`,
`requirements*.txt`, `Pipfile`, `uv.lock`, and `poetry.lock`.

## Basic Vetting

Run local metadata checks:

```bash
ca9 vet --repo .
```

This checks:

- untrusted package indexes
- missing artifact hashes
- missing artifact metadata
- source-only install risk
- mutable package sources
- malware entries from the installed `ca9.feed.v1` feed
- package-age policy when enabled in `ca9.toml`

Direct dependencies from untrusted indexes, feed-backed malware matches, and
too-new package versions are blocking findings by default. Missing package-age
release times warn by default and block when `[mode].offline` is `block` or
`strict`. Weaker local metadata signals are warnings unless policy support is
expanded.

## Artifact Static Analysis

Run artifact-based malicious package heuristics:

```bash
ca9 vet --repo . --scan-artifacts
```

By default, ca9 only downloads artifacts that have hashes in the inventory. It verifies the
hash, safely unpacks Python wheels/sdists and npm tarballs, rejects path traversal or
unsafe archive links, and scans files statically.

Lockfile URLs are untrusted input. ca9 fetches only `https` URLs on public registries or
on `--trusted-index` / `--private-index` hosts, checks every redirect the same way, and
refuses hosts that resolve to loopback, private, or link-local addresses unless they are a
configured `--private-index`. Local artifact paths are read only inside `--repo` or a
`--local-artifact-root` directory. Archives are unpacked only in the format their type
implies (npm tarballs and sdists as tar, wheels as zip); bytes that parse as both are
blocked. Entry counts, total size, and expansion ratio are capped, and downloads are
verified before they are cached.

Current blocking rules include:

- `.pth` startup lines that execute suspicious code (decoded payloads, process or network
  calls, credential reads); benign setuptools, editable-install, and virtualenv `.pth`
  files produce no finding, and other import lines are marked for investigation
- `sitecustomize.py` / `usercustomize.py` suspicious startup behavior
- install-time `setup.py` process/network/eval/exec behavior
- encoded payload decode plus execution, in either order and at any nesting level
  (Python files are analyzed with the AST, resolving import aliases and simple string
  building)
- credential harvesting (dumping the environment or reading credential files) near
  outbound network code
- top-level import-time risky behavior
- npm install lifecycle hooks
- npm install hooks that shell out, fetch, decode, or eval
- npm encoded payload execution, including base64 and hex decoding, `new Function`, and
  dynamically built `require('child_' + 'process')`
- npm credential harvesting near network or process execution

Suspicious process execution outside setup/import startup paths is marked for
investigation, as are install hooks that run a bundled downloader or runtime installer,
native `.node`/`.so`/`.dll` binaries in npm packages, and files too large to inspect fully
(the first and last 1 MiB are still scanned). `sha1`/`md5`-only integrity is reported as
weak evidence rather than a mismatch.

Use this only if you want ca9 to download package artifacts:

```bash
ca9 vet --repo . --scan-artifacts --max-artifact-mb 100
```

Artifacts without hashes are skipped unless you explicitly opt in:

```bash
ca9 vet --repo . --scan-artifacts --allow-unhashed-downloads
```

## Package Feeds and Package Age

Install a package-intelligence feed before relying on deterministic offline malware or
package-age decisions:

```bash
ca9 feed update
ca9 feed update --require-attestation
ca9 feed update --from ./ca9-feed.json
ca9 feed status
```

`ca9 feed update` with no `--from` uses `CA9_FEED_URL` when set, otherwise the built-in
default feed URL on the project's published `feed` branch. Use `--from` or
`CA9_FEED_URL` to select a local or alternate hosted bundle.

`--require-attestation` checks the downloaded bundle with
`gh attestation verify <file> --repo duriantaco/ca9 --cert-identity
https://github.com/duriantaco/ca9/.github/workflows/feed.yml@refs/heads/main
--source-ref refs/heads/main --deny-self-hosted-runners` before installing it. Only a
bundle signed by `feed.yml` running from `main` on a GitHub-hosted runner passes; the
same workflow dispatched from another branch does not. The exact bytes that were
verified are the bytes installed. The update fails, and nothing is installed, when
`gh` is missing, verification fails, or the source is a snapshot directory rather than
a single bundle file. `gh` needs a GitHub token (`GH_TOKEN` in CI). Without the flag the
update behaves as before.

Feed bundles use schema `ca9.feed.v1` and always contain `npm-malware`, `pypi-malware`,
`npm-releases`, and `pypi-releases`. Newer bundles add the optional
`npm-malware-ranges` and `pypi-malware-ranges` datasets, and the optional
`npm-suspicious` and `pypi-suspicious` datasets described below. Feed snapshots are stored under
`~/.cache/ca9/feed/` and verified with SHA-256 content hashes before use. Tampered feeds
always block.

Malware entries come from OSV records with a `MAL-` id or alias, explicit
malicious-package metadata, or CWE-506 "Embedded Malicious Code" (GitHub advisories such
as `GHSA-33qr-m49q-rxfx` for `xrpl`). Withdrawn records are skipped. A record that lists
versions becomes one entry per version, and a record that covers the whole package
(no versions, or a range from `introduced: "0"` with no upper bound) matches every
version. A record that only gives bounded ranges (for example `@solana/web3.js`
`introduced: 1.95.6`, `fixed: 1.95.8`) is kept with its OSV events unchanged in the
`*-malware-ranges` dataset. ca9 matches those ranges with npm semver ordering
(prereleases sort before their release, build metadata is ignored, a leading `v` is
accepted) or PEP 440 ordering for PyPI. A version outside every range never matches,
and a range is never widened into a whole-package entry. Clients older than this
change ignore the range datasets and keep working; run `ca9 feed update` after
upgrading so the installed snapshot includes them.

Enable package-age policy in `ca9.toml`:

```toml
[package_age]
enabled = true
minimum_hours = 48
```

Release times come from the feed's releases dataset when it has them, and otherwise
from registry metadata: the npm packument `time` map (from the registry npm uses, when
policy trusts it, else `registry.npmjs.org`) or PyPI's JSON API. A PyPI release can gain
files long after its first upload, so its time is the newest upload among its
non-yanked files: a wheel added today to a 2020 release makes that release new again.
ca9 caches release times under `~/.cache/ca9/release-times/` (bounded in size, written
atomically, never through symlinks, and never caching a failed lookup). npm times never
change and are reused; a cached PyPI time is re-checked after 10 minutes. The hosted
feed still ships empty releases datasets for older clients; an empty dataset without
`covers_since` no longer settles anything by itself. A minimum age that is missing,
negative, or not a number makes the result unknown rather than "old enough".

If a release time is younger than `minimum_hours`, ca9 blocks and names the newest
stable version published before the window (not a prerelease, yanked, unpublished or
deprecated version; versions below the requested one are preferred). If a release
dataset declares `covers_since`, a missing version can pass when it is provably older
than the configured minimum. If neither the feed nor the registry knows the release
time, it is unknown; the default offline mode warns, and `[mode].offline = "block"`
blocks. `ca9 vet --offline` only uses cached release times.

`ca9 run` holds versions published less than 24 hours ago even without a
`[package_age]` table, naming an older version to use instead. Turn it off from a
trusted policy (`--policy`, `CA9_POLICY`, or `~/.config/ca9/policy.toml`) with
`package_age.enabled = false` or `package_age.minimum_hours = 0`; a trusted policy can
also lower `minimum_hours` or add `exclusions`. A repository `ca9.toml` that ca9 only
discovers in the working directory is merged against the 24-hour hold: it can raise
`minimum_hours`, but `enabled = false`, a lower `minimum_hours`, and new `exclusions`
are ignored with a warning naming the setting. `vet` and `protect` keep package age
opt-in.

Known limit of the default hold: when ca9 cannot read a version's release time, the
24-hour default warns and lets the install continue; only an explicit
`[package_age]` policy turns that into a block (with `[mode].offline = "block"`).
This covers a registry or network outage, a version the registry does not list, a
publish time that does not parse, an npm packument larger than 64 MiB (ca9 stops
reading registry metadata at that size), and a private registry that needs
credentials ca9 does not send.

### How often the hosted feed changes

`.github/workflows/feed.yml` publishes a new `latest.json` to the `feed` branch every
hour.

- The OSV malware data (`*-malware`, `*-malware-ranges`, `*-releases`) is rebuilt from
  OSV every 6 hours. In the hours between, those datasets are copied unchanged from the
  previously published bundle. If that bundle cannot be read, they are rebuilt that hour.
- The bundle records `osv_built_at`, the time the OSV data was built. `ca9 feed status`
  prints it as `OSV data built`, and `api.feed_status()` returns it. The bundle expires
  7 days after `osv_built_at`, so copying the data forward never makes old OSV data look
  current for longer.
- The suspicious-release datasets below are refreshed every hour.
- Maintainers can change the rebuild interval with the workflow input `osv_rebuild_hours`
  (manual runs) or the repository variable `CA9_OSV_REBUILD_HOURS`; `0` rebuilds every
  hour.
- Nothing changes on your machine until you update: run `ca9 feed update`, or call
  `api.refresh_feed()`, which downloads only when the installed feed is older than
  `max_age_hours` (6 by default).

### Suspicious new releases (sentinel)

Every hour, `scripts/sentinel.py` checks new releases of the most downloaded npm and PyPI
packages (the first 5,000 names of `sentinel/watch-npm.json` and
`sentinel/watch-pypi.json`). It compares each new version with the release before it,
using ca9's upgrade review: a static diff of the two published files. Package code is
downloaded and read, never installed or run. Versions that look malicious go into two
optional datasets, `npm-suspicious` and `pypi-suspicious`, often before anyone has
reported them to OSV.

What makes an entry:

- `block`: the new version adds code that runs at install, import or interpreter start: a
  `.pth` file with code, `sitecustomize`, an install script or build hook, code that
  decodes and runs data, a git or URL dependency, an agent or editor hook file, or a
  command named like a system tool (`node`, `npm`, `git`, `python`).
- `warn`: other review findings that are more often packaging accidents (ambiguous
  archive contents, imported bytecode without source), and two combinations: a publisher
  change together with new import-time network, process or obfuscated code; or obfuscated
  code together with new import-time network or process code.
- A single warning on its own never makes an entry, and prereleases are not reviewed.

Each entry lists `name`, `version`, `previous` (the version it was compared with),
`kinds`, `verdict`, a few short `evidence` lines, `reviewed_at` and `published_at`.
Entries are kept for 30 days. They are the sentinel's own judgment from a static review,
not confirmed malware reports, so they can be wrong.

`api.suspicious_matches(packages)` matches exact versions against these datasets
offline and returns findings with signal type `suspicious_release` and action `block` or
`warn`. Skylos can call it. ca9's own `vet`, `protect` and `run` commands do not act on these
datasets yet, and older ca9 versions ignore them.

Each dataset also carries the sentinel's state and a `coverage` record of the last run:
packages watched and checked, new versions seen, reviewed, incomplete, flagged and
deferred. The build log prints the same numbers, so a partial run is visible.

#### Reporting a false positive

Reviewed false positives are listed in `sentinel/allow.json`. An allowlisted version is
never published, and one that is already published drops out at the next hourly run.

1. Open an issue or pull request naming the package, the version and the `kinds` it was
   flagged for.
2. A maintainer reads the flagged change (the `evidence` lines name the files and lines)
   and decides whether it is benign.
3. If it is, the pull request adds an entry to `entries`:

```json
{
  "ecosystem": "npm",
  "name": "example-pkg",
  "version": "2.3.1",
  "kinds": ["new_install_hook"],
  "reason": "postinstall downloads the package's own prebuilt binary from its GitHub releases",
  "reviewed_by": "maintainer-github-handle"
}
```

Every entry needs `ecosystem` (`npm` or `pypi`), `name`, an exact `version` or `"*"`, a
`reason`, and `reviewed_by`; an entry without them fails the feed build, so nothing is
published until it is fixed. `kinds` is optional and limits the entry to those kinds. Use
`"*"` only when every future version will legitimately do the same thing, and always give
`kinds` with it, so a later release that adds something different is still flagged.

## Malicious Advisory Query

Query OSV for known malicious-package advisories:

```bash
ca9 vet --repo . --malware-query
```

ca9 treats OSV `MAL-*`, `PYSEC-MAL-*`, explicit malicious-package metadata, and
malware-labeled GHSA/OSV advisories as blocking malware findings for PyPI and npm. This
is separate from the installed local feed: the feed path is deterministic and local,
while `--malware-query` asks OSV or uses the OSV cache. Use `--offline` to restrict the
query path to cached OSV data.

## Npm Publisher Change Review

Query the public npm registry for recent changes in publishers after a dormant
release period:

```bash
ca9 vet --repo . --scan-publisher-changes
```

This optional check covers direct npm dependencies pinned in `package-lock.json`
and resolved from `https://registry.npmjs.org`. It reads full package metadata
and warns when a stable release in the past 365 days followed a gap of at least
180 days and came from a publisher not seen in earlier releases. The locked
version must be from that publisher and no older than the handover. Releases
with npm's verified trusted-publisher identity and publishers with another
package receiving at least 100,000 weekly downloads are excluded. If the
publisher lookup is unavailable, ca9 keeps the finding and adds a report
warning. Metadata fetch failures also appear in report warnings. This signal calls
for human review; it does not establish malicious behavior. The check can
download large registry documents, so it is opt-in and cannot run with
`--offline`.

Some old npm releases have timestamps but no publisher identity. ca9 reports
that incomplete history and can still warn when the publisher immediately
before the handover is known. In that case, the new publisher is the first
*observed* publisher in the available metadata, not necessarily the first ever.

## GitHub Actions Workflow Scanning

Scan workflow files for risky token and trust-boundary patterns:

```bash
ca9 vet --repo . --scan-workflows
```

The workflow scanner reads `.github/workflows/*`, composite actions under
`.github/actions/`, and a root `action.yml`. It recognizes triggers in every YAML form
(`on: pull_request_target`, `on: [push, pull_request_target]`, and mappings), ignores
YAML comments, and flags:

- `pull_request_target`, `workflow_run`, and `issue_comment` workflows that check out
  pull request-controlled code, including `github.head_ref`, PR head refs/SHAs, and
  `gh pr checkout`
- template injection: untrusted `${{ github.event.* }}` fields (titles, bodies, branch
  names, commit messages) or `${{ github.head_ref }}` interpolated into `run:` scripts
- `workflow_run` workflows that consume artifacts from the triggering run
- broad write-capable `GITHUB_TOKEN` permissions
- `id-token: write` OIDC token minting
- mutable action references such as `@main`, and third-party actions not pinned to a full
  commit SHA (`actions/*` and `github/*` tags are not flagged)
- cache use across `pull_request_target` trust boundaries
- source-clone commands such as `gh repo clone`
- encoded shell payloads such as `base64 -d | bash`
- cloud metadata, OIDC request token, and broad credential-file harvest patterns

High-risk combinations such as pull request-code checkout, template injection under an
untrusted trigger, workflow-wide write permissions, and source-clone commands with
write-capable token scope are blocking by default. Encoded shell execution, cloud
metadata probing, and broad local credential-file access are also blocking because they
match common CI/CD credential-stealing behavior. Job-scoped write permissions and OIDC
write scope without an untrusted trigger are lower-severity warnings.

## Policy Trust

ca9 merges built-in defaults, the user policy (`~/.config/ca9/policy.toml`), and
`CA9_POLICY`, and trusts all of them, as well as any file passed with `--policy`. A
`ca9.toml` discovered in the working directory is repository content and may only tighten
that policy: settings that would relax it (a lower mode, a disabled check, a wider
`registries.allow`, a lower `package_age.minimum_hours`, new exceptions) are ignored with a
warning naming the key. Trust a repository policy explicitly with `--policy ca9.toml` or
`CA9_POLICY=ca9.toml`. `ca9 policy explain` lists ignored settings, and `ca9 run` records
them in the audit log.

## Dependency Confusion

Protect internal package names from resolving from public or unexpected indexes:

```bash
ca9 vet --repo . \
  --internal-package 'acme-*' \
  --private-index https://packages.acme.internal/simple
```

An internal direct dependency that resolves outside the configured private indexes is a
blocking dependency-confusion finding. Transitive matches are marked for investigation.

Use `--trusted-index` to define package indexes that are generally trusted:

```bash
ca9 vet --repo . \
  --trusted-index https://pypi.org/simple \
  --trusted-index https://packages.acme.internal/simple
```

## License Policy

Gate denied licenses from wheel/sdist metadata:

```bash
ca9 vet --repo . \
  --deny-license AGPL-3.0 \
  --deny-license GPL-3.0
```

ca9 reads:

- wheel `.dist-info/METADATA`
- sdist `PKG-INFO`
- `License-Expression`
- `License`
- `Classifier: License :: ...`

Denied licenses on direct dependencies are blocking findings. Denied licenses on transitive
dependencies are investigation findings until richer policy configuration lands.

Warn when scanned artifacts do not declare a known license:

```bash
ca9 vet --repo . --require-known-license
```

License checks require artifact metadata, so `--deny-license` and `--require-known-license`
implicitly enable artifact collection. The same safe artifact rules apply: hashes are
required by default, archives are safely unpacked, and package code is not executed.

## JSON Output

```bash
ca9 vet --repo . --scan-artifacts -f json -o ca9-vet.json
```

The JSON schema includes:

- inventory summary
- findings with signal type, severity, package key, evidence, and metadata
- decisions with action, policy ID, and reason
- artifact scan counts and skipped artifact counts

Example signal types:

- `untrusted_registry`
- `dependency_confusion`
- `malware`
- `new_package_version`
- `package_age_unknown`
- `github_actions_pull_request_target_checkout`
- `github_actions_oidc_write`
- `github_actions_write_permissions`
- `python-startup-pth-exec`
- `python-startup-customize-exec`
- `setup-install-exec`
- `encoded-execution`
- `credential-network-exfiltration`
- `import-time-risky-behavior`
- `silent-process-execution`
- `npm-install-script`
- `npm-install-script-exec`
- `npm-encoded-execution`
- `npm-credential-exfiltration`
- `denied_license`
- `unknown_license`

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No blocking supply-chain findings. |
| `1` | Blocking supply-chain findings were found. |

Warnings and investigation findings remain visible in output but do not currently fail the
default gate unless they are represented as blocking decisions.

## Current Limits

ca9 does not yet implement every dependency attack class. The current `vet` path covers
the core local gates first: feed-backed malware, optional OSV/GHSA malware advisory
matching, package-age policy, dependency confusion/internal source policy, artifact
integrity basics, Python/npm artifact heuristics, GitHub Actions workflow risk patterns,
and license policy.

Still planned:

- typosquatting and namespace confusion
- lockfile poisoning diffs
- hosted complete recent-release datasets for package-age feeds
- maintainer or repository hijack signals
- provenance/Sigstore/SLSA checks
- yarn, pnpm, uv, poetry, pipx, npx, requirements-file, direct URL, local path, and
  alternate pip-source runtime mediation
