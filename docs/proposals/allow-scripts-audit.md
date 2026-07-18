# Proposal: install-script allowlist audit (`ca9 scripts audit`)

**Status:** v1 implemented (`ca9 scripts audit` with report and command emitters);
v1.1 allowlist writing and v1.2 integrations pending.

**Problem it solves:** npm v12 became the `latest`/GA release on July 8, 2026 and
disables dependency lifecycle scripts by default. Every project upgrading to npm v12
— and every pnpm ≥10 project before it — must now decide which install scripts to
approve. Registry packages normally expose `preinstall`/`install`/`postinstall`;
non-registry dependencies can also run `prepare` and must be audited on the same path.
npm gives teams the *mechanism* (`npm approve-scripts`, an `allowScripts` allowlist in
`package.json`) but no *evidence* for the decision. The practical result is `npm
approve-scripts --all`, which recreates the pre-v12 exposure with an official-looking
allowlist around it.

ca9 already has evidence that makes the decision safer: lockfile inventory with
`hasInstallScript` flags, SRI-verified tarball fetch and safe unpacking, npm
lifecycle-script static heuristics, and feed/OSV malware lookups — all local, no
execution, no code upload.

**Goal:** one command that audits every script-bearing package-lock occurrence and emits
an evidence-backed verdict per occurrence (`deny` / `review` / `allow-candidate`), plus
a conservative generator for the corresponding `npm approve-scripts` / `npm
deny-scripts` commands. Occurrences with the same name and version at different lock
paths remain separate evidence units. ca9 never edits the allowlist, runs a generated
command, or executes package code; the human reviews and applies the output.

---

## 1. The upstream mechanics we target (verified against npm docs/discussions)

- `allowScripts` (in `package.json`) is the allowlist. The command argument to `npm
  approve-scripts <name>` matches every installed occurrence of that package name, so
  an occurrence verdict cannot safely be emitted as an independent approval. ca9 uses
  `--allow-scripts-pin` on an approval command so npm records the audited version.
- `npm approve-scripts --allow-scripts-pending` — read-only list of packages whose
  scripts are not yet covered. `--all` approves everything pending (the dangerous path
  this feature competes with). `npm deny-scripts <pkg>` records an explicit deny that
  survives `--all`.
- Unapproved scripts are **skipped with a warning; the install still succeeds** — so
  breakage from a needed-but-blocked build script surfaces later, not at install time.
- `ignore-scripts=true` takes precedence over the allowlist entirely.
- npm 11.x can opt in early via `strict-allow-scripts`; `--allow-git` / `--allow-remote`
  default to `none` in v12 (separate finding surface, out of scope here).
- pnpm ≥10 has the same model with different spelling (`pnpm approve-builds`,
  `onlyBuiltDependencies`) — a second emitter target, not a second analyzer.

The exact JSON shape of `allowScripts` remains outside this feature. The stable output is
`npm approve-scripts`/`npm deny-scripts` command lines, which are a documented CLI
surface; v1 does not write `package.json`.

## 2. What already exists (do not rebuild)

- `readers/package_lock.py` preserves each lock occurrence (`lock_path` and
  `lock_occurrence_id`), `hasInstallScript`, installed names, requested specifiers,
  resolved URLs, SRI integrity, and direct/transitive kind for lock v2/v3. Requested
  specifiers distinguish registry dependencies from git/file/remote/workspace sources.
- `artifacts/fetch.py` + `artifacts/unpack.py` download and safely unpack npm tarballs
  with SRI verification, no code execution.
- `analyzers/package_code.py` already classifies npm manifests and scripts:
  `_analyze_npm_manifest` (lifecycle-hook presence, suspicious hook commands) and
  `_analyze_npm_script` (encoded execution, credential exfiltration). These rules were
  built for `vet --scan-artifacts` and apply unchanged.
- `package_feed.lookup_malware()` and the `vet --malware-query` OSV path classify known
  malicious name@version pairs.
- `runtime/shell.py` shows the house pattern for backup-then-edit file mutation.

So this proposal is **an orchestrator, a classifier tier, and two emitters** — not a
new package-code execution engine.

## 3. Design

### Pipeline

1. **Validate and enumerate occurrences** from an npm v2/v3 `package-lock.json`.
   Missing, unreadable, malformed, unsupported, or structurally invalid lockfiles are
   command errors. A script-bearing entry or link that cannot be materialized as an
   auditable occurrence is also a hard error; it is never silently dropped.
2. **Establish source and identity.** Requested dependency specifiers determine whether
   an occurrence is registry, git, file, remote, or workspace sourced. Registry-policy
   and command identity come from trusted lock source evidence (including the resolved
   registry tarball identity/version), never from package-controlled manifest fields.
   Local workspace sources are excluded. External or out-of-root file targets remain
   visible but cannot be trusted as approval evidence, so they stay `review`.
3. **Resolve hook text** per occurrence, in order:
   a. its exact lock-path `node_modules/.../package.json` when the installed name and
      version match (fast and useful offline, but not sufficient approval evidence);
   b. when online, enforce registry policy before any request, then fetch and safely
      unpack the locked tarball (respecting the positive `--max-artifact-mb` limit and
      requiring integrity by default);
   c. otherwise report `review` with reason `scripts-unavailable`.
   A matching local manifest supplies text only. Online mode still scans the locked
   artifact, and disagreement between installed and artifact hook text is reported.
4. **Select hooks** using the npm execution model: audit `preinstall`, `install`, and
   `postinstall`, plus `prepare` for git/file/remote/other non-registry dependencies.
5. **Classify** each occurrence with layered evidence:
   - feed malware, an explicitly denied registry, or a blocking `package_code` finding
     (encoded execution, credential exfiltration, or a suspicious hook) ⇒ `deny`;
   - feed failure under fail-closed policy globally suppresses approvals and exits `1`;
     a custom registry requiring approval is not fetched and remains `review`;
   - warn-level findings, missing/unverified artifact analysis, helper hooks, or script
     text that matches no recognized whole-command shape ⇒ `review`;
   - recognized native-build shapes remain `review` even with clean analysis of a
     hash-verified artifact. The artifact does not prove which lifecycle-PATH executable
     will run, and the presence or apparent safety of `binding.gyp`/GYP inputs does not
     establish end-to-end executable and build provenance.
6. **Verify the installed tree and emit by trusted npm identity.** Every locked
   occurrence of a name must match the installed path/name/version set exactly before a
   command can be emitted. A deny in any occurrence wins; otherwise any reviewed
   occurrence suppresses approval. Missing trusted identity or version evidence also
   suppresses commands. Any future approval command uses
   `npm approve-scripts <name> --allow-scripts-pin`.

### Recognized build-command shapes (small and versioned)

A short curated list of script shapes identifies common native/binary builds, e.g.
`node-gyp rebuild`, `prebuild-install || node-gyp rebuild`, `node-pre-gyp install`, and
`node-gyp-build`. Rules match the whole command: control characters or a newline produce
`deny`, and one appended `&& curl` breaks the match. Clean analysis of the hash-verified
locked artifact is required even to recognize native-build evidence, but it is not
sufficient to approve: executable resolution and build/GYP provenance are not yet
modeled end to end. Native shapes, and convenience hooks that are usually safe to skip
such as `husky` and `patch-package`, therefore remain `review`.

The v1 schema and emitter retain the `allow-candidate` state for future evidence tiers,
but the currently accepted command shapes do not provide a reachable automatic
approval path. v1 is deliberately useful for denial and structured human review rather
than promising that verification alone will generate approvals.

### CLI surface

```bash
ca9 scripts audit [DIRECTORY] [--policy ca9.toml] [-f table|json]
ca9 scripts audit --repo DIRECTORY --offline
ca9 scripts audit --emit commands   # conservative npm approve/deny command lines
```

Both the positional path and `--repo` accept directories only. `--max-artifact-mb` must
be positive. Lockfile and policy errors are ordinary CLI errors rather than tracebacks.

```
-r, --repo DIRECTORY            Project directory (alternative to DIRECTORY)
-f, --format [table|json]       Report format  [default: table]
--emit [report|commands]        Report or guarded npm command lines  [default: report]
-o, --output PATH               Write output to a file instead of stdout
--policy PATH                   Package, registry, and malware policy TOML
--allow-unhashed-downloads      Fetch an artifact without lock integrity for review
--max-artifact-mb N             Positive artifact download limit  [default: 100]
--offline                       Do not download artifacts
```

`--emit commands` produces comment-and-command text and is incompatible with JSON
format (`--format json`). The generated `#` comments are valid in POSIX shells and
PowerShell. The output
states the audited repository and must be reviewed and run from that repository.

`--emit commands` groups entries by package name because npm applies a named command to
all installed occurrences of that name. It prints `npm deny-scripts <name>` only when a
denied group has trusted identity/version evidence and the installed tree exactly
matches every audited occurrence. A review, missing trusted identity/version, or an
installed-tree mismatch produces a comment and no command. The future approval path
additionally requires every occurrence to be an `allow-candidate` and emits `npm
approve-scripts <name> --allow-scripts-pin`; the current v1 classifier does not promise
to reach that state. Exit codes follow house convention: `1` when a `deny` or global
blocker exists, `2` when review findings remain, and `0` when neither is present.

Example report row:

```
verdict          package                script      command                          evidence
deny             evil-pkg@1.0.3         postinstall "node -e eval(atob('...'))"      npm-encoded-exec, feed:MAL-2026-...
review           left-pad-tools@2.1.0   install     "./configure.sh"                 no-benign-match
review           sharp@0.33.4           install     "prebuild-install || node-gyp…"  executable-provenance-unverified
```

## 4. Staged rollout

### v1 — audit + commands emitter (the useful core)

- [x] `scripts_audit.py` orchestrator (mirrors `supply_chain.py` report shape).
- [x] Whole-command recognition and deny/review classifier tier in
      `analyzers/install_scripts.py` (`package_code.py` rules imported, not duplicated).
- [x] `ca9 scripts audit` with table/json + `--emit commands`; JSON output records
      occurrence paths and rule IDs so decisions are auditable.
- [x] Fixtures: strict/unmaterializable lockfile handling, repeated occurrences,
      non-registry `prepare`, workspace exclusion, external file review, exact installed
      trees, malware-feed failure/hit, trusted registry identity, verified tarballs, and
      native-build command variants.

### v1.1 — allowlist emitter + write mode

- [ ] Model executable and build/GYP provenance strongly enough to define a reachable
      automatic-approval evidence tier.
- [ ] Verify `allowScripts` JSON shape against `npm/cli`; add `--emit allowlist` and
      `--write` (backup-then-edit, only touches the `allowScripts` key, and refuses on
      `deny`/`review`-only trees).
- [ ] pnpm emitter (`onlyBuiltDependencies` / `pnpm approve-builds`) once field names are
      verified — same audit, second spelling.

### v1.2 — integration

- [ ] `ca9 run` preflight: read npm major version + `allowScripts`/`ignore-scripts` to
      refine `install_scripts_possible` instead of the current `--ignore-scripts`-only
      check (`runtime/preflight.py:304`).
- [ ] `ca9 vet` posture finding: script-capable deps present but no
      `allowScripts`/`ignore-scripts`/pnpm equivalent configured on a pre-v12 toolchain
      (bridges to the separate defense-posture proposal).

## 5. Code changes summary

| File | Change | Stage |
|---|---|---|
| `src/ca9/scripts_audit.py` | new orchestrator: enumerate → resolve → classify → report | v1 |
| `src/ca9/analyzers/install_scripts.py` | recognized command shapes + deny/review tiering over `package_code` findings | v1 |
| `src/ca9/cli.py` | `scripts` group, `audit` command, emitters, exit codes | v1 |
| `src/ca9/artifacts/*` | none expected (reuse fetch/unpack as-is) | v1 |
| `src/ca9/runtime/preflight.py` | npm-v12-aware `install_scripts_possible` | v1.2 |
| docs / README | quick start: "migrating to npm v12 with evidence" | v1 |

## 6. Risks / open questions

- **`allowScripts` exact shape** is unverified; that is why file-writing is v1.1 and the
  v1 emitter targets the documented command surface instead.
- **False `allow-candidate`** is the costly failure. v1 keeps all recognized native and
  helper command shapes at `review`; whole-command matching, control-character denial,
  malware/heuristic checks, and hash-verified artifact analysis still improve the review
  evidence without claiming executable or GYP provenance.
- **Package-name command scope:** npm selects all installed occurrences matching the
  name. The audit keeps occurrence evidence separate, then the emitter treats a trusted
  name as one safety unit. Any reviewed occurrence suppresses approval, and any denied
  occurrence makes the group a denial candidate.
- **Command identity and tree drift:** manifest `name`/`version` fields are untrusted for
  command generation. The emitter requires trusted lock-source identity and version plus
  an exact locked-to-installed occurrence match. It emits a sanitized comment instead
  of a command when either check is incomplete.
- **Private/scoped registries:** tarball fallback enforces the package policy before
  fetching. Explicit denial blocks; registries requiring approval remain `review`;
  unreachable or unverifiable artifacts also degrade to `review`, never a guess.
- **Installed trees:** `node_modules` is useful for discovering hook text, but it must
  not weaken the result. Approval still requires the corresponding verified locked
  artifact and equivalent static package-code analysis.
- **Workspaces / local sources:** lock v3 workspaces are project code and are excluded
  from dependency approval verdicts. External or out-of-root file targets are not
  silently excluded, but remain `review` because ca9 cannot establish their contents as
  trusted in-root lock artifacts.
- **Windows script variants** (`node-gyp.cmd`, shell differences) need fixture coverage
  before the benign patterns are trusted.
