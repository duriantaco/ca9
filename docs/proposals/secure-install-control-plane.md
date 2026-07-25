# Proposal: a secure-install control plane

**Status:** P0 implemented on July 25, 2026; follow-on manager and provenance
work remains staged.

**Problem it solves:** ca9 has strong individual capabilities—lockfile inventory,
malware and package-age policy, registry mediation, install-script analysis, and
runtime secret shielding—but teams still have to assemble those capabilities
themselves. Two common workflows also fall through the prevention layer:
Python installs that use `requirements.txt`/constraints files, and temporary policy
waivers that need an owner and an expiry date.

**Goal:** make the safe path the easy path. A repository should be able to run one
read-only posture command, understand whether its dependency-install workflows are
actually protected, and then enforce supported npm and pip installs with the same
policy. Necessary exceptions must be narrow, time-bounded, and visible in evidence.

## User pain points

1. `ca9 run -- pip install -r requirements.txt` is currently rejected even though
   requirements files are the normal Python deployment interface.
2. `ca9 vet`, runtime preflight, feed state, and workflow checks are separate
   commands. A team adopting ca9 has no single answer to “are installs in this
   repository protected?”
3. Policy is all-or-nothing. A team with one accepted package exception must weaken a
   whole rule or maintain an out-of-band waiver that ca9 cannot audit.
4. The GitHub Action exposes only part of the local product surface, so adoption
   requires custom workflow scripting.

## P0 scope

### 1. Lock-backed pip requirement installs

`ca9 run` accepts local `-r` / `--requirement` and `-c` / `--constraint` files.

- Includes resolve relative to the containing file and must stay inside the
  repository root.
- Nested includes are supported with cycle and depth protection.
- Exact pins and hashes are preserved as evidence.
- Constraints refine direct requirements; a constraint-only entry is not treated as
  an installed package.
- Remote requirements, editable/direct URL dependencies, extra indexes, find-links,
  and out-of-root files remain blocked.
- Dependency and file arguments are preserved. When the PyPI gateway is active,
  ca9 removes top-level upstream index options and appends the loopback index as
  the final option so an index inside a requirements file cannot outrank it.

Acceptance:

- A malware-listed package in a requirements file is blocked before pip starts.
- Direct and nested requirements, constraints, hashes, comments, and continuations
  have fixtures.
- Unsupported or escaping input fails closed with a useful error.

### 2. Scoped, expiring policy exceptions

Add top-level `[[exceptions]]` entries to `ca9.toml`:

```toml
[[exceptions]]
policy_id = "ca9.package_age"
ecosystem = "pypi"
package = "example-package"
version = "1.2.*"
action = "warn"
owner = "platform-security"
reason = "Validated emergency release"
expires = "2026-08-01"
```

Rules:

- `policy_id`, `owner`, `reason`, and `expires` are required.
- Package, ecosystem, and version selectors are optional; omitted selectors broaden
  only that exception, never another policy.
- Expired entries do not match.
- Every applied exception is attached to the decision evidence.
- Known-malware decisions are never overridable.
- Later policy files replace the exception array under the existing merge model.

Acceptance:

- Validation rejects malformed, ownerless, reasonless, or invalid-date entries.
- Matching uses normalized package identities.
- `vet` and runtime package decisions expose applied waiver evidence.
- Expired and unrelated exceptions leave the original action unchanged.

### 3. `ca9 protect`

Add a local, non-mutating repository posture command:

```bash
ca9 protect --repo . --policy ca9.toml --format table
ca9 protect --repo . --format json --output ca9-protect.json
```

The v1 report combines:

- detected package-manager and lockfile workflows;
- whether ca9 runtime enforcement can parse each workflow;
- local feed readiness;
- current inventory, package-policy findings, and decisions;
- optional local GitHub Actions workflow checks;
- concrete remediation for unprotected or ambiguous workflows.

The stable JSON schema is `ca9.protect.v1`. Exit `1` means at least one blocking
posture or policy decision; warnings do not fail the command. The command performs no
network requests or repository mutations by default.

Acceptance:

- npm lockfile and pip requirements repositories report as supported.
- missing locks and detected-but-unsupported managers are explicit, actionable
  checks rather than silently ignored.
- JSON output is deterministic enough for CI fixtures.
- table and Markdown output lead with the overall posture and next actions.

### 4. First-class CI surface

The GitHub Action accepts `command: protect`, passes the repository and optional
policy, and can upload its SARIF output using the same guarded upload path as existing
commands.

## Delivery sequence

1. [x] Land this proposal and executable acceptance criteria.
2. [x] Extend the pip preflight parser and focused runtime tests.
3. [x] Add exception schema, matching, decision evidence, and tests.
4. [x] Add the `protect` report/CLI and fixture repositories.
5. [x] Extend the Action, README, CLI docs, and navigation.
6. [x] Run focused suites, lint/format checks, and the full test suite; distinguish
   any pre-existing environment failures from regressions.

## Non-goals for P0

- Full PEP 751 `pylock.toml`, `uv sync`, Poetry, pnpm, or Yarn runtime mediation.
- Automatic mutation of workflows, policy, lockfiles, or install-script allowlists.
- A hosted dashboard or telemetry service.
- Suppressing or downgrading known-malware decisions.
- Signing the hosted feed or evaluating registry provenance. Those remain high-value
  follow-ups once the adoption path is coherent.

## Follow-on priorities

1. Add `uv.lock`/PEP 751 runtime drivers and pnpm install/build-script policy.
2. Verify npm and PyPI provenance attestations and expose them in inventory.
3. Sign feed snapshots and publish populated release windows.
4. Add dependency-to-code reachability for JavaScript/TypeScript.
5. Offer a guarded `protect --fix` only for deterministic configuration changes, with
   backups and a dry-run diff.

## Risks and mitigations

- Requirements syntax is broad. P0 supports the safe, common subset and rejects
  ambiguous network/source options rather than guessing.
- Exceptions can become permanent bypasses. Required ownership, reason, expiry, and
  evidence make drift visible; malware remains immutable.
- A combined command can hide nuance. The JSON report retains each component check,
  finding, decision, and warning rather than collapsing everything into a score.
- Manager detection can overpromise. Every detected workflow reports an explicit
  enforcement coverage state: supported, partial, or unsupported.
