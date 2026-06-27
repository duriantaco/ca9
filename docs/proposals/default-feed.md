# Proposal: a default, OSV-backed package feed

**Status:** partially implemented; hosted feed data still pending.

**Problem it solves:** ca9's runtime prevention layer (`ca9 run`, the npm/PyPI gateways,
`ca9 vet` package-age and feed-backed malware checks) is fully built but still needs hosted
data. `ca9 feed update` now has a default URL, but that URL 404s until the `feed` branch is
published by the scheduled workflow. Out of the box, the malware blocker has nothing to
block against until a feed is installed from the default URL, `CA9_FEED_URL`, or `--from`.

**Goal:** `ca9 feed update` with **no arguments** installs a current, integrity-verified
malware feed from a hosted default source, so malware blocking works immediately after
`pip install ca9`.

Current code status:

- `DEFAULT_FEED_URL` is wired and `--from` is optional.
- The builder emits an inline malware bundle with required empty release datasets.
- Runtime preflight, npm/PyPI gateways, and `ca9 vet` consume installed feed malware.
- `covers_since` release-window semantics are implemented, but the hosted release window is
  not populated yet.
- Feed snapshots are hash-verified, but not signed.

---

## 1. What already exists (do not rebuild)

The feed engine in `src/ca9/package_feed.py` is complete and tested:

- `update_feed_from_source(source)` accepts an HTTPS URL, a JSON file, or a directory with
  `snapshot.json`; normalizes, sha256-hashes, writes a snapshot, and flips the `current.json`
  pointer atomically.
- `feed_status()` reports `ready | stale | missing | tampered` with policy-driven
  fail-open/closed.
- `lookup_malware()` / `lookup_release_time()` back `ca9 vet`, preflight, and both gateways.
- Integrity is already enforced: per-dataset sha256 + `snapshot_id` derived from metadata;
  tamper raises `FeedTamperError`.

So this proposal is **data + hosting + a zero-arg default**, not new feed plumbing.

`REQUIRED_DATASETS = ("npm-malware", "pypi-malware", "npm-releases", "pypi-releases")`.

### Exact dataset shapes the code expects (from tests + readers)

Malware dataset (`lookup_malware` matches by normalized name, optional version):

```json
{"packages": [
  {"name": "bad-lib", "version": "1.0.0", "id": "MAL-2024-1", "summary": "..."},
  {"name": "evil-pkg", "id": "MAL-2024-2", "summary": "all versions malicious"}
]}
```

- **Name only, no `version`** ⇒ matches the package at *any* version. In `preflight._malware_decisions`,
  a request with no pinned version *only* matches entries that omit `version`. So "whole package
  is malicious" MUST be emitted with no `version` field; version-specific malware needs one entry
  per affected version.
- Names are normalized: npm lowercased; PyPI canonicalized (`packaging.utils.canonicalize_name`).

Releases dataset (`lookup_release_time` fast path):

```json
{"packages": {"left-pad": {"1.3.0": "2026-06-25T00:00:00Z"}}}
```

Bundle envelope (inline form, what `update_feed_from_source` reads over HTTP today):

```json
{
  "schema": "ca9.feed.v1",
  "created_at": "2026-06-27T00:00:00Z",
  "expires_at": "2026-07-04T00:00:00Z",
  "datasets": { "npm-malware": {...}, "pypi-malware": {...},
                "npm-releases": {...}, "pypi-releases": {...} }
}
```

---

## 2. Data sources (open, redistributable)

| Dataset | Source | License | Access |
|---|---|---|---|
| npm/pypi **malware** | **OpenSSF `ossf/malicious-packages`** | Apache-2.0 | Bucket export + repo (`osv/` dir, OSV `MAL-` records) |
| npm/pypi **malware** (cross-ref) | OSV.dev per-ecosystem export | CC-BY-4.0 (per-source varies) | `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip` |
| npm/pypi **release times** | **deps.dev v3 API** (`published_at`) | Google, no key | per-package + batch; or registry-native firehoses |

**Recommendation:** source malware from **OpenSSF malicious-packages** as primary — it is
unambiguously Apache-2.0 and purpose-built for redistribution, avoiding OSV's per-source license
patchwork. Use OSV export only as a coverage cross-check. ([ossf/malicious-packages](https://github.com/ossf/malicious-packages),
[OSV data docs](https://google.github.io/osv.dev/data/), [deps.dev API](https://docs.deps.dev/api/v3/))

OSV `MAL-` record → ca9 entry mapping:

- `id` → entry `id` (e.g. `MAL-2025-12345`).
- `summary`/`details` → entry `summary`.
- `affected[].package.name` (+ `ecosystem` → `npm-malware`/`pypi-malware`) → entry `name`.
- `affected[].versions` → if the advisory pins specific versions, emit one entry per version.
- no `versions` and no bounded `ranges` → emit a single entry with **no** `version`, meaning
  every version matches.
- bounded `ranges` without explicit versions → currently skipped until range-aware feed
  matching exists; this avoids incorrectly turning a bounded range into a whole-package block.

---

## 3. The release-time problem and its fix (key design decision)

Shipping every npm/PyPI release timestamp is multi-GB and infeasible. But **package-age only
cares about recent packages** — a 48h (default) to ~30-day minimum. So we ship a **recent
window**, not all of history, plus a cutoff so absence is meaningful:

```json
{"covers_since": "2026-05-28T00:00:00Z",
 "packages": {"left-pad": {"1.3.0": "2026-06-25T00:00:00Z"}}}
```

Soundness: the builder guarantees the dataset contains **every** release published at/after
`covers_since`. Therefore a version **absent** from the dataset was published **before**
`covers_since`. New age logic:

1. version present → use its timestamp (block if younger than `minimum_hours`).
2. version absent **and** `now - covers_since >= minimum_hours` → **pass** (provably old enough).
3. version absent **and** window too short / no `covers_since` → `unknown` (current behavior).

This turns "ship all release history" into a small, correct, bounded dataset. Window of **30
days** covers essentially all realistic min-age policies.

Code touch points: `preflight._package_age_decisions` / `_unknown_release_time_decision` and
`npm_gateway._denied_version` / `pypi_gateway._denied_version` gain the case-2 short-circuit; add
a `lookup_release_window_start(snapshot, ecosystem)` helper in `package_feed.py`.

---

## 4. Staged rollout (each stage ships independently)

### v1 — MVP: malware blocking works out of the box  ← closes the headline gap

- Build a bundle with **complete** npm + PyPI malware from OpenSSF; ship releases datasets as
  `{"packages": {}}` (empty but present, so `REQUIRED_DATASETS` validation passes unchanged).
- Host it; point a new `DEFAULT_FEED_URL` at it.
- [x] Make `--from` optional: `ca9 feed update` with no arg uses `DEFAULT_FEED_URL`.
- [ ] Publish the `feed` branch so zero-arg `ca9 feed update` succeeds without `CA9_FEED_URL`.
- Result once hosted: after `pip install ca9 && ca9 feed update`, `ca9 run -- npm install <malware>` blocks.
  Package-age stays opt-in/BYO (it's already `enabled=False` by default), so empty releases data
  changes nothing for default users.

Size estimate: full npm+pypi malware ≈ tens of thousands of name/id rows, a few MB JSON, <1 MB
gzipped — fine as a single inline bundle.

### v1.1 — package-age works without BYO data

- [x] Add the case-2 age logic above.
- [ ] Add the 30-day recent-releases window (deps.dev `published_at`, or registry firehoses)
  with `covers_since`.
- Releases data is larger; host it as a **separate gzipped, file-backed dataset** rather than
  inline. Requires extending `_load_source`'s HTTP branch to fetch a file-backed/zip snapshot
  (today HTTP only handles `_load_inline_bundle`). Local file/dir already supports file-backed.

### v1.2 — hardening

- Detached signature (minisign/cosign) over `snapshot.json`; verify on `feed update`.
- Incremental refresh via OSV `modified_id.csv` instead of full rebuild.
- `feed update` UX: auto-refresh hint when `feed status` is `stale`; optional `--check`.

---

## 5. The builder

New `scripts/build_feed.py` (+ `tests/test_build_feed.py`), pure-stdlib where possible:

1. Download OpenSSF malicious-packages export (npm + PyPI).
2. Parse OSV `MAL-` records → `npm-malware` / `pypi-malware` per §2 mapping; normalize names;
   dedupe by `(name, version|∅, id)`.
3. (v1.1) Pull last-30-day releases → `npm-releases` / `pypi-releases` with `covers_since`.
4. Emit `schema: ca9.feed.v1`, `created_at = now`, `expires_at = now + 7d`.
5. Write inline bundle (v1) or file-backed snapshot dir (v1.1); the existing
   `update_feed_from_source` does hashing/snapshot-id — the builder can just emit datasets and
   let a publish step run `update_feed_from_source` to produce canonical output, or replicate the
   `_json_bytes` + `_snapshot_id` logic.

## 6. Hosting & refresh (zero infra cost)

- A scheduled GitHub Actions workflow (`.github/workflows/feed.yml`, daily) runs the builder and
  publishes the bundle to **GitHub Pages** (repo already deploys to `duriantaco.github.io/ca9`) or
  a **release asset** / dedicated `feed` branch.
- `DEFAULT_FEED_URL` points at that stable URL; `expires_at = now + 7d` gives a 6-day grace
  window before `feed status` reports `stale`.
- Consider a sibling `ca9-feed` repo so feed publish cadence is decoupled from code releases.

## 7. Code changes summary

| File | Change | Stage |
|---|---|---|
| `cli.py` `feed_update_cmd` | `--from` optional; default to `DEFAULT_FEED_URL` | v1 |
| `package_feed.py` | add `DEFAULT_FEED_URL`; add release-window helpers; wrap feed download/JSON errors cleanly | v1 / v1.1 |
| `preflight.py`, `npm_gateway.py`, `pypi_gateway.py` | case-2 "absent ⇒ old enough" age short-circuit; npm can use registry metadata time map in the gateway | v1.1 |
| `cli.py` `vet_cmd` | use installed local feed malware and package-age findings | v1 / v1.1 |
| `scripts/build_feed.py` + workflow | new builder + daily publish | v1 |
| docs / README | document zero-arg `feed update`, refresh, provenance/licenses | v1 |

## 8. Risks / open questions

- **Release-window size** (v1.1): npm publish volume is high; 30-day window may be tens of MB.
  Levers: shorter window, gzip + file-backed hosting, or per-ecosystem split. v1 sidesteps this
  entirely by shipping malware-only.
- **License hygiene:** keep malware sourcing to Apache-2.0 OpenSSF data; attribute OSV/deps.dev;
  add a `NOTICE`/attribution to the published bundle.
- **Trust:** the default feed is now a supply-chain dependency *of ca9 itself* — sign it (v1.2),
  and keep the hash-verified snapshot model (already present) as the integrity floor.
- **Naming match accuracy:** verify npm scoped names (`@scope/name`) and PyPI canonicalization
  round-trip exactly between the builder and `_normalize_package_name`.
