# ca9 Release Workflow

This document defines how ca9 versions, GitHub releases, and PyPI publishes are
handled.

## Scope

- Automated semantic versioning with Release Please
- Semantic PR title guardrails
- GitHub release and tag creation
- PyPI package build and publish from immutable release tags

## Required Guardrails

1. Protect `main`.
   - Require pull requests before merge.
   - Require CI checks to pass.
   - Prefer squash merges so the PR title becomes the release commit.

2. Use semantic PR titles.
   - Workflow: `.github/workflows/pr-title.yml`
   - Format: `<type>(<scope>): <subject>`
   - Examples:
     - `feat(inventory): add npm package-lock reader`
     - `fix(scanner): preserve npm package names`
     - `docs(release): document automated publishing`

3. Keep Release Please configured.
   - Workflow: `.github/workflows/release.yml`
   - Config: `tools/release/release-please-config.json`
   - Manifest: `tools/release/.release-please-manifest.json`

4. Keep PyPI trusted publishing configured.
   - Workflow file: `release.yml`
   - Environment: `pypi`
   - Package: `ca9`

5. Prefer a dedicated release token.
   - Preferred secret: `RELEASE_PLEASE_TOKEN`
   - Fallback: `GITHUB_TOKEN`
   - A dedicated token or GitHub App is better when release PRs must satisfy
     required status checks.

## Release Baseline

Release Please is bootstrapped from the existing `v0.3.1` GitHub release:

- Manifest version: `0.3.1`
- Bootstrap SHA: `6f6b322ec407c8b3c6a9e1a52afba068ca809b59`

This prevents Release Please from trying to create an already-existing `v0.3.1`
tag. Future releases are generated from commits after the bootstrap SHA.

## Release Flow

1. Contributors merge PRs to `main` with semantic titles.
2. On push to `main`, Release Please opens or updates a release PR.
3. Maintainers review and merge the Release Please PR.
4. Release Please creates the `vX.Y.Z` tag and GitHub release.
5. The same workflow builds and publishes from the generated tag.

The publish job checks that:

- the checked-out commit is the release tag commit,
- the release tag is reachable from `main`,
- the GitHub release exists,
- `pyproject.toml`, `src/ca9/__init__.py`,
  `tools/release/.release-please-manifest.json`, and docs structured metadata
  all match the tag version.

## Version Rules

- `feat` -> minor bump
- `fix` -> patch bump
- `BREAKING CHANGE` footer -> major bump
- `docs`, `test`, `chore`, `ci`, and similar maintenance commits normally do
  not create a release unless they include breaking-change metadata.

## Recovery

If publishing fails after the GitHub release was created:

1. Fix the workflow, package metadata, or PyPI publishing setup.
2. Re-run the failed publish job if the dist artifacts are still valid.
3. Otherwise, manually dispatch `.github/workflows/release.yml` with
   `ref=vX.Y.Z` to rebuild and publish from the existing release tag.
4. Do not publish from a branch ref.
