---
title: Release And Growth Checklist
description: Practical release, SEO, and growth checklist for publishing ca9 Python CVE reachability analysis updates.
---

# Release And Growth Checklist

Use this checklist before publishing a ca9 release or promoting a new docs update.

## Pre-release

```bash
pytest -q
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mkdocs build --strict -d /tmp/ca9-mkdocs-site
```

Check package metadata:

```bash
python -m ca9.cli --version
python -m ca9.cli --help
python -m ca9.cli check --help
```

## Automated release

ca9 uses Release Please for automatic versioning. Contributors merge PRs with semantic titles, and Release Please opens or updates the release PR from commits on `main`.

One-time setup:

- Configure PyPI Trusted Publisher for `duriantaco/ca9`.
- Use workflow file `release.yml`.
- Use environment `pypi`.
- Prefer a `RELEASE_PLEASE_TOKEN` secret so release PRs can satisfy required checks; the workflow falls back to `GITHUB_TOKEN`.

PR title format:

```text
<type>(<scope>): <subject>
```

Examples:

```text
feat(inventory): add npm package-lock reader
fix(scanner): preserve npm package names
docs(release): document automated publishing
```

Release flow:

- Pushes to `main` run `.github/workflows/release.yml`.
- Release Please updates `CHANGELOG.md`, `pyproject.toml`, `src/ca9/__init__.py`, docs structured metadata, and the release manifest.
- A maintainer reviews and merges the Release Please PR.
- Release Please creates the `vX.Y.Z` tag and GitHub release.
- The publish job checks tag provenance and version consistency, runs tests/lint/docs build, builds the package, and publishes to PyPI.
- If publish needs a safe retry after a GitHub release exists, manually dispatch `release.yml` with `ref=vX.Y.Z`.

Baseline:

- The release manifest starts from the existing `v0.3.1` GitHub release to avoid duplicate tag creation.
- Future versions are derived from semantic commit history after the bootstrap SHA.

## Metadata

- Confirm `pyproject.toml` version and `ca9.__version__` match.
- Confirm PyPI project URLs point to docs, source, issues, and changelog.
- Confirm README examples match the current CLI.
- Confirm SARIF and OpenVEX output use the current tool version.

## SEO

- Confirm `site_url` and canonical repository links are correct in `mkdocs.yml`.
- Confirm the homepage title and description include "Python CVE reachability analysis" naturally.
- Confirm integration pages exist for Snyk, Dependabot, Trivy, pip-audit, OSV, SARIF, OpenVEX, SBOM, MCP, and CI/CD.
- Build docs and submit the generated sitemap in Google Search Console after deployment.

## GitHub

Add or verify repository topics:

- `cve`
- `sca`
- `reachability-analysis`
- `openvex`
- `sarif`
- `python-security`
- `osv`

## Artifacts

For a release candidate, generate representative artifacts:

```bash
ca9 scan --repo . -f json -o ca9-report.json
ca9 scan --repo . -f sarif -o ca9.sarif
ca9 scan --repo . -f vex -o openvex.json
ca9 scan --repo . -f markdown -o ca9-report.md
ca9 scan --repo . -f html -o ca9-report.html
```
