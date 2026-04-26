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

The release workflow is manual by design: a maintainer chooses the SemVer version, then GitHub Actions handles the version bump, verification, tag, GitHub release, and PyPI publish.

One-time PyPI setup:

- Configure PyPI Trusted Publisher for `duriantaco/ca9`.
- Use workflow name `release.yml`.
- Use environment `pypi`.

Before running the workflow:

- Add a `CHANGELOG.md` section for the target version, such as `## [0.2.0] - 2026-04-26`.
- Commit and push the release candidate changes to `main`.
- Confirm there is no existing `vX.Y.Z` tag for the target version.

Run the release:

```bash
gh workflow run release.yml -f version=0.2.0
gh run watch
```

The workflow validates SemVer, writes the version into `pyproject.toml`, `ca9.__version__`, and docs structured data, runs tests/lint/docs build, builds the package, commits the version bump, tags `vX.Y.Z`, creates the GitHub release, and publishes to PyPI.

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
