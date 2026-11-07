# Security Policy

## Supported versions

Security fixes land on `main` and ship in the next release. Only the latest
released minor version of ca9 receives fixes; please upgrade before reporting.

## Reporting a vulnerability in ca9

Please report vulnerabilities privately. Do not open a public issue, pull
request, or discussion for an unfixed vulnerability.

- Use GitHub private vulnerability reporting:
  <https://github.com/duriantaco/ca9/security/advisories/new>
- Include the ca9 version, the command you ran, and a minimal reproduction.
  Synthetic fixtures are preferred over live malware samples.

We will acknowledge the report, agree on a fix and disclosure timeline with
you, and credit you in the advisory unless you ask us not to.

In scope: anything that makes ca9 miss, allow, or misreport something its
documentation says it blocks or detects; bypasses of `ca9 run`, the shims, or
the registry gateways; secret leakage through output or audit logs; unsafe
handling of untrusted lockfiles, artifacts, or feeds; and compromise of the
release or feed publishing pipelines.

## Verifying what you install

- **PyPI releases** are published from `.github/workflows/release.yml` with
  PyPI trusted publishing and carry PEP 740 attestations. Check them on the
  PyPI file page, or with
  `pypi-attestations verify pypi --repository https://github.com/duriantaco/ca9 pypi:<wheel-or-sdist-filename>`.
- **The default malware feed** (`latest.json` on the `feed` branch) carries a
  GitHub artifact attestation:
  `gh attestation verify latest.json --repo duriantaco/ca9`.
