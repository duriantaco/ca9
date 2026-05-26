# Security Policy

## Local Research Privacy

ca9 is a public package, but vulnerability research outputs belong to the user
running it. The `hunt` workflow is designed to run locally on code the user is
authorized to test.

ca9 does not intentionally:

- send hunt findings, harnesses, crash inputs, or exploit material to ca9 maintainers;
- phone home or collect telemetry from `ca9 hunt`;
- probe remote targets from `ca9 hunt`;
- include raw crashing inputs or exploit payloads in normal hunt reports.

Generated hunt artifacts are written locally. By default, harness output
and researcher packet directories include a `.gitignore` guard and best-effort
private directory permissions. Researcher packets are private triage material for
authorized validation and coordinated disclosure, not public advisories. Users
should still avoid publishing CI artifacts, logs, or MCP transcripts that contain
suspected vulnerability details.

## Reporting a Vulnerability in ca9

If you find a vulnerability in ca9 itself, report it privately through the
repository security advisory flow or by contacting the maintainers through the
project issue tracker without including exploit details in a public issue.
