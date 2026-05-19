# ca9.parsers

SCA report parsing with auto-detection.

---

## `detect_parser(path) -> SCAParser`

```python
from ca9.parsers import detect_parser

parser = detect_parser(Path("report.json"))
```

Auto-detects the SCA format of the given JSON file. Tries Snyk, Dependabot, Trivy, and
pip-audit parsers in order and returns the first match. Raises `ValueError` if no parser
can handle the file.

---

## SCAParser protocol

```python
class SCAParser(Protocol):
    def can_parse(self, data: Any) -> bool: ...
    def parse(self, data: Any) -> list[Vulnerability]: ...
```

All parsers implement this protocol. See [Parser Architecture](../architecture/parsers.md) for details on adding custom parsers.

---

## SnykParser

**Module:** `ca9.parsers.snyk`

Parses output from `snyk test --json`.

### `can_parse(data) -> bool`

Returns `True` if the data contains a `vulnerabilities` key (single project) or is a list of objects with `vulnerabilities` keys (multi-project).

### `parse(data) -> list[Vulnerability]`

Extracts vulnerabilities from Snyk JSON. Handles both single-project and multi-project layouts.

---

## DependabotParser

**Module:** `ca9.parsers.dependabot`

Parses GitHub Dependabot alerts exported via the API.

### `can_parse(data) -> bool`

Returns `True` if the data is a list of objects with `security_advisory` and `dependency` keys.

### `parse(data) -> list[Vulnerability]`

Extracts vulnerabilities from Dependabot alert objects. Uses GHSA ID, CVE ID, or alert number as the vulnerability ID.

---

## TrivyParser

**Module:** `ca9.parsers.trivy`

Parses output from `trivy fs --format json`.

### `can_parse(data) -> bool`

Returns `True` when the data has Trivy result metadata such as `Results` or
`SchemaVersion`.

### `parse(data) -> list[Vulnerability]`

Extracts package vulnerability findings from Trivy result entries. Preserves target
metadata, dependency paths when present, CWE/CPE data, references, advisory URLs, and
published/modified timestamps.

---

## PipAuditParser

**Module:** `ca9.parsers.pip_audit`

Parses output from `pip-audit --format json`.

### `can_parse(data) -> bool`

Returns `True` when the data has a `dependencies` array.

### `parse(data) -> list[Vulnerability]`

Extracts vulnerability entries from dependency records and preserves aliases and CWE data
where pip-audit provides them.
