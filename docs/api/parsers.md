# ca9.parsers

SCA report parsing with auto-detection.

---

## `detect_parser(path) -> SCAParser`

```python
from ca9.parsers import detect_parser

parser = detect_parser(Path("report.json"))
```

Auto-detects the SCA format of the given JSON file. Tries each registered parser in order and returns the first match. Raises `ValueError` if no parser can handle the file.

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

Parses native Trivy JSON result sections and preserves dependency and advisory metadata
when present.

---

## GrypeParser

**Module:** `ca9.parsers.grype`

Parses native Grype JSON `matches`, including vulnerability, artifact, ecosystem,
severity, alias, and reference data.

---

## OsvScannerParser

**Module:** `ca9.parsers.osv_scanner`

Parses OSV-Scanner's native `results[].packages[]` JSON and maps nested full OSV
records into ca9 vulnerabilities.

---

## PipAuditParser

**Module:** `ca9.parsers.pip_audit`

Parses pip-audit dependency and vulnerability entries.
