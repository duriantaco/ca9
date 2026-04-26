# ca9.report

Report formatting and output.

---

## `report_to_dict(report) -> dict`

```python
from ca9.report import report_to_dict

d = report_to_dict(report)
```

Converts a `Report` object to a JSON-serializable dictionary.

**Structure:**

```json
{
  "summary": {
    "total": 10,
    "reachable": 2,
    "unreachable": 7,
    "inconclusive": 1
  },
  "repo_path": ".",
  "coverage_path": "coverage.json",
  "results": [
    {
      "id": "GHSA-abcd-1234",
      "package": "jinja2",
      "version": "3.1.2",
      "severity": "high",
      "verdict": "UNREACHABLE (static)",
      "reason": "submodule jinja2.sandbox not imported",
      "imported_as": null,
      "executed_files": [],
      "dependency_of": null
    }
  ]
}
```

---

## `write_json(report, output=None) -> str`

Writes the report as formatted JSON.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `report` | `Report` | The report to format |
| `output` | `Path \| TextIO \| None` | Output destination (file path, file object, or `None` for string only) |

**Returns:** The JSON string.

---

## `write_table(report, output=None, verbose=False) -> str`

Writes the report as an ASCII table.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `report` | `Report` | The report to format |
| `output` | `Path \| TextIO \| None` | Output destination |
| `verbose` | `bool` | Include reasoning trace for each verdict |

**Returns:** The table string.

**Example output:**

```
┌──────────────────┬──────────┬──────────────────────────┬──────────┐
│ CVE              │ Package  │ Verdict                  │ Severity │
├──────────────────┼──────────┼──────────────────────────┼──────────┤
│ GHSA-abcd-1234   │ jinja2   │ UNREACHABLE (static)     │ high     │
│ CVE-2024-5678    │ django   │ REACHABLE                │ critical │
└──────────────────┴──────────┴──────────────────────────┴──────────┘

Summary: 2 CVEs analyzed — 1 reachable, 1 unreachable (50% noise reduction)
```

With `verbose=True`, each row also shows the reasoning trace.

---

## `write_sarif(report, output=None) -> str`

Writes the report as SARIF 2.1.0 for GitHub code scanning and SARIF-compatible tooling.

```python
from ca9.report import write_sarif

sarif_text = write_sarif(report)
```

SARIF results include stable fingerprints, severity mapping, confidence scores, evidence, policy adjustments, warnings, and optional blast-radius or threat-intel properties where available.

---

## `write_markdown(report, output=None) -> str`

Writes a human-readable Markdown report for PR comments, build artifacts, or internal review.

---

## `write_html(report, output=None) -> str`

Writes a standalone HTML report with escaped result content.
