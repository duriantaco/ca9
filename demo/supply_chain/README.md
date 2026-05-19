# Supply-Chain Demo

This demo creates a local fixture repository with a generated `fyn.lock` and local
wheel artifacts. It is designed for README screenshots and CI gate examples without
using a live suspicious repository or executing package code.

Run it from this directory:

```bash
bash run_demo.sh
```

The report demonstrates three blocking checks:

- dependency confusion: `acme-internal` matches `acme-*` but resolves from PyPI
- artifact static analysis: `startup-hook` contains suspicious `.pth` startup code
- license policy: `license-risk` declares `AGPL-3.0-only`

`run_demo.sh` also writes `ca9-vet.json` in this directory for screenshots of the JSON
report or for uploading as a CI artifact.
