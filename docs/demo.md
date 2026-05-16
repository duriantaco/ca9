# Demo

ca9 ships with two local demos:

- a Flask reachability demo for CVE noise reduction
- a supply-chain vetting demo for artifact, dependency-confusion, and license gates

Both demos are local fixtures. The supply-chain demo intentionally avoids using a live
malicious repository, so screenshots are reproducible and safe.

## Reachability Demo

### What's in the demo

The demo is a Flask weather dashboard (`demo/app.py`) that intentionally imports a mix of packages — some used, some not — to demonstrate how ca9 distinguishes reachable from unreachable CVEs.

**Dependencies:**

- Flask, requests, pyyaml, colorama (actively used)
- Django, Pygments, sqlparse (imported but not meaningfully used)
- Plus their transitive dependencies

### Running the reachability demo

```bash
cd demo
bash setup_demo.sh
```

This creates a virtual environment, installs the pinned dependencies, and generates coverage data.

```bash
bash run_demo.sh
```

Or run manually:

```bash
# Activate the demo venv
source .venv/bin/activate

# Scan the demo dependency inventory with coverage
ca9 scan --repo . --coverage coverage.json --verbose
```

### Expected reachability results

The demo typically finds ~61 CVEs across the pinned demo dependency inventory:

- **~36 unreachable** (59%) — packages not imported or code not executed
- **~25 reachable** — vulnerable code paths that are actually used
- **0 inconclusive** — coverage data eliminates all ambiguity

This demonstrates ca9's core value: **nearly 60% of flagged CVEs are noise** that you can safely deprioritize.

### Key takeaways

1. **Static analysis alone** catches packages that are never imported (e.g., a transitive dependency of Django that your app doesn't use)
2. **Dynamic analysis** catches packages that are imported but whose vulnerable submodules are never called
3. **Submodule precision** matters — a package may be imported, but the specific vulnerable function may not be reachable
4. **Coverage quality** directly impacts verdict accuracy — better test coverage means fewer INCONCLUSIVE results

## Supply-Chain Vetting Demo

The supply-chain demo lives in `demo/supply_chain`. It generates a local fixture repo with
a `fyn.lock` and three hash-pinned wheel artifacts:

- `acme-internal`, an internal-looking package resolving from PyPI
- `startup-hook`, a wheel containing suspicious `.pth` startup code
- `license-risk`, a direct dependency declaring `AGPL-3.0-only`

Run it from the repository root:

```bash
bash demo/supply_chain/run_demo.sh
```

The wrapper prints the terminal report and writes `demo/supply_chain/ca9-vet.json`.
The underlying `ca9 vet` command exits `1` because the fixture intentionally contains
blocking findings.

Expected terminal output:

```text
ca9 supply-chain report for .../demo/supply_chain/repo
Packages: 4 | Edges: 3 | Findings: 3 | Block: 3 | Warn: 0
Artifact scans: 3 | Skipped artifacts: 0

Findings:
  [BLOCK] dependency_confusion critical acme-internal@1.0.0
    Possible dependency confusion for acme-internal
  [BLOCK] python-startup-pth-exec critical startup-hook@1.0.0
    Python startup file executes suspicious code in startup-hook
  [BLOCK] denied_license high license-risk@1.0.0
    Denied license for license-risk
```

Manual command:

```bash
cd demo/supply_chain
python3 make_demo.py
PYTHONPATH=../../src CA9_ARTIFACT_CACHE_DIR=.ca9-artifact-cache \
  python3 -m ca9.cli vet \
  --repo repo \
  --scan-artifacts \
  --internal-package 'acme-*' \
  --private-index https://packages.acme.internal/simple \
  --deny-license AGPL-3.0
```
