# Demo

ca9 ships with a demo project that showcases the full analysis pipeline.

## What's in the demo

The demo is a Flask weather dashboard (`demo/app.py`) that intentionally imports a mix of packages — some used, some not — to demonstrate how ca9 distinguishes reachable from unreachable CVEs.

**Dependencies:**

- Flask, requests, pyyaml, colorama (actively used)
- Django, Pygments, sqlparse (imported but not meaningfully used)
- Plus their transitive dependencies

## Running the demo

### Setup

```bash
cd demo
bash setup_demo.sh
```

This creates a virtual environment, installs the pinned dependencies, and generates coverage data.

### Run the analysis

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

## Expected results

The demo typically finds ~61 CVEs across the pinned demo dependency inventory:

- **~36 unreachable** (59%) — packages not imported or code not executed
- **~25 reachable** — vulnerable code paths that are actually used
- **0 inconclusive** — coverage data eliminates all ambiguity

This demonstrates ca9's core value: **nearly 60% of flagged CVEs are noise** that you can safely deprioritize.

## Key takeaways

1. **Static analysis alone** catches packages that are never imported (e.g., a transitive dependency of Django that your app doesn't use)
2. **Dynamic analysis** catches packages that are imported but whose vulnerable submodules are never called
3. **Submodule precision** matters — a package may be imported, but the specific vulnerable function may not be reachable
4. **Coverage quality** directly impacts verdict accuracy — better test coverage means fewer INCONCLUSIVE results
