# Installation

## Requirements

- Python **3.10** or later

## Install from source

```bash
git clone https://github.com/duriantaco/ca9.git
cd ca9
pip install .
```

This installs the core library. The only required runtime dependency is `packaging`, which ca9 uses for PEP 440 version comparison.

## Install with CLI support

The CLI requires [click](https://click.palletsprojects.com/):

```bash
pip install ".[cli]"
```

## Development install

```bash
pip install ".[dev]"
pre-commit install
```

Or use the Makefile:

```bash
make dev
```

This installs all development dependencies (pytest, ruff, tox, pre-commit, skylos) and sets up pre-commit hooks.

## Verify installation

```bash
ca9 --help
```

You should see:

```
Usage: ca9 [OPTIONS] COMMAND [ARGS]...

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  action-plan   Generate a machine-readable action plan for CI/CD...
  cap-diff      Compute capability diff between two AI-BOM scans.
  cap-gate      Evaluate capability diff against a policy file.
  capabilities  Scan repository for AI capabilities...
  check         Analyze an SCA report for reachability.
  enrich-sbom   Enrich a CycloneDX or SPDX SBOM with ca9 reachability...
  inventory     Show normalized package inventory.
  scan          Scan declared or installed packages via OSV.dev.
  trace         Trace exploit paths from entry points to vulnerable API...
  vet           Run package supply-chain risk checks.
  vex-diff      Compare two VEX documents and show what changed...
```
