"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_REPO = FIXTURES_DIR / "sample_repo"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def sample_repo():
    return SAMPLE_REPO


@pytest.fixture
def snyk_path():
    return FIXTURES_DIR / "snyk_sample.json"


@pytest.fixture
def dependabot_path():
    return FIXTURES_DIR / "dependabot_sample.json"


@pytest.fixture
def coverage_path():
    return FIXTURES_DIR / "coverage_sample.json"


@pytest.fixture
def trivy_path():
    return FIXTURES_DIR / "trivy_sample.json"


@pytest.fixture
def pip_audit_path():
    return FIXTURES_DIR / "pip_audit_sample.json"


@pytest.fixture(autouse=True)
def _no_registry_release_lookups(monkeypatch):
    """Keep release-age registry lookups offline unless a test supplies its own fetch."""
    from ca9 import release_age

    def offline_fetch(url: str):
        raise OSError(f"registry access is disabled in tests: {url}")

    monkeypatch.setattr(release_age, "_default_fetch", offline_fetch)
