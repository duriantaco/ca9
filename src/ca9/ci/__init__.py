"""CI job reach model (GitHub Actions, GitLab CI) and publish-job rules."""

from ca9.ci.audit import RULES, audit_repository
from ca9.ci.inventory import DEFAULT_MAX_JOBS, build_inventory
from ca9.ci.model import SCHEMA

__all__ = ["DEFAULT_MAX_JOBS", "RULES", "SCHEMA", "audit_repository", "build_inventory"]
