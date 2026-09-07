"""Verified npm dependency-update review.

The public ``review_lockfiles`` API compares declarations and bounded static
observations; it does not establish behavioral equivalence or package safety.
"""

from ca9.review.service import ReviewReport, review_lockfiles

__all__ = ["ReviewReport", "review_lockfiles"]
