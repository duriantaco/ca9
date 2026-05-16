from __future__ import annotations

from ca9.core.models import Inventory
from ca9.core.pipeline import PipelineContext


def test_pipeline_context_keeps_repo_path(tmp_path):
    context = PipelineContext(repo_path=tmp_path, options={"mode": "inventory"})
    inventory = Inventory(repo_path=str(context.repo_path))

    assert inventory.repo_path == str(tmp_path)
    assert context.options["mode"] == "inventory"
