from pathlib import Path


def test_composite_action_exposes_protect_command_inputs():
    action = (Path(__file__).parents[1] / "action.yml").read_text()

    assert "Use scan, check, or protect." in action
    assert "CA9_POLICY: ${{ inputs.policy }}" in action
    assert "CA9_SCAN_WORKFLOWS: ${{ inputs.scan-workflows }}" in action
    assert '"$CA9_COMMAND" != "protect"' in action
    assert 'if [[ "$CA9_COMMAND" == "protect" ]]; then' in action
    assert 'cmd+=(--policy "$CA9_POLICY")' in action
    assert "cmd+=(--no-scan-workflows)" in action
