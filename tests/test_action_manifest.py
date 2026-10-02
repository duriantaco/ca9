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


def test_composite_action_coverage_generation_is_opt_in():
    action = (Path(__file__).parents[1] / "action.yml").read_text()

    block = action.split("  auto-coverage:\n", 1)[1].split("\n  no-auto-coverage:", 1)[0]
    assert 'default: "false"' in block
    assert "CA9_AUTO_COVERAGE: ${{ inputs.auto-coverage }}" in action
    assert 'elif [[ "$CA9_AUTO_COVERAGE" == "true" ]]; then' in action
    assert "cmd+=(--auto-coverage)" in action
    # The deprecated input still parses and is passed through as a no-op.
    assert "CA9_NO_AUTO_COVERAGE: ${{ inputs.no-auto-coverage }}" in action
    assert "cmd+=(--no-auto-coverage)" in action
