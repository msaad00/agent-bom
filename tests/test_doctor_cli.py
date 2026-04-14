from __future__ import annotations

from click.testing import CliRunner

from agent_bom.cli import main


def test_doctor_groups_output_and_shows_next_steps():
    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert "Core readiness" in result.output
    assert "Runtime surfaces" in result.output
    assert "Platform integrations" in result.output
    assert "Next commands" in result.output
    assert "agent-bom agents --demo --offline" in result.output
