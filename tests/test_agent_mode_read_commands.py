"""`--agent-mode` must emit a valid stable JSON envelope for read commands.

The global `--agent-mode` flag is documented as emitting stable machine-readable
JSON, but only `scan` and `check` honored it. An automation caller doing
`agent-bom --agent-mode doctor | json.load` got an ANSI dump and a parse error
(with exit 0). These tests pin the envelope contract across the common read
commands.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

READ_COMMANDS = ["doctor", "capabilities", "where", "mesh", "scanners"]


@pytest.mark.parametrize("command", READ_COMMANDS)
def test_agent_mode_emits_parseable_envelope(command: str) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--agent-mode", command])

    assert result.exit_code == 0, result.output
    # The documented contract is `agent-bom --agent-mode <cmd> | json.load`, and a
    # shell pipe reads STDOUT only. Progress/log lines (e.g. discovery or
    # transitive-resolution banners emitted through a stderr Rich console, possibly
    # by a still-running background scan on the same xdist worker) belong on stderr
    # and must never corrupt the JSON. Assert on stdout alone — `result.output`
    # merges stderr in, which the real pipe never sees and which makes this an
    # order-dependent flake under a work-stealing distribution.
    payload = json.loads(result.stdout)  # stdout must be valid JSON, not ANSI
    assert payload["schema_version"] == "1"
    assert payload["mode"] == "agent"
    assert payload["command"] == command
    assert "data" in payload
