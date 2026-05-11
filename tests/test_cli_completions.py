"""Regression tests for `agent-bom completions {bash,zsh,fish}`.

These guard against the v0.86.5 regression where the command shelled out to
`agent-bom` via subprocess and silently emitted zero bytes when the binary was
not on PATH — breaking the documented `eval "$(agent-bom completions zsh)"`
setup path. The fix uses Click's in-process completion API so script generation
no longer depends on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli._inventory import completions_cmd


def _invoke(shell: str) -> str:
    runner = CliRunner()
    result = runner.invoke(completions_cmd, [shell])
    assert result.exit_code == 0, result.output
    return result.output


def test_completions_zsh_emits_nonempty_script():
    output = _invoke("zsh")
    assert len(output) > 0, "zsh completion script must not be empty"
    assert "#compdef agent-bom" in output
    assert "_AGENT_BOM_COMPLETE=zsh_complete" in output


def test_completions_bash_emits_nonempty_script(tmp_path: Path):
    output = _invoke("bash")
    assert len(output) > 0, "bash completion script must not be empty"
    assert "_AGENT_BOM_COMPLETE=bash_complete" in output

    # bash -n syntax-checks the generated script. If bash is available, run it.
    bash = shutil.which("bash")
    if bash:
        script = tmp_path / "completions.bash"
        script.write_text(output)
        proc = subprocess.run([bash, "-n", str(script)], capture_output=True, text=True)
        assert proc.returncode == 0, f"bash -n failed: {proc.stderr}"


def test_completions_fish_emits_nonempty_script():
    output = _invoke("fish")
    assert len(output) > 0, "fish completion script must not be empty"
    assert "_AGENT_BOM_COMPLETE=fish_complete" in output


def test_completions_zsh_independent_of_path(monkeypatch):
    """The script must be generated in-process so it works even when the
    `agent-bom` binary is not on PATH (pipx, --user, unactivated venv)."""
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    output = _invoke("zsh")
    assert "#compdef agent-bom" in output
    assert len(output) >= 1000
