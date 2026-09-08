"""A terminal recording must fail closed before publishing incomplete CLI output."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALID = "\n".join(
    [
        "Summary",
        "5 agents",
        "ANALYZE | Top Findings",
        "CVE-2023-4863",
        "ANALYZE | Critical Details",
        "PROTECT | Fix First",
        "Upgrade pillow",
        "GOVERN | Compliance",
    ]
)


@pytest.mark.parametrize(
    ("status", "output", "error"),
    [
        (0, VALID, "Expected the synthetic demo security verdict 1"),
        (2, VALID, "Expected the synthetic demo security verdict 1"),
        (1, "Traceback: scanner crashed", "Missing required CLI section"),
        (1, VALID.replace("PROTECT | Fix First", "changed heading"), "Missing required CLI section"),
        (1, VALID.replace("5 agents\n", ""), "Empty required CLI section"),
    ],
)
def test_recording_rejects_wrong_verdict_and_incomplete_output(tmp_path, status, output, error):
    executable = tmp_path / "agent-bom"
    executable.write_text(f"#!{sys.executable}\nprint({output!r})\nraise SystemExit({status})\n")
    executable.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/render_demo.sh")],
        text=True,
        capture_output=True,
        env={**os.environ, "PATH": f"{tmp_path}:{Path(sys.executable).parent}:{os.environ['PATH']}", "AGENT_BOM_DEMO_CHECK_ONLY": "1"},
    )
    assert result.returncode != 0
    assert error in result.stderr
    assert "recorded CLI excerpt" not in result.stdout


def test_failed_playback_preserves_previous_gif(tmp_path):
    vhs = tmp_path / "vhs"
    vhs.write_text("#!/bin/sh\nexit 0\n")  # VHS itself can succeed while the command inside it fails.
    vhs.chmod(0o755)
    artifact = tmp_path / "existing.gif"
    artifact.write_bytes(b"previous verified recording")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/render_demo_gif.sh")],
        text=True,
        capture_output=True,
        env={**os.environ, "PATH": f"{tmp_path}:{Path(sys.executable).parent}:{os.environ['PATH']}", "AGENT_BOM_DEMO_GIF": str(artifact)},
    )
    assert result.returncode != 0
    assert "playback did not complete" in result.stderr
    assert artifact.read_bytes() == b"previous verified recording"
