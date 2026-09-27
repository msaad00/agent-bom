"""The README demo excerpt is real output of ``agent-bom scan --demo --offline``.

The excerpt drifted (it printed ``CRIT 2 HIGH 16`` while the command printed
``CRIT 7 HIGH 11``) because nothing compared it with the command. This runs the
command and requires every excerpt line to appear in the real console output, in
the same order.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_BORDER = "│┃║"
_RULE = "─━"


def _normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip().strip(_BORDER).strip().strip(_RULE).strip())


def readme_excerpt() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    sample = readme.split("<summary>No project handy?", 1)[1].split("</details>", 1)[0]
    block = re.search(r"```text\n(.*?)\n```", sample, re.S)
    assert block, "README demo excerpt block not found"
    return [_normalize(line) for line in block.group(1).splitlines() if line.strip()]


def missing_in_order(excerpt: list[str], output: str) -> list[str]:
    """Return the excerpt lines that do not appear, in order, in *output*."""
    lines = [_normalize(line) for line in output.splitlines()]
    missing: list[str] = []
    cursor = 0
    for wanted in excerpt:
        for index in range(cursor, len(lines)):
            if lines[index] == wanted:
                cursor = index + 1
                break
        else:
            missing.append(wanted)
    return missing


def test_matcher_rejects_stale_and_reordered_excerpts() -> None:
    output = "│ Security posture: CRIT 7 HIGH 11 MED 5 │\nDISCOVER | Agents\n"
    assert missing_in_order(["Security posture: CRIT 7 HIGH 11 MED 5", "DISCOVER | Agents"], output) == []
    assert missing_in_order(["Security posture: CRIT 2 HIGH 16 MED 5"], output)
    assert missing_in_order(["DISCOVER | Agents", "Security posture: CRIT 7 HIGH 11 MED 5"], output)


def _run_demo(home: Path, hash_seed: str) -> str:
    env = {
        **os.environ,
        "PYTHONHASHSEED": hash_seed,
        "COLUMNS": "120",
        "HOME": str(home),
        "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
        "NO_COLOR": "1",
    }
    result = subprocess.run(
        [sys.executable, "-c", "from agent_bom.cli import cli_main; cli_main()", "scan", "--demo", "--offline", "--format", "console"],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 1, result.stdout[-2000:] + result.stderr[-2000:]
    return result.stdout + result.stderr


# Two hash seeds: set-ordered output (credential lists in blast lines once came
# from ``list(set(...))``) would pass under one seed and drift under another.
@pytest.mark.parametrize("hash_seed", ["0", "4242"])
def test_readme_demo_excerpt_matches_real_demo_output(tmp_path: Path, hash_seed: str) -> None:
    excerpt = readme_excerpt()
    assert any(line.startswith("Security posture:") for line in excerpt)
    assert any(line.startswith("Blast:") and "," in line for line in excerpt)
    assert missing_in_order(excerpt, _run_demo(tmp_path, hash_seed)) == []
