"""Data model atlas regeneration guardrails."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_data_model_atlas_generator_check_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/regenerate_data_model_atlas.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
