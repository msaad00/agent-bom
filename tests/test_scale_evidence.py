from __future__ import annotations

import subprocess
import sys


def test_scale_evidence_scaffold_is_complete() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_scale_evidence.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
