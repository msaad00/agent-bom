from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_product_surface_contract_is_aligned() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts/check_product_surface_contract.py")],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
