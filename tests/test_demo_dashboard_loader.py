from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_demo_loader_is_valid_shell() -> None:
    subprocess.run(["bash", "-n", str(ROOT / "scripts" / "demo" / "load-dashboard-demo.sh")], check=True)
