from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_smoke_script_is_valid_shell() -> None:
    subprocess.run(["bash", "-n", str(ROOT / "scripts" / "release_smoke.sh")], check=True)


def test_release_smoke_golden_path() -> None:
    """Offline demo scan smoke must pass on every CI run."""
    subprocess.run(
        ["bash", str(ROOT / "scripts" / "release_smoke.sh")],
        check=True,
        cwd=ROOT,
        env={
            **dict(__import__("os").environ),
            "AGENT_BOM_RELEASE_SMOKE_SKIP_UI": "1",
        },
    )
