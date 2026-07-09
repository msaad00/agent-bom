from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_smoke_script_is_valid_shell() -> None:
    subprocess.run(["bash", "-n", str(ROOT / "scripts" / "release_smoke.sh")], check=True)


def test_release_smoke_golden_path(tmp_path: Path) -> None:
    """Offline demo scan smoke must pass on every CI run."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env.update(
        {
            "AGENT_BOM_RELEASE_SMOKE_SKIP_UI": "1",
            "AGENT_BOM_STATE_DIR": str(tmp_path / "release-smoke-state"),
        }
    )
    subprocess.run(
        ["bash", str(ROOT / "scripts" / "release_smoke.sh")],
        check=True,
        cwd=ROOT,
        env=env,
    )
