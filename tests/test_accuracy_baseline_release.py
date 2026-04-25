from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agent_bom.accuracy_baseline import build_accuracy_baseline

ROOT = Path(__file__).resolve().parents[1]


def test_accuracy_baseline_has_release_accounting() -> None:
    baseline = build_accuracy_baseline()

    assert baseline["schema_version"] == "accuracy-baseline/v1"
    assert baseline["scope"]["release_gate"] is True
    assert baseline["runtime_red_team"]["attack_cases"] == 17
    assert baseline["runtime_red_team"]["benign_cases"] == 2
    assert baseline["runtime_red_team"]["missed_attacks"] == 0
    assert baseline["runtime_red_team"]["false_positives"] == 0
    assert "vex_suppressed" in baseline["finding_state_accounting"]
    assert "fixed_verified" in baseline["finding_state_accounting"]


def test_checked_in_accuracy_baseline_is_current() -> None:
    checked_in = json.loads((ROOT / "docs" / "accuracy-baseline.json").read_text(encoding="utf-8"))
    assert checked_in == build_accuracy_baseline()


def test_accuracy_baseline_check_command_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_accuracy_baseline.py", "--check"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
