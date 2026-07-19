"""Tests for the cloud-SDK pin-drift signal + CI drift gate (issue #3835).

Complements ``test_cloud_sdk_freshness.py`` (installed-vs-floor + API
deprecation). This lane covers the *pin* level: is the version floor the repo
pins itself lagging the ecosystem, measured against a dated, provenance-carrying
in-repo reference — and does the CI gate fail when a pin falls behind that
reference while staying green on the current tree?

Honesty (§7): the signal never claims a pin is "current" without the dated
reference; a missing reference degrades to an explicit "unknown / last checked
never" rather than implying freshness.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agent_bom.cloud_sdk_freshness import (
    RECOMMENDED_FLOORS,
    REFERENCE_PATH,
    cloud_sdk_freshness_summary,
    cloud_sdk_pin_drift,
    evaluate_pin_reference_gate,
    load_sdk_reference,
    pyproject_sdk_floors,
)

ROOT = Path(__file__).resolve().parent.parent
DRIFT_SCRIPT = ROOT / "scripts" / "check_cloud_sdk_drift.py"


# ---------------------------------------------------------------------------
# Reference file + provenance
# ---------------------------------------------------------------------------


def test_shipped_reference_has_provenance_and_covers_every_anchor():
    ref = load_sdk_reference()
    assert ref, "shipped reference must load"
    # Provenance is mandatory: a dated retrieval + an official source.
    assert ref["retrieved"] and len(ref["retrieved"]) == 10  # ISO YYYY-MM-DD
    assert "pypi.org" in ref["source"]
    dists = {s["distribution"] for s in ref["sdks"]}
    for floor in RECOMMENDED_FLOORS:
        assert floor.distribution in dists, f"reference missing anchor {floor.distribution}"
    for sdk in ref["sdks"]:
        assert sdk["floor"] and sdk["known_latest"]
        assert sdk["floor_released"] and sdk["latest_released"]


def test_reference_ships_inside_the_data_dir():
    assert REFERENCE_PATH.name == "cloud_sdk_reference.json"
    assert REFERENCE_PATH.exists()


# ---------------------------------------------------------------------------
# Pin-drift signal
# ---------------------------------------------------------------------------


def test_pin_drift_flags_floors_behind_the_reference():
    # The shipped reference records real known-latest releases well ahead of the
    # pinned floors, so every anchor must read as "behind" and the aggregate as
    # stale — the honest signal the plain installed-vs-floor check is blind to.
    drift = cloud_sdk_pin_drift()
    assert drift["status"] == "stale"
    assert drift["behind_count"] == len(RECOMMENDED_FLOORS)
    boto = next(s for s in drift["sdks"] if s["distribution"] == "boto3")
    assert boto["status"] == "behind"
    assert boto["months_behind"] is not None and boto["months_behind"] > 12
    vb = boto["versions_behind"]
    assert vb["major"] >= 0 and vb["minor"] >= 1
    assert drift["warnings"]


def test_pin_drift_carries_reference_provenance():
    drift = cloud_sdk_pin_drift()
    ref = load_sdk_reference()
    assert drift["retrieved"] == ref["retrieved"]
    assert drift["last_checked"] == ref["retrieved"]
    assert "pypi.org" in drift["source"]
    # Provenance is echoed per-SDK too so a single row is self-describing.
    for sdk in drift["sdks"]:
        assert sdk["retrieved"] == ref["retrieved"]


def test_pin_drift_current_when_floor_matches_latest_minor():
    ref = {
        "retrieved": "2026-07-18",
        "source": "https://pypi.org/pypi/{distribution}/json",
        "sdks": [
            {
                "provider": "aws",
                "distribution": "boto3",
                "floor": "1.34",
                "floor_released": "2026-07-01",
                "known_latest": "1.34.9",
                "latest_released": "2026-07-17",
            }
        ],
    }
    only = (next(f for f in RECOMMENDED_FLOORS if f.distribution == "boto3"),)
    drift = cloud_sdk_pin_drift(reference=ref, floors=only)
    assert drift["status"] == "ok"
    assert drift["behind_count"] == 0
    assert drift["sdks"][0]["status"] == "current"


def test_pin_drift_without_reference_is_unknown_never_current():
    # Offline honesty: with no dated reference we must NOT imply freshness.
    drift = cloud_sdk_pin_drift(reference={})
    assert drift["status"] == "unknown"
    assert drift["last_checked"] is None
    assert all(s["status"] == "unknown" for s in drift["sdks"])
    assert all(s["status"] != "current" for s in drift["sdks"])
    joined = " ".join(s["message"] for s in drift["sdks"]).lower()
    assert "reference" in joined and "never" in joined


# ---------------------------------------------------------------------------
# CI drift gate (pure logic)
# ---------------------------------------------------------------------------


def test_pin_gate_passes_on_current_tree():
    # pyproject floors and the shipped reference are in lockstep today.
    gate = evaluate_pin_reference_gate(pyproject_floors=pyproject_sdk_floors())
    assert gate["ok"] is True, gate["violations"]
    assert gate["violations"] == []
    assert gate["checked"] == len(RECOMMENDED_FLOORS)


def test_pin_gate_fails_when_a_pin_falls_behind_the_reference():
    ref = {
        "retrieved": "2026-07-18",
        "source": "https://pypi.org/pypi/{distribution}/json",
        "sdks": [
            {
                "provider": "aws",
                "distribution": "boto3",
                "floor": "1.50",
                "floor_released": "2026-07-01",
                "known_latest": "1.50.0",
                "latest_released": "2026-07-17",
            }
        ],
    }
    floors = {f.distribution: f.floor for f in RECOMMENDED_FLOORS}
    gate = evaluate_pin_reference_gate(pyproject_floors=floors, reference=ref)
    assert gate["ok"] is False
    codes = {v["code"] for v in gate["violations"]}
    assert "below_reference" in codes
    boto = next(v for v in gate["violations"] if v["distribution"] == "boto3")
    assert boto["pyproject_floor"] == "1.34"
    assert boto["reference_floor"] == "1.50"


def test_pin_gate_fails_when_pyproject_drops_an_anchor():
    floors = {f.distribution: f.floor for f in RECOMMENDED_FLOORS if f.distribution != "boto3"}
    gate = evaluate_pin_reference_gate(pyproject_floors=floors)
    assert gate["ok"] is False
    codes = {v["code"] for v in gate["violations"]}
    assert "missing_in_pyproject" in codes


def test_pyproject_floors_match_recommended_anchors():
    floors = pyproject_sdk_floors()
    for anchor in RECOMMENDED_FLOORS:
        assert floors.get(anchor.distribution) == anchor.floor


# ---------------------------------------------------------------------------
# CI drift-check script
# ---------------------------------------------------------------------------


def test_drift_script_exits_zero_on_current_tree():
    proc = subprocess.run(
        [sys.executable, str(DRIFT_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_drift_script_exits_nonzero_when_pin_below_reference(tmp_path):
    ref = {
        "retrieved": "2026-07-18",
        "source": "https://pypi.org/pypi/{distribution}/json",
        "sdks": [
            {
                "provider": "aws",
                "distribution": "boto3",
                "floor": "9.99",
                "floor_released": "2026-07-01",
                "known_latest": "9.99.0",
                "latest_released": "2026-07-17",
            }
        ],
    }
    ref_file = tmp_path / "ref.json"
    ref_file.write_text(json.dumps(ref))
    proc = subprocess.run(
        [sys.executable, str(DRIFT_SCRIPT), "--reference", str(ref_file)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "below_reference" in (proc.stdout + proc.stderr)


# ---------------------------------------------------------------------------
# Consumer surfaces (wire-align)
# ---------------------------------------------------------------------------


def test_agent_mode_summary_nests_pin_drift():
    summary = cloud_sdk_freshness_summary(installed=None)
    assert "pin_drift" in summary
    assert summary["pin_drift"]["status"] in {"ok", "stale", "unknown"}


def test_doctor_renders_pin_drift_section():
    from click.testing import CliRunner

    from agent_bom.cli._doctor import doctor_cmd

    result = CliRunner().invoke(doctor_cmd, [])
    assert result.exit_code == 0, result.output
    assert "Cloud SDK pin drift" in result.output
