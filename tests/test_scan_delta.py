"""Tests for delta scanning (issue #577)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agent_bom.scan_delta import (
    DeltaResult,
    apply_delta_to_scan,
    compute_delta,
    extract_delta_keys,
    load_baseline,
    save_baseline,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan_json(*blast_items) -> dict:
    """Build a minimal scan JSON dict with the given blast_radius items."""
    return {
        "document_type": "AI-BOM",
        "summary": {"total_vulnerabilities": len(blast_items)},
        "blast_radius": list(blast_items),
    }


def _br(vuln_id: str, pkg: str = "requests@2.0.0", severity: str = "high") -> dict:
    return {
        "vulnerability_id": vuln_id,
        "package": pkg,
        "severity": severity,
        "risk_score": 7.0,
        "fixed_version": "2.1.0",
    }


# ---------------------------------------------------------------------------
# extract_delta_keys
# ---------------------------------------------------------------------------


def test_extract_delta_keys_basic():
    scan = _scan_json(_br("CVE-2024-001"), _br("CVE-2024-002", "flask@1.0.0"))
    keys = extract_delta_keys(scan)
    assert ("CVE-2024-001", "requests", "2.0.0") in keys
    assert ("CVE-2024-002", "flask", "1.0.0") in keys


def test_extract_delta_keys_empty_scan():
    assert extract_delta_keys({"blast_radius": []}) == set()


def test_extract_delta_keys_normalizes_vuln_id_to_upper():
    scan = _scan_json(_br("cve-2024-001"))
    keys = extract_delta_keys(scan)
    assert ("CVE-2024-001", "requests", "2.0.0") in keys


def test_extract_delta_keys_skips_malformed():
    scan = {"blast_radius": [{"vulnerability_id": "", "package": "foo@1.0"}]}
    keys = extract_delta_keys(scan)
    assert len(keys) == 0


def test_extract_delta_keys_package_without_version():
    scan = _scan_json({"vulnerability_id": "CVE-2024-001", "package": "requests", "severity": "high"})
    keys = extract_delta_keys(scan)
    assert ("CVE-2024-001", "requests", "") in keys


# ---------------------------------------------------------------------------
# compute_delta
# ---------------------------------------------------------------------------


def test_compute_delta_all_new():
    current = _scan_json(_br("CVE-2024-001"), _br("CVE-2024-002"))
    baseline = _scan_json()  # empty baseline
    result = compute_delta(current, baseline)
    assert result.new_count == 2
    assert result.pre_existing_count == 0
    assert result.has_new is True


def test_compute_delta_all_pre_existing():
    item = _br("CVE-2024-001")
    current = _scan_json(item)
    baseline = _scan_json(item)
    result = compute_delta(current, baseline)
    assert result.new_count == 0
    assert result.pre_existing_count == 1
    assert result.has_new is False


def test_compute_delta_mixed():
    old_item = _br("CVE-2024-001")
    new_item = _br("CVE-2024-002")
    current = _scan_json(old_item, new_item)
    baseline = _scan_json(old_item)
    result = compute_delta(current, baseline)
    assert result.new_count == 1
    assert result.pre_existing_count == 1
    assert result.new_items[0]["vulnerability_id"] == "CVE-2024-002"


def test_compute_delta_same_vuln_different_package_is_new():
    item_a = _br("CVE-2024-001", pkg="flask@1.0.0")
    item_b = _br("CVE-2024-001", pkg="requests@2.0.0")  # same CVE, different pkg
    current = _scan_json(item_b)
    baseline = _scan_json(item_a)
    result = compute_delta(current, baseline)
    assert result.new_count == 1  # requests not in baseline
    assert result.pre_existing_count == 0


def test_compute_delta_case_insensitive_vuln_id():
    """CVE ID comparison should be case-insensitive."""
    current = _scan_json(_br("cve-2024-001"))
    baseline = _scan_json(_br("CVE-2024-001"))
    result = compute_delta(current, baseline)
    assert result.new_count == 0
    assert result.pre_existing_count == 1


# ---------------------------------------------------------------------------
# DeltaResult
# ---------------------------------------------------------------------------


def test_delta_result_summary_line_new_only():
    result = DeltaResult(new_items=[_br("CVE-X")], pre_existing_items=[], baseline_path=None)
    assert "1 new" in result.summary_line()
    assert "pre-existing" not in result.summary_line()


def test_delta_result_summary_line_mixed():
    result = DeltaResult(
        new_items=[_br("CVE-X")],
        pre_existing_items=[_br("CVE-Y")],
        baseline_path=None,
    )
    assert "1 new" in result.summary_line()
    assert "pre-existing" in result.summary_line()


def test_delta_result_summary_line_clean():
    result = DeltaResult(new_items=[], pre_existing_items=[], baseline_path=None)
    assert result.summary_line() == "No findings (delta clean)"


# ---------------------------------------------------------------------------
# apply_delta_to_scan
# ---------------------------------------------------------------------------


def test_apply_delta_to_scan_replaces_blast_radius():
    original = _scan_json(_br("CVE-2024-001"), _br("CVE-2024-002"))
    delta = DeltaResult(
        new_items=[_br("CVE-2024-002")],
        pre_existing_items=[_br("CVE-2024-001")],
        baseline_path="/tmp/baseline.json",
    )
    result = apply_delta_to_scan(original, delta)
    assert len(result["blast_radius"]) == 1
    assert result["blast_radius"][0]["vulnerability_id"] == "CVE-2024-002"


def test_apply_delta_to_scan_adds_delta_section():
    original = _scan_json(_br("CVE-2024-001"))
    delta = DeltaResult(new_items=[_br("CVE-2024-001")], pre_existing_items=[], baseline_path="/b.json")
    result = apply_delta_to_scan(original, delta)
    assert result["delta"]["enabled"] is True
    assert result["delta"]["new_count"] == 1
    assert result["delta"]["pre_existing_count"] == 0
    assert result["delta"]["baseline_path"] == "/b.json"


def test_apply_delta_to_scan_does_not_mutate_original():
    original = _scan_json(_br("CVE-2024-001"))
    original_len = len(original["blast_radius"])
    delta = DeltaResult(new_items=[], pre_existing_items=[_br("CVE-2024-001")], baseline_path=None)
    apply_delta_to_scan(original, delta)
    assert len(original["blast_radius"]) == original_len  # not mutated


def test_apply_delta_updates_summary_count():
    original = _scan_json(_br("CVE-2024-001"), _br("CVE-2024-002"))
    delta = DeltaResult(new_items=[_br("CVE-2024-002")], pre_existing_items=[_br("CVE-2024-001")], baseline_path=None)
    result = apply_delta_to_scan(original, delta)
    assert result["summary"]["total_vulnerabilities"] == 1


# ---------------------------------------------------------------------------
# load_baseline and save_baseline
# ---------------------------------------------------------------------------


def test_load_baseline_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_baseline("/nonexistent/path/baseline.json")


def test_load_baseline_invalid_json():
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write("not json {{")
        name = f.name
    with pytest.raises(ValueError, match="not valid JSON"):
        load_baseline(name)


def test_load_baseline_missing_blast_radius_key():
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump({"document_type": "other"}, f)
        name = f.name
    with pytest.raises(ValueError, match="missing 'blast_radius'"):
        load_baseline(name)


def test_load_baseline_valid():
    data = _scan_json(_br("CVE-2024-001"))
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(data, f)
        name = f.name
    loaded = load_baseline(name)
    assert loaded["blast_radius"][0]["vulnerability_id"] == "CVE-2024-001"


def test_save_baseline_writes_file():
    data = _scan_json(_br("CVE-2024-001"))
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "baseline.json"
        written = save_baseline(data, path)
        assert written == path
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded["blast_radius"][0]["vulnerability_id"] == "CVE-2024-001"


def test_save_baseline_creates_parent_dirs():
    data = _scan_json()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "deep" / "nested" / "baseline.json"
        save_baseline(data, path)
        assert path.exists()
