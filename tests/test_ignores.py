"""Tests for the .agent-bom-ignore.yaml allowlist feature (#576)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.ignores import _entry_is_expired, apply_ignores, load_ignore_file

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_blast_radius(cve_id="CVE-2024-1234", pkg_name="requests", version="2.28.0", credentials=None):
    br = MagicMock()
    br.vulnerability.id = cve_id
    br.package.name = pkg_name
    br.package.version = version
    br.exposed_credentials = credentials or []
    br.affected_agents = []
    return br


# ---------------------------------------------------------------------------
# load_ignore_file
# ---------------------------------------------------------------------------


def test_load_ignore_file_not_found():
    assert load_ignore_file("/nonexistent/.agent-bom-ignore.yaml") == []


def test_load_ignore_file_json_fallback(tmp_path):
    f = tmp_path / "ignores.json"
    f.write_text(json.dumps({"ignores": [{"id": "CVE-2024-9999", "reason": "test"}]}))
    entries = load_ignore_file(f)
    assert len(entries) == 1
    assert entries[0]["id"] == "CVE-2024-9999"


def test_load_ignore_file_yaml(tmp_path):
    pytest.importorskip("yaml")
    f = tmp_path / ".agent-bom-ignore.yaml"
    f.write_text("ignores:\n  - id: CVE-2024-1111\n    reason: test\n")
    entries = load_ignore_file(f)
    assert len(entries) == 1
    assert entries[0]["id"] == "CVE-2024-1111"


def test_load_ignore_file_invalid_yaml_raises(tmp_path):
    pytest.importorskip("yaml")
    f = tmp_path / ".agent-bom-ignore.yaml"
    f.write_text("ignores:\n  - id: [unterminated\n")
    with pytest.raises(ValueError, match="Invalid YAML in ignore file"):
        load_ignore_file(f)


def test_load_ignore_file_requires_mapping_top_level(tmp_path):
    pytest.importorskip("yaml")
    f = tmp_path / ".agent-bom-ignore.yaml"
    f.write_text("- id: CVE-2024-1111\n  reason: test\n")
    with pytest.raises(ValueError, match="must be a YAML mapping"):
        load_ignore_file(f)


def test_load_ignore_file_requires_ignores_list(tmp_path):
    pytest.importorskip("yaml")
    f = tmp_path / ".agent-bom-ignore.yaml"
    f.write_text("ignores: nope\n")
    with pytest.raises(ValueError, match="field 'ignores' must be a list"):
        load_ignore_file(f)


def test_load_ignore_file_default_name(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    monkeypatch.chdir(tmp_path)
    f = tmp_path / ".agent-bom-ignore.yaml"
    f.write_text("ignores:\n  - id: CVE-2024-2222\n    reason: default path test\n")
    entries = load_ignore_file(None)
    assert entries[0]["id"] == "CVE-2024-2222"


# ---------------------------------------------------------------------------
# _entry_is_expired
# ---------------------------------------------------------------------------


def test_not_expired_no_date():
    assert _entry_is_expired({}) is False


def test_not_expired_future_date():
    assert _entry_is_expired({"expires": "2099-12-31"}) is False


def test_expired_past_date():
    assert _entry_is_expired({"expires": "2020-01-01"}) is True


def test_invalid_expires_treated_as_not_expired():
    assert _entry_is_expired({"expires": "not-a-date"}) is False


# ---------------------------------------------------------------------------
# apply_ignores — CVE ID match
# ---------------------------------------------------------------------------


def test_cve_id_match_suppresses():
    br = _make_blast_radius(cve_id="CVE-2024-1234")
    entries = [{"id": "CVE-2024-1234", "reason": "accepted"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 1
    assert filtered == []


def test_cve_id_case_insensitive():
    br = _make_blast_radius(cve_id="CVE-2024-1234")
    entries = [{"id": "cve-2024-1234", "reason": "lower case test"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 1


def test_cve_id_no_match_passes_through():
    br = _make_blast_radius(cve_id="CVE-2024-9999")
    entries = [{"id": "CVE-2024-1234", "reason": "different CVE"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 0
    assert len(filtered) == 1


# ---------------------------------------------------------------------------
# apply_ignores — package name match
# ---------------------------------------------------------------------------


def test_package_name_match_all_versions():
    br = _make_blast_radius(pkg_name="requests", version="2.28.0")
    entries = [{"package": "requests", "reason": "all versions accepted"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 1


def test_package_name_version_lt_match():
    br = _make_blast_radius(pkg_name="requests", version="2.28.0")
    entries = [{"package": "requests@<2.32.0", "reason": "below fix"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 1


def test_package_name_version_lt_no_match():
    br = _make_blast_radius(pkg_name="requests", version="2.32.0")
    entries = [{"package": "requests@<2.32.0", "reason": "below fix"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 0


def test_package_name_mismatch():
    br = _make_blast_radius(pkg_name="urllib3", version="1.26.0")
    entries = [{"package": "requests", "reason": "wrong package"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 0


# ---------------------------------------------------------------------------
# apply_ignores — expiry
# ---------------------------------------------------------------------------


def test_expired_entry_does_not_suppress():
    br = _make_blast_radius(cve_id="CVE-2024-1234")
    entries = [{"id": "CVE-2024-1234", "reason": "expired", "expires": "2020-01-01"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 0
    assert len(filtered) == 1


def test_future_expiry_still_suppresses():
    br = _make_blast_radius(cve_id="CVE-2024-1234")
    entries = [{"id": "CVE-2024-1234", "reason": "future", "expires": "2099-01-01"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 1


# ---------------------------------------------------------------------------
# apply_ignores — credential-exposure type
# ---------------------------------------------------------------------------


def test_credential_type_match():
    br = _make_blast_radius(credentials=["AWS_SECRET_ACCESS_KEY"])
    entries = [{"type": "credential-exposure", "reason": "test creds"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 1


def test_credential_type_no_match_when_no_creds():
    br = _make_blast_radius(credentials=[])
    entries = [{"type": "credential-exposure", "reason": "no creds here"}]
    filtered, suppressed = apply_ignores([br], entries)
    assert suppressed == 0


# ---------------------------------------------------------------------------
# apply_ignores — empty / no entries
# ---------------------------------------------------------------------------


def test_empty_entries_passthrough():
    brs = [_make_blast_radius(), _make_blast_radius(cve_id="CVE-2024-5678")]
    filtered, suppressed = apply_ignores(brs, [])
    assert suppressed == 0
    assert len(filtered) == 2


def test_multiple_findings_partial_suppress():
    br1 = _make_blast_radius(cve_id="CVE-2024-1111")
    br2 = _make_blast_radius(cve_id="CVE-2024-2222")
    entries = [{"id": "CVE-2024-1111", "reason": "suppress only one"}]
    filtered, suppressed = apply_ignores([br1, br2], entries)
    assert suppressed == 1
    assert len(filtered) == 1
    assert filtered[0].vulnerability.id == "CVE-2024-2222"


# ---------------------------------------------------------------------------
# CLI integration — --ignore-file flag is accepted
# ---------------------------------------------------------------------------


def test_scan_ignore_file_flag_accepted(tmp_path):
    from click.testing import CliRunner

    from agent_bom.cli import main

    ignore_f = tmp_path / ".agent-bom-ignore.yaml"
    ignore_f.write_text("ignores: []\n")

    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = CliRunner().invoke(main, ["scan", "--demo", "--ignore-file", str(ignore_f), "--no-scan"])
    assert result.exit_code == 0
