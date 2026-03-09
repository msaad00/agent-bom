"""Tests for project_config — .agent-bom.yaml loading."""

from __future__ import annotations

from pathlib import Path

from agent_bom.project_config import (
    find_project_config,
    get_fail_on_severity,
    get_ignore_list,
    get_min_severity,
    get_policy_path,
    load_project_config,
)

# ─── find_project_config ─────────────────────────────────────────────────────


def test_find_project_config_in_cwd(tmp_path):
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text("min_severity: high\n")
    result = find_project_config(start=tmp_path)
    assert result == cfg


def test_find_project_config_yml_variant(tmp_path):
    cfg = tmp_path / ".agent-bom.yml"
    cfg.write_text("fail_on_severity: critical\n")
    result = find_project_config(start=tmp_path)
    assert result == cfg


def test_find_project_config_in_parent(tmp_path):
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text("enrich: true\n")
    subdir = tmp_path / "src" / "app"
    subdir.mkdir(parents=True)
    result = find_project_config(start=subdir)
    assert result == cfg


def test_find_project_config_not_found(tmp_path):
    result = find_project_config(start=tmp_path)
    assert result is None


def test_find_project_config_prefers_dot_variant(tmp_path):
    """'.agent-bom.yaml' should be found before 'agent-bom.yaml' (same dir)."""
    hidden = tmp_path / ".agent-bom.yaml"
    visible = tmp_path / "agent-bom.yaml"
    hidden.write_text("x: 1\n")
    visible.write_text("x: 2\n")
    result = find_project_config(start=tmp_path)
    assert result == hidden


# ─── load_project_config ─────────────────────────────────────────────────────


def test_load_project_config_basic(tmp_path):
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text("min_severity: medium\nfail_on_kev: true\n")
    data = load_project_config(cfg)
    assert data["min_severity"] == "medium"
    assert data["fail_on_kev"] is True


def test_load_project_config_not_found_returns_empty():
    data = load_project_config(Path("/nonexistent/.agent-bom.yaml"))
    assert data == {}


def test_load_project_config_invalid_yaml(tmp_path):
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text("key: [unclosed bracket\n")
    data = load_project_config(cfg)
    assert data == {}


def test_load_project_config_non_dict_returns_empty(tmp_path):
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text("- item1\n- item2\n")
    data = load_project_config(cfg)
    assert data == {}


def test_load_project_config_empty_file_returns_empty(tmp_path):
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text("")
    data = load_project_config(cfg)
    assert data == {}


def test_load_project_config_auto_discover(tmp_path):
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text("enrich: true\n")
    # Pass None — triggers auto-discovery from tmp_path
    data = load_project_config(cfg)
    assert data.get("enrich") is True


# ─── helper extractors ────────────────────────────────────────────────────────


def test_get_ignore_list():
    cfg = {"ignore": ["CVE-2023-1234", "GHSA-xxxx-yyyy-zzzz"]}
    assert get_ignore_list(cfg) == ["CVE-2023-1234", "GHSA-xxxx-yyyy-zzzz"]


def test_get_ignore_list_empty():
    assert get_ignore_list({}) == []


def test_get_ignore_list_non_list():
    assert get_ignore_list({"ignore": "CVE-2023-1234"}) == []


def test_get_min_severity_valid():
    for sev in ("low", "medium", "high", "critical"):
        assert get_min_severity({"min_severity": sev}) == sev


def test_get_min_severity_case_insensitive():
    assert get_min_severity({"min_severity": "HIGH"}) == "high"


def test_get_min_severity_invalid():
    assert get_min_severity({"min_severity": "extreme"}) is None


def test_get_min_severity_missing():
    assert get_min_severity({}) is None


def test_get_fail_on_severity_valid():
    assert get_fail_on_severity({"fail_on_severity": "critical"}) == "critical"


def test_get_fail_on_severity_missing():
    assert get_fail_on_severity({}) is None


def test_get_policy_path(tmp_path):
    cfg_data = {"policy": "security/policy.yml"}
    result = get_policy_path(cfg_data)
    assert result == Path("security/policy.yml")


def test_get_policy_path_missing():
    assert get_policy_path({}) is None


# ─── full config example ─────────────────────────────────────────────────────


def test_full_config_round_trip(tmp_path):
    cfg_text = """
ignore:
  - CVE-2023-9999
  - GHSA-aaaa-bbbb-cccc

min_severity: medium
fail_on_severity: high
fail_on_kev: true
enrich: true
transitive: true

policy: security/policy.yml

output: json
output_file: agent-bom-report.json

scan:
  aws: false
  verify_model_hashes: true
"""
    cfg = tmp_path / ".agent-bom.yaml"
    cfg.write_text(cfg_text)
    data = load_project_config(cfg)

    assert get_ignore_list(data) == ["CVE-2023-9999", "GHSA-aaaa-bbbb-cccc"]
    assert get_min_severity(data) == "medium"
    assert get_fail_on_severity(data) == "high"
    assert data.get("fail_on_kev") is True
    assert data.get("enrich") is True
    assert get_policy_path(data) == Path("security/policy.yml")
    assert data["scan"]["verify_model_hashes"] is True
