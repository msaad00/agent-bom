"""Tests for CWE-aware impact classification engine."""

from __future__ import annotations

from agent_bom.cwe_impact import (
    IMPACT_AVAILABILITY,
    IMPACT_CLIENT_SIDE,
    IMPACT_CODE_EXECUTION,
    IMPACT_CREDENTIAL_ACCESS,
    IMPACT_DATA_LEAK,
    IMPACT_FILE_ACCESS,
    IMPACT_INJECTION,
    IMPACT_SSRF,
    build_attack_vector_summary,
    classify_cwe_impact,
    filter_credentials_by_impact,
    filter_tools_by_impact,
)

# ── classify_cwe_impact ──────────────────────────────────────────────────────


def test_no_cwe_returns_code_execution():
    """Conservative default: no CWE data assumes worst case."""
    assert classify_cwe_impact([]) == IMPACT_CODE_EXECUTION


def test_unknown_cwe_returns_code_execution():
    """Unrecognized CWE IDs assume worst case."""
    assert classify_cwe_impact(["CWE-999999"]) == IMPACT_CODE_EXECUTION


def test_single_rce_cwe():
    assert classify_cwe_impact(["CWE-94"]) == IMPACT_CODE_EXECUTION


def test_single_xss_cwe():
    assert classify_cwe_impact(["CWE-79"]) == IMPACT_CLIENT_SIDE


def test_single_dos_cwe():
    assert classify_cwe_impact(["CWE-400"]) == IMPACT_AVAILABILITY


def test_single_sqli_cwe():
    assert classify_cwe_impact(["CWE-89"]) == IMPACT_INJECTION


def test_single_ssrf_cwe():
    assert classify_cwe_impact(["CWE-918"]) == IMPACT_SSRF


def test_single_path_traversal():
    assert classify_cwe_impact(["CWE-22"]) == IMPACT_FILE_ACCESS


def test_single_auth_bypass():
    assert classify_cwe_impact(["CWE-287"]) == IMPACT_CREDENTIAL_ACCESS


def test_single_info_disclosure():
    assert classify_cwe_impact(["CWE-200"]) == IMPACT_DATA_LEAK


def test_mixed_cwes_returns_worst_case():
    """When multiple CWEs present, return the most severe."""
    # XSS + RCE → RCE wins
    assert classify_cwe_impact(["CWE-79", "CWE-94"]) == IMPACT_CODE_EXECUTION


def test_mixed_dos_and_sqli():
    # DoS + SQL injection → injection wins (more severe)
    assert classify_cwe_impact(["CWE-400", "CWE-89"]) == IMPACT_INJECTION


def test_mixed_client_side_and_data_leak():
    # XSS + info disclosure → data-leak wins
    assert classify_cwe_impact(["CWE-79", "CWE-200"]) == IMPACT_DATA_LEAK


def test_mixed_unknown_and_known():
    # Unknown + XSS → XSS (don't escalate just because one is unknown)
    assert classify_cwe_impact(["CWE-999999", "CWE-79"]) == IMPACT_CLIENT_SIDE


def test_deserialization_is_code_execution():
    assert classify_cwe_impact(["CWE-502"]) == IMPACT_CODE_EXECUTION


def test_prototype_pollution_is_code_execution():
    assert classify_cwe_impact(["CWE-1321"]) == IMPACT_CODE_EXECUTION


def test_hardcoded_credentials():
    assert classify_cwe_impact(["CWE-798"]) == IMPACT_CREDENTIAL_ACCESS


def test_csrf_is_client_side():
    assert classify_cwe_impact(["CWE-352"]) == IMPACT_CLIENT_SIDE


def test_redos_is_availability():
    assert classify_cwe_impact(["CWE-1333"]) == IMPACT_AVAILABILITY


# ── filter_credentials_by_impact ─────────────────────────────────────────────

_TEST_CREDS = ["DATABASE_URL", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "SLACK_WEBHOOK"]


def test_code_execution_returns_all_creds():
    result = filter_credentials_by_impact(IMPACT_CODE_EXECUTION, _TEST_CREDS)
    assert set(result) == set(_TEST_CREDS)


def test_credential_access_returns_all_creds():
    result = filter_credentials_by_impact(IMPACT_CREDENTIAL_ACCESS, _TEST_CREDS)
    assert set(result) == set(_TEST_CREDS)


def test_client_side_returns_no_creds():
    result = filter_credentials_by_impact(IMPACT_CLIENT_SIDE, _TEST_CREDS)
    assert result == []


def test_availability_returns_no_creds():
    result = filter_credentials_by_impact(IMPACT_AVAILABILITY, _TEST_CREDS)
    assert result == []


def test_injection_returns_only_db_creds():
    result = filter_credentials_by_impact(IMPACT_INJECTION, _TEST_CREDS)
    assert "DATABASE_URL" in result
    assert "GITHUB_TOKEN" not in result
    assert "ANTHROPIC_API_KEY" not in result


def test_injection_with_postgres_cred():
    creds = ["POSTGRES_PASSWORD", "SLACK_TOKEN", "MONGO_URI"]
    result = filter_credentials_by_impact(IMPACT_INJECTION, creds)
    assert "POSTGRES_PASSWORD" in result
    assert "MONGO_URI" in result
    assert "SLACK_TOKEN" not in result


def test_file_access_returns_all_creds():
    """File access can read .env files — all credentials potentially exposed."""
    result = filter_credentials_by_impact(IMPACT_FILE_ACCESS, _TEST_CREDS)
    assert set(result) == set(_TEST_CREDS)


def test_ssrf_returns_all_creds():
    result = filter_credentials_by_impact(IMPACT_SSRF, _TEST_CREDS)
    assert set(result) == set(_TEST_CREDS)


def test_data_leak_returns_all_creds():
    result = filter_credentials_by_impact(IMPACT_DATA_LEAK, _TEST_CREDS)
    assert set(result) == set(_TEST_CREDS)


def test_empty_creds_returns_empty():
    result = filter_credentials_by_impact(IMPACT_CODE_EXECUTION, [])
    assert result == []


# ── filter_tools_by_impact ───────────────────────────────────────────────────


class _MockTool:
    def __init__(self, name: str):
        self.name = name


_TEST_TOOLS = [_MockTool("run_query"), _MockTool("execute_sql"), _MockTool("read_file"), _MockTool("send_message")]


def test_code_execution_returns_all_tools():
    result = filter_tools_by_impact(IMPACT_CODE_EXECUTION, _TEST_TOOLS)
    assert len(result) == 4


def test_client_side_returns_no_tools():
    result = filter_tools_by_impact(IMPACT_CLIENT_SIDE, _TEST_TOOLS)
    assert result == []


def test_availability_returns_no_tools():
    result = filter_tools_by_impact(IMPACT_AVAILABILITY, _TEST_TOOLS)
    assert result == []


def test_injection_returns_only_db_tools():
    result = filter_tools_by_impact(IMPACT_INJECTION, _TEST_TOOLS)
    names = [t.name for t in result]
    assert "run_query" in names
    assert "execute_sql" in names
    assert "read_file" not in names
    assert "send_message" not in names


def test_empty_tools_returns_empty():
    result = filter_tools_by_impact(IMPACT_CODE_EXECUTION, [])
    assert result == []


# ── build_attack_vector_summary ──────────────────────────────────────────────


def test_rce_summary():
    summary = build_attack_vector_summary(
        ["CWE-94"],
        IMPACT_CODE_EXECUTION,
        ["DB_URL", "API_KEY"],
        [_MockTool("run")],
    )
    assert "Code execution" in summary
    assert "CWE-94" in summary
    assert "2 credential(s)" in summary


def test_xss_summary():
    summary = build_attack_vector_summary(["CWE-79"], IMPACT_CLIENT_SIDE, [], [])
    assert "Client-side" in summary
    assert "Does not expose server-side credentials" in summary


def test_dos_summary():
    summary = build_attack_vector_summary(["CWE-400"], IMPACT_AVAILABILITY, [], [])
    assert "Denial of service" in summary
    assert "Does not expose credentials" in summary


def test_kev_prefix():
    summary = build_attack_vector_summary(
        ["CWE-94"],
        IMPACT_CODE_EXECUTION,
        ["KEY"],
        [],
        is_kev=True,
    )
    assert summary.startswith("Actively exploited.")


def test_no_cwe_summary():
    summary = build_attack_vector_summary([], IMPACT_CODE_EXECUTION, [], [])
    assert "Unknown CWE" in summary


def test_injection_summary_with_db_creds():
    summary = build_attack_vector_summary(
        ["CWE-89"],
        IMPACT_INJECTION,
        ["DATABASE_URL"],
        [_MockTool("query")],
    )
    assert "Injection" in summary
    assert "1 database credential(s)" in summary
