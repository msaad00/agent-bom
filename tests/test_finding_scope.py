"""Tests for first-class finding scope + security-domain taxonomy (issue #3946)."""

from __future__ import annotations

from agent_bom.finding import (
    Asset,
    Finding,
    FindingSource,
    FindingType,
    cloud_cis_check_to_finding,
    snowflake_governance_finding_to_finding,
)
from agent_bom.finding_scope import (
    account_ref_from_arn,
    normalize_account_ref,
    region_from_arn,
    security_domain_for,
)

# ---------------------------------------------------------------------------
# Account-ref / ARN normalization
# ---------------------------------------------------------------------------


def test_account_ref_from_aws_arn() -> None:
    arn = "arn:aws:s3:::my-bucket"
    # S3 ARNs carry no account segment; fall back to None
    assert account_ref_from_arn(arn) is None
    ec2 = "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc"
    assert account_ref_from_arn(ec2) == "123456789012"
    assert region_from_arn(ec2) == "us-east-1"


def test_normalize_account_ref_adds_provider_prefix() -> None:
    assert normalize_account_ref("aws", "123456789012") == "aws:123456789012"
    assert normalize_account_ref("azure", "sub-uuid-1") == "azure:sub-uuid-1"
    assert normalize_account_ref("gcp", "my-project") == "gcp:my-project"


def test_normalize_account_ref_idempotent_when_prefixed() -> None:
    assert normalize_account_ref("aws", "aws:123456789012") == "aws:123456789012"
    # provider casing is normalized
    assert normalize_account_ref("AWS", "123456789012") == "aws:123456789012"


def test_normalize_account_ref_none_and_empty() -> None:
    assert normalize_account_ref("aws", None) is None
    assert normalize_account_ref("aws", "") is None
    assert normalize_account_ref("", "123") is None


# ---------------------------------------------------------------------------
# FindingSource / FindingType -> security_domain
# ---------------------------------------------------------------------------


def test_domain_cloud_cis_is_cspm() -> None:
    assert security_domain_for(FindingSource.CLOUD_CIS, FindingType.CIS_FAIL, {"benchmark": "CIS"}) == "cspm"


def test_domain_dependency_cve_is_vuln() -> None:
    assert security_domain_for(FindingSource.MCP_SCAN, FindingType.CVE) == "vuln"
    assert security_domain_for(FindingSource.SBOM, FindingType.CVE) == "vuln"
    assert security_domain_for(FindingSource.CONTAINER, FindingType.CVE) == "vuln"
    assert security_domain_for(FindingSource.MCP_SCAN, FindingType.MALICIOUS_PACKAGE) == "vuln"


def test_domain_sast_and_secret_is_appsec_sca() -> None:
    assert security_domain_for(FindingSource.SAST, FindingType.SAST) == "appsec_sca"
    assert security_domain_for(FindingSource.SECRET_SCAN, FindingType.CREDENTIAL_EXPOSURE) == "appsec_sca"


def test_domain_mcp_agent_signals_are_aispm() -> None:
    assert security_domain_for(FindingSource.MCP_SCAN, FindingType.TOOL_DRIFT) == "aispm"
    assert security_domain_for(FindingSource.PROXY, FindingType.EXFILTRATION) == "aispm"
    assert security_domain_for(FindingSource.SKILL, FindingType.SKILL_RISK) == "aispm"
    assert security_domain_for(FindingSource.PROMPT_SCAN, FindingType.PROMPT_SECURITY) == "aispm"


def test_domain_snowflake_governance_is_dspm() -> None:
    ev = {"provider": "snowflake", "category": "sensitive-data-access"}
    assert security_domain_for(FindingSource.CLOUD_CIS, FindingType.CIS_FAIL, ev) == "dspm"


def test_domain_is_one_of_the_five() -> None:
    valid = {"cspm", "vuln", "appsec_sca", "dspm", "aispm"}
    for source in FindingSource:
        for ftype in FindingType:
            assert security_domain_for(source, ftype) in valid


# ---------------------------------------------------------------------------
# Finding / Asset carry scope + domain through serialization
# ---------------------------------------------------------------------------


def test_finding_scope_fields_default_none_and_serialize() -> None:
    f = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="requests", asset_type="package"),
        severity="high",
    )
    assert f.provider is None
    assert f.account_ref is None
    assert f.region is None
    assert f.environment is None
    payload = f.to_dict()
    assert payload["provider"] is None
    assert payload["account_ref"] is None
    assert payload["region"] is None
    assert payload["environment"] is None
    assert payload["security_domain"] == "vuln"
    # asset scope block present
    assert payload["asset"]["provider"] is None


def test_finding_scope_fields_serialize_when_set() -> None:
    f = Finding(
        finding_type=FindingType.CIS_FAIL,
        source=FindingSource.CLOUD_CIS,
        asset=Asset(name="root", asset_type="cloud_resource"),
        severity="high",
        provider="aws",
        account_ref="aws:123456789012",
        region="us-east-1",
        environment="prod",
    )
    payload = f.to_dict()
    assert payload["provider"] == "aws"
    assert payload["account_ref"] == "aws:123456789012"
    assert payload["region"] == "us-east-1"
    assert payload["environment"] == "prod"
    assert payload["security_domain"] == "cspm"
    assert payload["asset"]["account_ref"] == "aws:123456789012"


# ---------------------------------------------------------------------------
# Ingest converters populate scope
# ---------------------------------------------------------------------------


def test_cloud_cis_converter_threads_scope() -> None:
    check = {
        "check_id": "2.1.1",
        "title": "S3 bucket encryption",
        "severity": "high",
        "status": "FAIL",
        "resource_ids": ["arn:aws:ec2:us-west-2:210987654321:instance/i-1"],
        "account_id": "210987654321",
        "benchmark": "CIS",
    }
    f = cloud_cis_check_to_finding(check, "aws")
    assert f.provider == "aws"
    assert f.account_ref == "aws:210987654321"
    assert f.region == "us-west-2"
    assert f.security_domain == "cspm"
    payload = f.to_dict()
    assert payload["account_ref"] == "aws:210987654321"


def test_snowflake_governance_converter_normalizes_account_and_domain() -> None:
    raw = {
        "category": "sensitive-data-access",
        "severity": "high",
        "title": "Broad SELECT on PII",
        "object_name": "DB.SCHEMA.CUSTOMERS",
    }
    f = snowflake_governance_finding_to_finding(raw, "xy12345")
    assert f.provider == "snowflake"
    assert f.account_ref == "snowflake:xy12345"
    assert f.security_domain == "dspm"
