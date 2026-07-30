"""Prevent CIS remediation overrides drifting away from live controls."""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

from agent_bom.cloud.cis_remediation import (
    _OVERRIDES,
    _VERIFIED_CLI_CONTROLS,
    CISControlIdentity,
    CISRemediationOverride,
    build_remediation,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CLOUD_MODULES = {
    "aws": _REPO_ROOT / "src/agent_bom/cloud/aws_cis_benchmark.py",
    "azure": _REPO_ROOT / "src/agent_bom/cloud/azure_cis_benchmark.py",
    "gcp": _REPO_ROOT / "src/agent_bom/cloud/gcp_cis_benchmark.py",
    "snowflake": _REPO_ROOT / "src/agent_bom/cloud/snowflake_cis_benchmark.py",
}


def _literal_string(node: ast.expr | None, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _catalog_identities(cloud: str, path: Path) -> list[CISControlIdentity]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    constants: dict[str, str] = {}
    benchmark_version = ""

    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = _literal_string(node.value, constants)
            if value is not None:
                constants[node.targets[0].id] = value
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) and child.target.id == "benchmark_version":
                    benchmark_version = _literal_string(child.value, constants) or ""

    identities: list[CISControlIdentity] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "CISCheckResult"):
            continue
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        check_id = _literal_string(keywords.get("check_id"), constants)
        title = _literal_string(keywords.get("title"), constants)
        cis_section = _literal_string(keywords.get("cis_section"), constants)
        if check_id is not None and title is not None and cis_section is not None:
            identities.append(
                CISControlIdentity(
                    cloud=cloud,
                    benchmark_version=benchmark_version,
                    check_id=check_id,
                    title=title,
                    cis_section=cis_section,
                )
            )
    return identities


def test_each_override_matches_exactly_one_live_catalog_control() -> None:
    live = Counter(identity for cloud, path in _CLOUD_MODULES.items() for identity in _catalog_identities(cloud, path))

    assert _OVERRIDES
    for identity, override in _OVERRIDES.items():
        assert isinstance(identity, CISControlIdentity)
        assert isinstance(override, CISRemediationOverride)
        assert live[identity] == 1, f"override is stale or ambiguous: {identity}"


_VERIFIED_EXPECTATIONS = {
    CISControlIdentity("aws", "3.0", "2.1.1", "S3 account-level public access block configured", "2 - Storage"): (
        "aws s3control put-public-access-block --account-id <ACCOUNT_ID> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "https://docs.aws.amazon.com/cli/latest/reference/s3control/put-public-access-block.html",
    ),
    CISControlIdentity("aws", "3.0", "2.1.2", "S3 bucket server-side encryption enabled", "2 - Storage"): (
        "aws s3api put-bucket-encryption --bucket <BUCKET_NAME> "
        "--server-side-encryption-configuration "
        '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
        "https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-encryption.html",
    ),
    CISControlIdentity("aws", "3.0", "3.2", "CloudTrail log file validation enabled", "3 - Logging"): (
        "aws cloudtrail update-trail --name <TRAIL_NAME_OR_ARN> --enable-log-file-validation",
        "https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html",
    ),
    CISControlIdentity("azure", "3.0", "3.1", "Secure transfer required on storage accounts", "3 - Storage Accounts"): (
        "az storage account update --name <STORAGE_ACCOUNT_NAME> --resource-group <RESOURCE_GROUP_NAME> --https-only true",
        "https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer",
    ),
    CISControlIdentity("azure", "3.0", "3.7", "Blob containers set to private access", "3 - Storage Accounts"): (
        "az storage account update --name <STORAGE_ACCOUNT_NAME> --resource-group <RESOURCE_GROUP_NAME> --allow-blob-public-access false",
        "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-configure",
    ),
    CISControlIdentity("gcp", "3.0", "5.2", "Uniform bucket-level access enabled on buckets", "5 - Cloud Storage"): (
        "gcloud storage buckets update gs://<BUCKET_NAME> --uniform-bucket-level-access",
        "https://cloud.google.com/storage/docs/using-uniform-bucket-level-access",
    ),
}


def test_only_provider_verified_cli_mutations_are_enabled() -> None:
    assert _VERIFIED_CLI_CONTROLS == frozenset(_VERIFIED_EXPECTATIONS)

    for identity, (expected_command, expected_docs) in _VERIFIED_EXPECTATIONS.items():
        override = _OVERRIDES[identity]
        assert override.fix_cli == expected_command
        assert override.docs == expected_docs
        assert override.effort == "low"
        assert override.requires_human_review is True

        remediation = build_remediation(
            cloud=identity.cloud,
            benchmark_version=identity.benchmark_version,
            check_id=identity.check_id,
            title=identity.title,
            severity="high",
            recommendation="",
            cis_section=identity.cis_section,
        )
        assert remediation["fix_cli"] == expected_command
        assert remediation["docs"] == expected_docs
        assert remediation["effort"] == "low"
        assert remediation["requires_human_review"] is True


def test_every_exposed_cis_command_is_placeholder_bound_and_allowlisted() -> None:
    for identity in _OVERRIDES:
        remediation = build_remediation(
            cloud=identity.cloud,
            benchmark_version=identity.benchmark_version,
            check_id=identity.check_id,
            title=identity.title,
            severity="high",
            recommendation="",
            cis_section=identity.cis_section,
        )
        command = remediation["fix_cli"]
        if command is None:
            continue
        assert identity in _VERIFIED_EXPECTATIONS
        assert "<" in command and ">" in command
        assert remediation["requires_human_review"] is True
