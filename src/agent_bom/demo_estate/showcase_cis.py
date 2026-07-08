"""Curated CIS benchmark posture for the hosted demo estate.

Injected into the demo scan-job result so the CIS / compliance surfaces
(``/v1/cis/checks``, ``/v1/cis/trends``, the compliance scorecard) render a
believable multi-cloud posture — a spread of pass/fail across AWS, GCP, and
Azure that yields a realistic grade (not empty, not a perfect 100%).

Every check uses a real CIS Foundations Benchmark control id and section so
the screenshots map to controls an auditor can look up. Deterministic — the
same estate reproduces the same posture on every run.
"""

from __future__ import annotations

from typing import Any


def _check(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    cis_section: str,
    evidence: str,
    resource_ids: list[str],
    remediation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "cis_section": cis_section,
        "evidence": evidence,
        "resource_ids": resource_ids,
        "remediation": remediation,
    }


def _rem(
    fix_cli: str,
    fix_console: str,
    effort: str,
    priority: int,
    *,
    guardrails: list[str] | None = None,
    requires_human_review: bool = False,
) -> dict[str, Any]:
    return {
        "fix_cli": fix_cli,
        "fix_console": fix_console,
        "effort": effort,
        "priority": priority,
        "guardrails": guardrails or [],
        "requires_human_review": requires_human_review,
    }


_AWS_CHECKS: list[dict[str, Any]] = [
    _check(
        "1.4", "Ensure no root user account access key exists", "pass", "high",
        "1 Identity and Access Management",
        "No access keys attached to the root account.", ["root"],
        _rem("aws iam delete-access-key --user-name root", "IAM > Security credentials", "low", 3),
    ),
    _check(
        "1.12", "Ensure credentials unused for 45 days are disabled", "fail", "medium",
        "1 Identity and Access Management",
        "IAM user 'bob@contractor' has an access key unused for 118 days.", ["bob@contractor"],
        _rem(
            "aws iam update-access-key --user-name bob --status Inactive --access-key-id AKIA...",
            "IAM > Users > bob > Security credentials > Make inactive",
            "low", 6,
        ),
    ),
    _check(
        "2.1.1", "Ensure S3 bucket server-side encryption is enabled", "pass", "medium",
        "2 Storage",
        "Default SSE-KMS enabled on all in-scope buckets.", ["customer-pii-prod"],
        _rem("aws s3api put-bucket-encryption ...", "S3 > Bucket > Properties > Encryption", "low", 4),
    ),
    _check(
        "2.1.5", "Ensure S3 buckets block public access", "fail", "critical",
        "2 Storage",
        "Bucket 'customer-pii-prod' is publicly readable (Block Public Access off).",
        ["customer-pii-prod"],
        _rem(
            "aws s3api put-public-access-block --bucket customer-pii-prod "
            "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "S3 > customer-pii-prod > Permissions > Block public access > Edit",
            "low", 9, guardrails=["Confirm no legitimate anonymous readers before enabling."],
            requires_human_review=True,
        ),
    ),
    _check(
        "3.1", "Ensure CloudTrail is enabled in all regions", "pass", "high",
        "3 Logging",
        "Multi-region trail 'org-trail' active with log file validation.", ["org-trail"],
        _rem("aws cloudtrail update-trail --name org-trail --is-multi-region-trail",
             "CloudTrail > Trails", "medium", 5),
    ),
    _check(
        "4.1", "Ensure no security group allows ingress from 0.0.0.0/0 to port 22", "fail", "high",
        "4 Networking",
        "Security group 'sg-prod' allows 0.0.0.0/0 on tcp/22 (prod-bastion).", ["sg-prod"],
        _rem(
            "aws ec2 revoke-security-group-ingress --group-id sg-prod --protocol tcp "
            "--port 22 --cidr 0.0.0.0/0",
            "VPC > Security Groups > sg-prod > Inbound rules > Edit",
            "low", 8,
        ),
    ),
    _check(
        "2.2.1", "Ensure EBS volume encryption is enabled by default", "pass", "medium",
        "2 Storage",
        "Account-level default EBS encryption is on in all active regions.", ["ec2-default"],
        _rem("aws ec2 enable-ebs-encryption-by-default", "EC2 > Settings > Data protection", "low", 4),
    ),
    _check(
        "1.20", "Ensure IAM Access Analyzer is enabled for all regions", "pass", "low",
        "1 Identity and Access Management",
        "Access Analyzer 'org-analyzer' enabled in all regions.", ["org-analyzer"],
        _rem("aws accessanalyzer create-analyzer --analyzer-name org-analyzer --type ORGANIZATION",
             "IAM > Access Analyzer", "low", 2),
    ),
]

_GCP_CHECKS: list[dict[str, Any]] = [
    _check(
        "1.4", "Ensure user-managed service account keys are rotated <= 90 days", "fail", "medium",
        "1 Identity and Access Management",
        "Key for 'data-pipeline@proj.iam' is 214 days old.", ["data-pipeline@proj.iam"],
        _rem(
            "gcloud iam service-accounts keys create key.json --iam-account data-pipeline@proj.iam "
            "&& gcloud iam service-accounts keys delete OLD_KEY",
            "IAM & Admin > Service Accounts > Keys",
            "medium", 6, requires_human_review=True,
        ),
    ),
    _check(
        "3.6", "Ensure SSH access is restricted from the internet", "fail", "high",
        "3 Networking",
        "Firewall 'allow-ssh' permits 0.0.0.0/0 on tcp/22.", ["allow-ssh"],
        _rem("gcloud compute firewall-rules update allow-ssh --source-ranges=10.0.0.0/8",
             "VPC network > Firewall > allow-ssh", "low", 8),
    ),
    _check(
        "5.1", "Ensure Cloud Storage bucket is not anonymously/publicly accessible", "pass", "high",
        "5 Storage",
        "No buckets grant allUsers/allAuthenticatedUsers.", ["analytics-exports"],
        _rem("gsutil iam ch -d allUsers gs://BUCKET", "Cloud Storage > Bucket > Permissions", "low", 5),
    ),
    _check(
        "2.2", "Ensure a log sink captures all log entries", "pass", "medium",
        "2 Logging and Monitoring",
        "Aggregated sink 'org-sink' exports to a locked bucket.", ["org-sink"],
        _rem("gcloud logging sinks create org-sink ...", "Logging > Log Router", "medium", 4),
    ),
    _check(
        "6.2.4", "Ensure PostgreSQL 'log_min_messages' flag is set appropriately", "pass", "low",
        "6 Cloud SQL Database Services",
        "Flag set to 'warning' on all Cloud SQL PostgreSQL instances.", ["payments-db"],
        _rem("gcloud sql instances patch payments-db --database-flags=log_min_messages=warning",
             "SQL > Instance > Flags", "low", 3),
    ),
    _check(
        "1.5", "Ensure Service Account has no admin privileges", "fail", "high",
        "1 Identity and Access Management",
        "'data-pipeline@proj.iam' holds roles/owner.", ["data-pipeline@proj.iam"],
        _rem("gcloud projects remove-iam-policy-binding proj --member=... --role=roles/owner",
             "IAM & Admin > IAM", "medium", 7, requires_human_review=True),
    ),
]

_AZURE_CHECKS: list[dict[str, Any]] = [
    _check(
        "3.1", "Ensure 'Secure transfer required' is enabled on storage accounts", "pass", "medium",
        "3 Storage Accounts",
        "HTTPS-only enforced on all storage accounts.", ["stpiiprod"],
        _rem("az storage account update -n stpiiprod --https-only true",
             "Storage account > Configuration", "low", 4),
    ),
    _check(
        "3.7", "Ensure public network access to blob storage is disabled", "fail", "high",
        "3 Storage Accounts",
        "'stpiiprod' allows public blob access.", ["stpiiprod"],
        _rem("az storage account update -n stpiiprod --allow-blob-public-access false",
             "Storage account > Networking", "low", 8, requires_human_review=True),
    ),
    _check(
        "4.1.1", "Ensure auditing is enabled on SQL servers", "pass", "high",
        "4 Database Services",
        "Auditing enabled and shipping to Log Analytics for all SQL servers.", ["sql-payments"],
        _rem("az sql server audit-policy update ...", "SQL server > Auditing", "medium", 5),
    ),
    _check(
        "6.1", "Ensure RDP access is restricted from the internet", "fail", "high",
        "6 Networking",
        "NSG 'nsg-prod' allows Internet on tcp/3389.", ["nsg-prod"],
        _rem("az network nsg rule update -g rg --nsg-name nsg-prod -n rdp --source-address-prefixes 10.0.0.0/8",
             "Network security group > Inbound security rules", "low", 8),
    ),
    _check(
        "1.23", "Ensure no custom subscription owner roles are created", "pass", "medium",
        "1 Identity and Access Management",
        "No custom roles grant subscription-scoped Owner.", ["subscription"],
        _rem("az role definition delete --name CUSTOM_OWNER", "Subscriptions > Access control (IAM)", "medium", 4),
    ),
    _check(
        "8.1", "Ensure Key Vault is recoverable (soft-delete + purge protection)", "pass", "medium",
        "8 Key Vault",
        "Soft-delete and purge protection enabled on all vaults.", ["kv-prod"],
        _rem("az keyvault update --name kv-prod --enable-purge-protection true",
             "Key Vault > Properties", "low", 3),
    ),
]


def _benchmark(name: str, version: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(1 for c in checks if c["status"] == "pass")
    failed = sum(1 for c in checks if c["status"] == "fail")
    total = len(checks)
    return {
        "benchmark": name,
        "version": version,
        "passed": passed,
        "failed": failed,
        "total": total,
        "pass_rate": round((passed / total) * 100, 1) if total else 0.0,
        "checks": checks,
    }


def demo_cis_benchmarks() -> dict[str, Any]:
    """Return the curated AWS/GCP/Azure CIS benchmark blobs for the demo report.

    Keys match what ``build_cis_benchmark_check_rows`` reads from a scan result:
    ``cis_benchmark`` (AWS), ``gcp_cis_benchmark``, ``azure_cis_benchmark``.
    """
    return {
        "cis_benchmark": _benchmark(
            "CIS Amazon Web Services Foundations Benchmark", "3.0.0", _AWS_CHECKS
        ),
        "gcp_cis_benchmark": _benchmark(
            "CIS Google Cloud Platform Foundation Benchmark", "2.0.0", _GCP_CHECKS
        ),
        "azure_cis_benchmark": _benchmark(
            "CIS Microsoft Azure Foundations Benchmark", "2.1.0", _AZURE_CHECKS
        ),
    }
