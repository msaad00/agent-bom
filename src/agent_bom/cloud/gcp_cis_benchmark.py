"""CIS Google Cloud Platform Foundation Benchmark v3.0 — live project checks.

Runs read-only GCP API calls against the CIS GCP Foundation Benchmark v3.0
covering IAM, Logging, Networking, Virtual Machines, Storage, Cloud SQL,
and BigQuery.

Required roles (all read-only):
    roles/iam.securityReviewer
    roles/logging.viewer
    roles/compute.networkViewer
    roles/storage.objectViewer (for bucket IAM inspection)
    roles/bigquery.dataViewer (for BigQuery dataset inspection)

Required permissions for additional checks:
    compute.instances.list (CIS 4.1–4.9, 4.11)
    compute.subnetworks.list (CIS 3.9, 3.10)
    compute.firewalls.list (CIS 3.6–3.8)
    sqladmin.instances.list (CIS 6.1–6.7)
    logging.logMetrics.list (CIS 2.3–2.11)
    logging.sinks.list (CIS 2.2)
    dns.managedZones.list (CIS 2.12, 3.3–3.5)
    cloudkms.cryptoKeys.list (CIS 1.9–1.11)
    serviceusage.apiKeys.list (CIS 1.12–1.14)
    essentialcontacts.contacts.list (CIS 1.15)
    bigquery.datasets.list (CIS 7.1–7.3)

Authentication uses Application Default Credentials:
    gcloud auth application-default login
    or GOOGLE_APPLICATION_CREDENTIALS env var.

Install: ``pip install 'agent-bom[gcp]'``
"""

from __future__ import annotations

import importlib
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from .aws_cis_benchmark import CheckStatus, CISCheckResult
from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def _import_google_cloud_module(module: str) -> Any:
    """Import optional Google Cloud SDK modules without requiring mypy stubs."""
    return importlib.import_module(f"google.cloud.{module}")


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class GCPCISReport:
    """Aggregated CIS GCP Foundation Benchmark results."""

    benchmark_version: str = "3.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    project_id: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        evaluated = sum(1 for c in self.checks if c.status in (CheckStatus.PASS, CheckStatus.FAIL))
        return (self.passed / evaluated * 100) if evaluated else 0.0

    def to_dict(self) -> dict:
        from agent_bom.mitre_attack import tag_cis_check

        return {
            "benchmark": "CIS Google Cloud Platform Foundation",
            "benchmark_version": self.benchmark_version,
            "project_id": self.project_id,
            "pass_rate": round(self.pass_rate, 1),
            "passed": self.passed,
            "failed": self.failed,
            "total": self.total,
            "checks": [
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "status": c.status.value,
                    "severity": c.severity,
                    "evidence": c.evidence,
                    "resource_ids": c.resource_ids,
                    "recommendation": c.recommendation,
                    "remediation": c.remediation,
                    "cis_section": c.cis_section,
                    "attack_techniques": tag_cis_check(c),
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Section labels
# ---------------------------------------------------------------------------

_IAM_SECTION = "1 - Identity and Access Management"
_LOGGING_SECTION = "2 - Logging"
_NETWORK_SECTION = "3 - Networking"
_COMPUTE_SECTION = "4 - Virtual Machines"
_STORAGE_SECTION = "5 - Cloud Storage"
_SQL_SECTION = "6 - Cloud SQL"
_BIGQUERY_SECTION = "7 - BigQuery"


# ---------------------------------------------------------------------------
# Individual checks — CIS 1.x (Identity and Access Management)
# ---------------------------------------------------------------------------


def _check_1_1(project_id: str) -> CISCheckResult:
    """CIS 1.1 — Ensure corporate login credentials are used."""
    result = CISCheckResult(
        check_id="1.1",
        title="Ensure that corporate login credentials are used",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove IAM bindings for members using gmail.com accounts. Use corporate/organisational login credentials instead.",
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery

        crm = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])

        gmail_members: list[str] = []
        for binding in bindings:
            for member in binding.get("members", []):
                if member.lower().endswith("@gmail.com"):
                    gmail_members.append(f"{binding.get('role', '')}: {member}")

        if gmail_members:
            result.status = CheckStatus.FAIL
            result.evidence = f"Gmail accounts found in IAM policy: {', '.join(gmail_members[:10])}"
            result.resource_ids = gmail_members
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No gmail.com accounts found in project IAM policy."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check IAM policy for gmail accounts: {exc}"
    return result


def _check_1_2(project_id: str) -> CISCheckResult:
    """CIS 1.2 — Ensure multi-factor authentication is enforced for all users."""
    return CISCheckResult(
        check_id="1.2",
        title="Ensure multi-factor authentication is enforced for all users",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        evidence="MFA enforcement is configured at the Google Workspace / Cloud Identity level and cannot be verified via project-level API calls. Manual verification required.",
        recommendation="Enable 2-Step Verification enforcement in Google Workspace Admin Console under Security > 2-Step Verification.",
        cis_section=_IAM_SECTION,
    )


def _check_1_3(project_id: str) -> CISCheckResult:
    """CIS 1.3 — Ensure Security Key enforcement is enabled for all admin accounts."""
    return CISCheckResult(
        check_id="1.3",
        title="Ensure Security Key enforcement is enabled for all admin accounts",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        evidence="Security Key enforcement is configured at the Google Workspace / Cloud Identity level and cannot be verified via project-level API calls. Manual verification required.",
        recommendation="Enforce Security Key usage for all admin accounts in Google Workspace Admin Console.",
        cis_section=_IAM_SECTION,
    )


def _check_1_4(project_id: str) -> CISCheckResult:
    """CIS 1.4 — Ensure service account keys are not created for user-managed service accounts."""
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure service account keys are not created for user-managed service accounts",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Delete user-managed service account keys and use short-lived credentials via Workload Identity or impersonation instead."
        ),
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery
        from google.oauth2 import service_account as _sa  # noqa: F401 — availability check

        iam_service = googleapiclient.discovery.build("iam", "v1", cache_discovery=False)
        sa_list = iam_service.projects().serviceAccounts().list(name=f"projects/{project_id}").execute()
        service_accounts = sa_list.get("accounts", [])

        failing: list[str] = []
        for sa in service_accounts:
            sa_name = sa.get("name", "")
            if not sa_name:
                continue
            keys_resp = iam_service.projects().serviceAccounts().keys().list(name=sa_name, keyTypes=["USER_MANAGED"]).execute()
            user_keys = keys_resp.get("keys", [])
            if user_keys:
                failing.append(f"{sa.get('email', sa_name)} ({len(user_keys)} key(s))")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Service accounts with user-managed keys: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No user-managed keys found across {len(service_accounts)} service account(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check service account keys: {exc}"
    return result


def _check_1_5(project_id: str) -> CISCheckResult:
    """CIS 1.5 — Ensure primitive roles (Owner/Editor) are not used on the project."""
    result = CISCheckResult(
        check_id="1.5",
        title="Ensure primitive roles (Owner/Editor) are not assigned at project level",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Replace primitive Owner/Editor bindings with predefined or custom roles following least privilege.",
        cis_section=_IAM_SECTION,
    )
    primitive_roles = {"roles/owner", "roles/editor"}
    try:
        import googleapiclient.discovery

        crm = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])

        failing_members: list[str] = []
        for binding in bindings:
            role = binding.get("role", "")
            if role in primitive_roles:
                members = binding.get("members", [])
                # Exclude service agents and GCP-managed accounts
                user_members = [m for m in members if not (m.startswith("serviceAccount:") and m.endswith(".iam.gserviceaccount.com"))]
                for m in user_members:
                    failing_members.append(f"{role}: {m}")

        if failing_members:
            result.status = CheckStatus.FAIL
            result.evidence = f"Primitive role bindings found: {', '.join(failing_members[:10])}"
            result.resource_ids = failing_members
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No primitive Owner/Editor roles assigned to user accounts at project level."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check IAM policy: {exc}"
    return result


def _check_1_6(project_id: str) -> CISCheckResult:
    """CIS 1.6 — Ensure service account has no admin privileges."""
    result = CISCheckResult(
        check_id="1.6",
        title="Ensure service account has no admin privileges",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=(
            "Remove roles/owner, roles/editor, and roles/iam.admin from service accounts. Use fine-grained predefined roles instead."
        ),
        cis_section=_IAM_SECTION,
    )
    admin_roles = {"roles/owner", "roles/editor", "roles/iam.admin"}
    try:
        import googleapiclient.discovery

        crm = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])

        failing: list[str] = []
        for binding in bindings:
            role = binding.get("role", "")
            if role not in admin_roles:
                continue
            for member in binding.get("members", []):
                if member.startswith("serviceAccount:"):
                    failing.append(f"{role}: {member}")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Service accounts with admin privileges: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No service accounts have admin privileges (owner/editor/iam.admin)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check service account admin privileges: {exc}"
    return result


def _check_1_7(project_id: str) -> CISCheckResult:
    """CIS 1.7 — Ensure user-managed service accounts do not have admin privileges."""
    result = CISCheckResult(
        check_id="1.7",
        title="Ensure user-managed service accounts do not have admin privileges",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Remove roles/iam.serviceAccountAdmin, roles/iam.serviceAccountKeyAdmin,"
            " and roles/compute.admin from user-managed service accounts."
        ),
        cis_section=_IAM_SECTION,
    )
    sa_admin_roles = {
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/compute.admin",
    }
    try:
        import googleapiclient.discovery

        crm = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])

        failing: list[str] = []
        for binding in bindings:
            role = binding.get("role", "")
            if role not in sa_admin_roles:
                continue
            for member in binding.get("members", []):
                if member.startswith("serviceAccount:"):
                    failing.append(f"{role}: {member}")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"User-managed service accounts with admin privileges: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No user-managed service accounts have serviceAccountAdmin, serviceAccountKeyAdmin, or compute.admin roles."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check user-managed service account admin privileges: {exc}"
    return result


def _check_1_8(project_id: str) -> CISCheckResult:
    """CIS 1.8 — Ensure rotation for user-managed service account keys is within 90 days."""
    result = CISCheckResult(
        check_id="1.8",
        title="Ensure user-managed service account keys are rotated within 90 days",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Rotate user-managed service account keys every 90 days or less. Prefer short-lived credentials via Workload Identity.",
        cis_section=_IAM_SECTION,
    )
    try:
        import datetime

        import googleapiclient.discovery

        iam_service = googleapiclient.discovery.build("iam", "v1", cache_discovery=False)
        sa_list = iam_service.projects().serviceAccounts().list(name=f"projects/{project_id}").execute()
        service_accounts = sa_list.get("accounts", [])

        failing: list[str] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold = datetime.timedelta(days=90)

        for sa in service_accounts:
            sa_name = sa.get("name", "")
            if not sa_name:
                continue
            keys_resp = iam_service.projects().serviceAccounts().keys().list(name=sa_name, keyTypes=["USER_MANAGED"]).execute()
            for key in keys_resp.get("keys", []):
                created = key.get("validAfterTime", "")
                if created:
                    created_dt = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if now - created_dt > threshold:
                        failing.append(f"{sa.get('email', sa_name)} (key created {created})")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Service account keys older than 90 days: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All user-managed service account keys across {len(service_accounts)} account(s) are within 90-day rotation."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check service account key rotation: {exc}"
    return result


def _check_1_9(project_id: str) -> CISCheckResult:
    """CIS 1.9 — Ensure Cloud KMS encryption keys are not anonymously or publicly accessible."""
    result = CISCheckResult(
        check_id="1.9",
        title="Ensure Cloud KMS encryption keys are not anonymously or publicly accessible",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove allUsers and allAuthenticatedUsers from Cloud KMS key IAM policies.",
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery

        kms = googleapiclient.discovery.build("cloudkms", "v1", cache_discovery=False)
        locations = kms.projects().locations().list(name=f"projects/{project_id}").execute()
        public_keys: list[str] = []

        for loc in locations.get("locations", []):
            loc_name = loc.get("name", "")
            keyrings = kms.projects().locations().keyRings().list(parent=loc_name).execute()
            for kr in keyrings.get("keyRings", []):
                kr_name = kr.get("name", "")
                keys_resp = kms.projects().locations().keyRings().cryptoKeys().list(parent=kr_name).execute()
                for key in keys_resp.get("cryptoKeys", []):
                    key_name = key.get("name", "")
                    policy = kms.projects().locations().keyRings().cryptoKeys().getIamPolicy(resource=key_name).execute()
                    for binding in policy.get("bindings", []):
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            public_keys.append(key_name)

        if public_keys:
            result.status = CheckStatus.FAIL
            result.evidence = f"Publicly accessible KMS keys: {', '.join(public_keys[:10])}"
            result.resource_ids = public_keys
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No KMS encryption keys are anonymously or publicly accessible."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check KMS key IAM policies: {exc}"
    return result


def _check_1_10(project_id: str) -> CISCheckResult:
    """CIS 1.10 — Ensure KMS encryption keys are rotated within a period of 90 days."""
    result = CISCheckResult(
        check_id="1.10",
        title="Ensure KMS encryption keys are rotated within 90 days",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set a rotation period of 90 days or less on all Cloud KMS encryption keys.",
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery

        kms = googleapiclient.discovery.build("cloudkms", "v1", cache_discovery=False)
        locations = kms.projects().locations().list(name=f"projects/{project_id}").execute()
        failing: list[str] = []
        max_rotation_seconds = 90 * 24 * 60 * 60  # 90 days in seconds

        for loc in locations.get("locations", []):
            loc_name = loc.get("name", "")
            keyrings = kms.projects().locations().keyRings().list(parent=loc_name).execute()
            for kr in keyrings.get("keyRings", []):
                kr_name = kr.get("name", "")
                keys_resp = kms.projects().locations().keyRings().cryptoKeys().list(parent=kr_name).execute()
                for key in keys_resp.get("cryptoKeys", []):
                    key_name = key.get("name", "")
                    rotation_period = key.get("rotationPeriod", "")
                    if not rotation_period:
                        failing.append(key_name)
                    else:
                        # rotationPeriod is like "7776000s"
                        period_s = int(rotation_period.rstrip("s"))
                        if period_s > max_rotation_seconds:
                            failing.append(key_name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"KMS keys without 90-day rotation: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All KMS encryption keys have rotation periods within 90 days."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check KMS key rotation: {exc}"
    return result


def _check_1_11(project_id: str) -> CISCheckResult:
    """CIS 1.11 — Ensure separation of duties is enforced while assigning KMS-related roles."""
    result = CISCheckResult(
        check_id="1.11",
        title="Ensure separation of duties is enforced while assigning KMS-related roles",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Ensure no user has both cloudkms.admin and any of cloudkms.cryptoKeyEncrypterDecrypter, cloudkms.cryptoKeyEncrypter, or cloudkms.cryptoKeyDecrypter roles.",
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery

        crm = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])

        admin_role = "roles/cloudkms.admin"
        crypto_roles = {
            "roles/cloudkms.cryptoKeyEncrypterDecrypter",
            "roles/cloudkms.cryptoKeyEncrypter",
            "roles/cloudkms.cryptoKeyDecrypter",
        }

        admins: set[str] = set()
        crypto_members: set[str] = set()

        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])
            if role == admin_role:
                admins.update(members)
            elif role in crypto_roles:
                crypto_members.update(members)

        overlap = admins & crypto_members
        if overlap:
            failing = list(overlap)
            result.status = CheckStatus.FAIL
            result.evidence = f"Members with both KMS admin and crypto roles: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No members have both KMS admin and crypto encrypter/decrypter roles."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check KMS role separation: {exc}"
    return result


def _check_1_12(project_id: str) -> CISCheckResult:
    """CIS 1.12 — Ensure API keys are restricted to only APIs the application needs."""
    result = CISCheckResult(
        check_id="1.12",
        title="Ensure API keys are restricted to only APIs the application needs",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Restrict each API key to only the specific APIs required by the application.",
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery

        apikeys = googleapiclient.discovery.build("apikeys", "v2", cache_discovery=False)
        keys_resp = apikeys.projects().locations().keys().list(parent=f"projects/{project_id}/locations/global").execute()
        keys = keys_resp.get("keys", [])

        unrestricted: list[str] = []
        for key in keys:
            key_name = key.get("name", "")
            # Get full key details
            key_detail = apikeys.projects().locations().keys().get(name=key_name).execute()
            restrictions = key_detail.get("restrictions", {})
            api_targets = restrictions.get("apiTargets", [])
            if not api_targets:
                unrestricted.append(key.get("displayName", key_name))

        if unrestricted:
            result.status = CheckStatus.FAIL
            result.evidence = f"API keys without API restrictions: {', '.join(unrestricted[:10])}"
            result.resource_ids = unrestricted
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(keys)} API key(s) are restricted to specific APIs."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check API key restrictions: {exc}"
    return result


def _check_1_13(project_id: str) -> CISCheckResult:
    """CIS 1.13 — Ensure API keys are restricted to specific hosts and apps."""
    result = CISCheckResult(
        check_id="1.13",
        title="Ensure API keys are restricted to specific hosts and apps",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Add application restrictions (HTTP referrers, IP addresses, Android/iOS apps) to each API key.",
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery

        apikeys = googleapiclient.discovery.build("apikeys", "v2", cache_discovery=False)
        keys_resp = apikeys.projects().locations().keys().list(parent=f"projects/{project_id}/locations/global").execute()
        keys = keys_resp.get("keys", [])

        unrestricted: list[str] = []
        for key in keys:
            key_name = key.get("name", "")
            key_detail = apikeys.projects().locations().keys().get(name=key_name).execute()
            restrictions = key_detail.get("restrictions", {})
            has_app_restriction = any(
                restrictions.get(r)
                for r in ("browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions")
            )
            if not has_app_restriction:
                unrestricted.append(key.get("displayName", key_name))

        if unrestricted:
            result.status = CheckStatus.FAIL
            result.evidence = f"API keys without host/app restrictions: {', '.join(unrestricted[:10])}"
            result.resource_ids = unrestricted
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(keys)} API key(s) are restricted to specific hosts or apps."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check API key host/app restrictions: {exc}"
    return result


def _check_1_14(project_id: str) -> CISCheckResult:
    """CIS 1.14 — Ensure API keys are rotated within 90 days."""
    result = CISCheckResult(
        check_id="1.14",
        title="Ensure API keys are rotated within 90 days",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Rotate API keys every 90 days or less to reduce the impact of compromised keys.",
        cis_section=_IAM_SECTION,
    )
    try:
        import datetime

        import googleapiclient.discovery

        apikeys = googleapiclient.discovery.build("apikeys", "v2", cache_discovery=False)
        keys_resp = apikeys.projects().locations().keys().list(parent=f"projects/{project_id}/locations/global").execute()
        keys = keys_resp.get("keys", [])

        failing: list[str] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold = datetime.timedelta(days=90)

        for key in keys:
            create_time = key.get("createTime", "")
            if create_time:
                created_dt = datetime.datetime.fromisoformat(create_time.replace("Z", "+00:00"))
                if now - created_dt > threshold:
                    failing.append(key.get("displayName", key.get("name", "unknown")))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"API keys older than 90 days: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(keys)} API key(s) are within 90-day rotation."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check API key rotation: {exc}"
    return result


def _check_1_15(project_id: str) -> CISCheckResult:
    """CIS 1.15 — Ensure essential contacts is configured for the organization."""
    result = CISCheckResult(
        check_id="1.15",
        title="Ensure essential contacts is configured for the organization",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Configure Essential Contacts for SECURITY, TECHNICAL, and BILLING notification categories.",
        cis_section=_IAM_SECTION,
    )
    try:
        import googleapiclient.discovery

        essentialcontacts = googleapiclient.discovery.build("essentialcontacts", "v1", cache_discovery=False)
        contacts = essentialcontacts.projects().contacts().list(parent=f"projects/{project_id}").execute()
        contact_list = contacts.get("contacts", [])

        if contact_list:
            categories = set()
            for contact in contact_list:
                categories.update(contact.get("notificationCategorySubscriptions", []))

            required = {"SECURITY", "TECHNICAL", "BILLING"}
            missing = required - categories
            if missing:
                result.status = CheckStatus.FAIL
                result.evidence = f"Essential contacts configured but missing categories: {', '.join(missing)}"
            else:
                result.status = CheckStatus.PASS
                result.evidence = (
                    f"Essential contacts configured with {len(contact_list)} contact(s) covering SECURITY, TECHNICAL, and BILLING."
                )
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No essential contacts configured for the project."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check essential contacts: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 2.x (Logging)
# ---------------------------------------------------------------------------


def _check_2_1(project_id: str) -> CISCheckResult:
    """CIS 2.1 — Ensure Cloud Audit Logs is configured to log Admin Activity and Data Access."""
    result = CISCheckResult(
        check_id="2.1",
        title="Ensure Cloud Audit Logs is configured for all services",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable DATA_READ and DATA_WRITE audit log types for all services in the project IAM policy.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        import googleapiclient.discovery

        crm = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        audit_configs = policy.get("auditConfigs", [])

        # Look for allServices audit config with DATA_READ + DATA_WRITE
        all_services_config = next((c for c in audit_configs if c.get("service") == "allServices"), None)

        if all_services_config:
            log_types = {al.get("logType") for al in all_services_config.get("auditLogConfigs", [])}
            missing = {"DATA_READ", "DATA_WRITE"} - log_types
            if missing:
                result.status = CheckStatus.FAIL
                result.evidence = f"Audit log types not enabled for allServices: {', '.join(missing)}"
            else:
                result.status = CheckStatus.PASS
                result.evidence = "DATA_READ and DATA_WRITE audit logs enabled for allServices."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No allServices audit log configuration found. Audit logging may be incomplete."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check audit log configuration: {exc}"
    return result


def _check_2_2(project_id: str) -> CISCheckResult:
    """CIS 2.2 — Ensure a log sink is configured for all log entries."""
    result = CISCheckResult(
        check_id="2.2",
        title="Ensure a log sink is configured to export all log entries",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Create a log sink in Cloud Logging that exports all log entries"
            " (_Default or custom filter) to Cloud Storage, BigQuery, or Pub/Sub."
        ),
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.ConfigServiceV2Client()
        parent = f"projects/{project_id}"
        sinks = list(client.list_sinks(parent=parent))

        # Look for a sink that covers all logs (no filter or broad filter)
        broad_sinks = [s for s in sinks if not s.filter or s.filter.strip() in ("", "true", "logName:*")]

        if broad_sinks:
            result.status = CheckStatus.PASS
            result.evidence = f"Found {len(broad_sinks)} broad log sink(s) exporting all entries."
        elif sinks:
            result.status = CheckStatus.FAIL
            result.evidence = f"Found {len(sinks)} log sink(s) but none cover all log entries (filtered). Add a sink with no filter."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log sinks configured. Log entries are not being exported."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed. Install with: pip install google-cloud-logging"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log sinks: {exc}"
    return result


def _check_2_3(project_id: str) -> CISCheckResult:
    """CIS 2.3 — Ensure log metric filter and alerts exist for Project Ownership changes."""
    result = CISCheckResult(
        check_id="2.3",
        title="Ensure log metric filter and alerts exist for Project Ownership changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for (protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee).',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["projectownership", "projectownerinvitee"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for Project Ownership changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for Project Ownership changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_4(project_id: str) -> CISCheckResult:
    """CIS 2.4 — Ensure log metric filter and alerts exist for Audit Configuration changes."""
    result = CISCheckResult(
        check_id="2.4",
        title="Ensure log metric filter and alerts exist for Audit Configuration changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*.',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["auditconfigdeltas", "setiampolicy"]
        found = any(all(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for Audit Configuration changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for Audit Configuration changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_5(project_id: str) -> CISCheckResult:
    """CIS 2.5 — Ensure log metric filter and alerts exist for Custom Role changes."""
    result = CISCheckResult(
        check_id="2.5",
        title="Ensure log metric filter and alerts exist for Custom Role changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="iam_role" AND (methodName="google.iam.admin.v1.CreateRole" OR methodName="google.iam.admin.v1.DeleteRole" OR methodName="google.iam.admin.v1.UpdateRole").',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["createrole", "deleterole", "updaterole"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for Custom Role changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for Custom Role changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_6(project_id: str) -> CISCheckResult:
    """CIS 2.6 — Ensure log metric filter and alerts exist for VPC Network Firewall Rule changes."""
    result = CISCheckResult(
        check_id="2.6",
        title="Ensure log metric filter and alerts exist for VPC Network Firewall Rule changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gce_firewall_rule" AND (methodName:"compute.firewalls.patch" OR methodName:"compute.firewalls.insert" OR methodName:"compute.firewalls.delete").',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["compute.firewalls"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for VPC Network Firewall Rule changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for VPC Network Firewall Rule changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_7(project_id: str) -> CISCheckResult:
    """CIS 2.7 — Ensure log metric filter and alerts exist for VPC Network Route changes."""
    result = CISCheckResult(
        check_id="2.7",
        title="Ensure log metric filter and alerts exist for VPC Network Route changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gce_route" AND (methodName:"compute.routes.delete" OR methodName:"compute.routes.insert").',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["compute.routes"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for VPC Network Route changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for VPC Network Route changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_8(project_id: str) -> CISCheckResult:
    """CIS 2.8 — Ensure log metric filter and alerts exist for VPC Network changes."""
    result = CISCheckResult(
        check_id="2.8",
        title="Ensure log metric filter and alerts exist for VPC Network changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gce_network" AND (methodName:"compute.networks.insert" OR methodName:"compute.networks.patch" OR methodName:"compute.networks.delete" OR methodName:"compute.networks.removePeering" OR methodName:"compute.networks.addPeering").',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["compute.networks"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for VPC Network changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for VPC Network changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_9(project_id: str) -> CISCheckResult:
    """CIS 2.9 — Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes."""
    result = CISCheckResult(
        check_id="2.9",
        title="Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions".',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["storage.setiampermissions"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for Cloud Storage IAM permission changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for Cloud Storage IAM permission changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_10(project_id: str) -> CISCheckResult:
    """CIS 2.10 — Ensure log metric filter and alerts exist for SQL instance configuration changes."""
    result = CISCheckResult(
        check_id="2.10",
        title="Ensure log metric filter and alerts exist for SQL instance configuration changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for protoPayload.methodName="cloudsql.instances.update".',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["cloudsql.instances.update"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for SQL instance configuration changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for SQL instance configuration changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_11(project_id: str) -> CISCheckResult:
    """CIS 2.11 — Ensure log metric filter and alerts exist for DNS Zone changes."""
    result = CISCheckResult(
        check_id="2.11",
        title="Ensure log metric filter and alerts exist for DNS Zone changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="dns_managed_zone" AND (methodName:"dns.managedZones.create" OR methodName:"dns.managedZones.patch" OR methodName:"dns.managedZones.update" OR methodName:"dns.managedZones.delete").',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client()
        parent = f"projects/{project_id}"
        metrics = list(client.list_log_metrics(parent=parent))

        filter_keywords = ["dns.managedzones"]
        found = any(any(kw in (m.filter or "").lower() for kw in filter_keywords) for m in metrics)

        if found:
            result.status = CheckStatus.PASS
            result.evidence = "Log metric filter for DNS Zone changes exists."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log metric filter found for DNS Zone changes."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-logging not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log metrics: {exc}"
    return result


def _check_2_12(project_id: str) -> CISCheckResult:
    """CIS 2.12 — Ensure Cloud DNS logging is enabled for all VPC networks."""
    result = CISCheckResult(
        check_id="2.12",
        title="Ensure Cloud DNS logging is enabled for all VPC networks",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable DNS logging on all Cloud DNS managed zones by setting the logging configuration.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        import googleapiclient.discovery

        dns = googleapiclient.discovery.build("dns", "v1", cache_discovery=False)
        zones_resp = dns.managedZones().list(project=project_id).execute()
        zones = zones_resp.get("managedZones", [])

        failing: list[str] = []
        for zone in zones:
            zone_name = zone.get("name", "unknown")
            # Check if DNS logging is enabled via the zone's cloud logging config
            visibility = zone.get("visibility", "")
            if visibility == "private":
                logging_config = zone.get("cloudLoggingConfig", {})
                if not logging_config.get("enableLogging", False):
                    failing.append(zone_name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"DNS zones without logging ({len(failing)}/{len(zones)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"Cloud DNS logging is enabled for all {len(zones)} managed zone(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud DNS logging: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 3.x (Networking)
# ---------------------------------------------------------------------------


def _check_3_1(project_id: str) -> CISCheckResult:
    """CIS 3.1 — Ensure the default VPC network does not exist in a project."""
    result = CISCheckResult(
        check_id="3.1",
        title="Ensure the default VPC network does not exist in the project",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Delete the 'default' VPC network and create custom VPC networks with explicit firewall rules.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.NetworksClient()
        networks = list(client.list(project=project_id))
        default_net = next((n for n in networks if n.name == "default"), None)

        if default_net:
            result.status = CheckStatus.FAIL
            result.evidence = "The 'default' VPC network exists. It has permissive default firewall rules that may expose resources."
            result.resource_ids = ["default"]
        else:
            result.status = CheckStatus.PASS
            result.evidence = "The 'default' VPC network has been deleted. Custom networks in use."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VPC networks: {exc}"
    return result


def _check_3_2(project_id: str) -> CISCheckResult:
    """CIS 3.2 — Ensure legacy networks do not exist in the project."""
    result = CISCheckResult(
        check_id="3.2",
        title="Ensure legacy networks do not exist in the project",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Delete legacy networks and create VPC networks with custom subnet mode instead.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.NetworksClient()
        networks = list(client.list(project=project_id))
        legacy: list[str] = []

        for net in networks:
            # Legacy networks have auto_create_subnetworks as None (not True/False)
            if getattr(net, "auto_create_subnetworks", None) is None:
                legacy.append(getattr(net, "name", "unknown"))

        if legacy:
            result.status = CheckStatus.FAIL
            result.evidence = f"Legacy networks found: {', '.join(legacy)}"
            result.resource_ids = legacy
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No legacy networks found across {len(networks)} network(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check for legacy networks: {exc}"
    return result


def _check_3_3(project_id: str) -> CISCheckResult:
    """CIS 3.3 — Ensure DNSSEC is enabled for Cloud DNS."""
    result = CISCheckResult(
        check_id="3.3",
        title="Ensure that DNSSEC is enabled for Cloud DNS",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable DNSSEC on all public Cloud DNS managed zones.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        import googleapiclient.discovery

        dns = googleapiclient.discovery.build("dns", "v1", cache_discovery=False)
        zones_resp = dns.managedZones().list(project=project_id).execute()
        zones = zones_resp.get("managedZones", [])

        failing: list[str] = []
        public_zones = [z for z in zones if z.get("visibility", "public") == "public"]

        for zone in public_zones:
            zone_name = zone.get("name", "unknown")
            dnssec_config = zone.get("dnssecConfig", {})
            state = dnssec_config.get("state", "off")
            if state != "on":
                failing.append(zone_name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Public DNS zones without DNSSEC ({len(failing)}/{len(public_zones)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"DNSSEC is enabled on all {len(public_zones)} public DNS zone(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check DNSSEC configuration: {exc}"
    return result


def _check_3_4(project_id: str) -> CISCheckResult:
    """CIS 3.4 — Ensure RSASHA1 is not used for key-signing in DNSSEC."""
    result = CISCheckResult(
        check_id="3.4",
        title="Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Use RSASHA256, RSASHA512, or ECDSAP256SHA256 for DNSSEC key-signing keys instead of RSASHA1.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        import googleapiclient.discovery

        dns = googleapiclient.discovery.build("dns", "v1", cache_discovery=False)
        zones_resp = dns.managedZones().list(project=project_id).execute()
        zones = zones_resp.get("managedZones", [])

        failing: list[str] = []
        for zone in zones:
            dnssec_config = zone.get("dnssecConfig", {})
            if dnssec_config.get("state", "off") != "on":
                continue
            for key_spec in dnssec_config.get("defaultKeySpecs", []):
                if key_spec.get("keyType") == "keySigning" and key_spec.get("algorithm") == "RSASHA1":
                    failing.append(zone.get("name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"DNS zones using RSASHA1 for key-signing: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No DNS zones use RSASHA1 for key-signing."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check DNSSEC key-signing algorithm: {exc}"
    return result


def _check_3_5(project_id: str) -> CISCheckResult:
    """CIS 3.5 — Ensure RSASHA1 is not used for zone-signing in DNSSEC."""
    result = CISCheckResult(
        check_id="3.5",
        title="Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Use RSASHA256, RSASHA512, or ECDSAP256SHA256 for DNSSEC zone-signing keys instead of RSASHA1.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        import googleapiclient.discovery

        dns = googleapiclient.discovery.build("dns", "v1", cache_discovery=False)
        zones_resp = dns.managedZones().list(project=project_id).execute()
        zones = zones_resp.get("managedZones", [])

        failing: list[str] = []
        for zone in zones:
            dnssec_config = zone.get("dnssecConfig", {})
            if dnssec_config.get("state", "off") != "on":
                continue
            for key_spec in dnssec_config.get("defaultKeySpecs", []):
                if key_spec.get("keyType") == "zoneSigning" and key_spec.get("algorithm") == "RSASHA1":
                    failing.append(zone.get("name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"DNS zones using RSASHA1 for zone-signing: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No DNS zones use RSASHA1 for zone-signing."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check DNSSEC zone-signing algorithm: {exc}"
    return result


def _check_3_8(project_id: str) -> CISCheckResult:
    """CIS 3.8 — Ensure Firewall Rules for ICMP are not open to the world."""
    result = CISCheckResult(
        check_id="3.8",
        title="Ensure that Firewall Rules for ICMP are not open to the world",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Remove or restrict firewall rules that allow ICMP from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.FirewallsClient()
        rules = list(client.list(project=project_id))
        failing: list[str] = []

        for rule in rules:
            if getattr(rule, "direction", "") != "INGRESS":
                continue
            if getattr(rule, "disabled", False):
                continue
            source_ranges = list(getattr(rule, "source_ranges", []) or [])
            if not any(r in ("0.0.0.0/0", "::/0") for r in source_ranges):
                continue
            for allowed in getattr(rule, "allowed", []) or []:
                proto = getattr(allowed, "I_p_protocol", "") or getattr(allowed, "ip_protocol", "")
                if proto in ("icmp", "all"):
                    failing.append(rule.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Firewall rules allowing ICMP from internet: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No firewall rules allow ICMP from 0.0.0.0/0 or ::/0."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check firewall rules: {exc}"
    return result


def _check_3_10(project_id: str) -> CISCheckResult:
    """CIS 3.10 — Ensure private Google access is enabled for all subnets."""
    result = CISCheckResult(
        check_id="3.10",
        title="Ensure Private Google Access is enabled for all subnets in a VPC",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Private Google Access on all subnets to allow VMs without external IPs to reach Google APIs.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.SubnetworksClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _region, response in agg:
            for subnet in response.subnetworks or []:
                total += 1
                if not getattr(subnet, "private_ip_google_access", False):
                    failing.append(getattr(subnet, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Subnets without Private Google Access ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"Private Google Access enabled on all {total} subnet(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Private Google Access: {exc}"
    return result


def _check_3_9(project_id: str) -> CISCheckResult:
    """CIS 3.9 — Ensure VPC Flow Logs are enabled for every subnet."""
    result = CISCheckResult(
        check_id="3.9",
        title="Ensure VPC Flow Logs are enabled for every subnet",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable VPC Flow Logs on all subnets for network monitoring and forensics.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.SubnetworksClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _region, response in agg:
            for subnet in response.subnetworks or []:
                total += 1
                log_config = getattr(subnet, "log_config", None)
                if log_config is None or not getattr(log_config, "enable", False):
                    failing.append(getattr(subnet, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Subnets without VPC Flow Logs ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"VPC Flow Logs enabled on all {total} subnet(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VPC Flow Logs: {exc}"
    return result


def _check_3_6(project_id: str) -> CISCheckResult:
    """CIS 3.6 — Ensure SSH access is restricted from the internet."""
    result = CISCheckResult(
        check_id="3.6",
        title="Ensure that SSH access is restricted from the internet (port 22)",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove or restrict firewall rules that allow TCP port 22 from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.FirewallsClient()
        rules = list(client.list(project=project_id))
        failing: list[str] = []

        for rule in rules:
            if getattr(rule, "direction", "") != "INGRESS":
                continue
            if getattr(rule, "disabled", False):
                continue
            source_ranges = list(getattr(rule, "source_ranges", []) or [])
            if not any(r in ("0.0.0.0/0", "::/0") for r in source_ranges):
                continue
            for allowed in getattr(rule, "allowed", []) or []:
                proto = getattr(allowed, "I_p_protocol", "") or getattr(allowed, "ip_protocol", "")
                ports = list(getattr(allowed, "ports", []) or [])
                if proto in ("tcp", "all") and (not ports or "22" in ports or "0-65535" in ports):
                    failing.append(rule.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Firewall rules allowing SSH from internet: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No firewall rules allow SSH (22) from 0.0.0.0/0 or ::/0."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check firewall rules: {exc}"
    return result


def _check_3_7(project_id: str) -> CISCheckResult:
    """CIS 3.7 — Ensure RDP access is restricted from the internet."""
    result = CISCheckResult(
        check_id="3.7",
        title="Ensure that RDP access is restricted from the internet (port 3389)",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove or restrict firewall rules that allow TCP port 3389 from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.FirewallsClient()
        rules = list(client.list(project=project_id))
        failing: list[str] = []

        for rule in rules:
            if getattr(rule, "direction", "") != "INGRESS":
                continue
            if getattr(rule, "disabled", False):
                continue
            source_ranges = list(getattr(rule, "source_ranges", []) or [])
            if not any(r in ("0.0.0.0/0", "::/0") for r in source_ranges):
                continue
            for allowed in getattr(rule, "allowed", []) or []:
                proto = getattr(allowed, "I_p_protocol", "") or getattr(allowed, "ip_protocol", "")
                ports = list(getattr(allowed, "ports", []) or [])
                if proto in ("tcp", "all") and (not ports or "3389" in ports or "0-65535" in ports):
                    failing.append(rule.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Firewall rules allowing RDP from internet: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No firewall rules allow RDP (3389) from 0.0.0.0/0 or ::/0."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check firewall rules: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 4.x (Virtual Machines)
# ---------------------------------------------------------------------------


def _check_4_1(project_id: str) -> CISCheckResult:
    """CIS 4.1 — Ensure instances are not configured to use default service account."""
    result = CISCheckResult(
        check_id="4.1",
        title="Ensure instances are not configured to use default service account",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=(
            "Create and assign a custom service account to each VM instance instead of using the default Compute Engine service account."
        ),
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                sas = list(getattr(instance, "service_accounts", []) or [])
                if sas:
                    email = getattr(sas[0], "email", "")
                    if email.endswith("-compute@developer.gserviceaccount.com"):
                        failing.append(getattr(instance, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances using default service account ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No instances using default service account across {total} instance(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check instance service accounts: {exc}"
    return result


def _check_4_2(project_id: str) -> CISCheckResult:
    """CIS 4.2 — Ensure instances are not configured to use the default service account with full access."""
    result = CISCheckResult(
        check_id="4.2",
        title="Ensure instances are not configured to use the default service account with full access to all APIs",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove the default service account or restrict its scopes. Do not use https://www.googleapis.com/auth/cloud-platform scope with the default SA.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                sas = list(getattr(instance, "service_accounts", []) or [])
                if sas:
                    email = getattr(sas[0], "email", "")
                    scopes = list(getattr(sas[0], "scopes", []) or [])
                    if (
                        email.endswith("-compute@developer.gserviceaccount.com")
                        and "https://www.googleapis.com/auth/cloud-platform" in scopes
                    ):
                        failing.append(getattr(instance, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances using default SA with full access ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No instances use the default service account with full API access across {total} instance(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check instance service account scopes: {exc}"
    return result


def _check_4_3(project_id: str) -> CISCheckResult:
    """CIS 4.3 — Ensure 'Block Project-wide SSH Keys' is enabled for VM instances."""
    result = CISCheckResult(
        check_id="4.3",
        title="Ensure 'Block Project-wide SSH Keys' is enabled for VM instances",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Set the 'block-project-ssh-keys' metadata key to 'true' on each VM instance to prevent project-wide SSH key access."
        ),
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                metadata = getattr(instance, "metadata", None)
                items = list(getattr(metadata, "items", []) or []) if metadata else []
                blocked = False
                for item in items:
                    key = getattr(item, "key", "")
                    value = getattr(item, "value", "")
                    if key == "block-project-ssh-keys" and value.lower() == "true":
                        blocked = True
                        break
                if not blocked:
                    failing.append(getattr(instance, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances without 'block-project-ssh-keys' ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {total} instance(s) have 'block-project-ssh-keys' enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check instance SSH key metadata: {exc}"
    return result


def _check_4_4(project_id: str) -> CISCheckResult:
    """CIS 4.4 — Ensure OS login is enabled for a project."""
    result = CISCheckResult(
        check_id="4.4",
        title="Ensure OS Login is enabled for a project",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'enable-oslogin' metadata key to 'TRUE' at the project level.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.ProjectsClient()
        project = client.get(project=project_id)
        metadata = getattr(project, "common_instance_metadata", None)
        items = list(getattr(metadata, "items", []) or []) if metadata else []

        os_login_enabled = False
        for item in items:
            key = getattr(item, "key", "")
            value = getattr(item, "value", "")
            if key == "enable-oslogin" and value.lower() == "true":
                os_login_enabled = True
                break

        if os_login_enabled:
            result.status = CheckStatus.PASS
            result.evidence = "OS Login is enabled at the project level."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "OS Login is not enabled at the project level. Set enable-oslogin=TRUE in project metadata."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check OS Login configuration: {exc}"
    return result


def _check_4_5(project_id: str) -> CISCheckResult:
    """CIS 4.5 — Ensure 'Enable connecting to serial ports' is not enabled for VM instances."""
    result = CISCheckResult(
        check_id="4.5",
        title="Ensure 'Enable connecting to serial ports' is not enabled for VM instances",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set 'serial-port-enable' metadata to 'false' or remove it from all VM instances.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                metadata = getattr(instance, "metadata", None)
                items = list(getattr(metadata, "items", []) or []) if metadata else []
                for item in items:
                    key = getattr(item, "key", "")
                    value = getattr(item, "value", "")
                    if key == "serial-port-enable" and value.lower() == "true":
                        failing.append(getattr(instance, "name", "unknown"))
                        break

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances with serial port enabled ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No instances have serial port access enabled across {total} instance(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check serial port configuration: {exc}"
    return result


def _check_4_6(project_id: str) -> CISCheckResult:
    """CIS 4.6 — Ensure IP forwarding is not enabled on instances."""
    result = CISCheckResult(
        check_id="4.6",
        title="Ensure that IP forwarding is not enabled on Instances",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Disable IP forwarding on instances unless explicitly required for NAT or routing functions.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                if getattr(instance, "can_ip_forward", False):
                    failing.append(getattr(instance, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances with IP forwarding enabled ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No instances have IP forwarding enabled across {total} instance(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check IP forwarding: {exc}"
    return result


def _check_4_7(project_id: str) -> CISCheckResult:
    """CIS 4.7 — Ensure VM disks for critical VMs are encrypted with CSEK."""
    result = CISCheckResult(
        check_id="4.7",
        title="Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Encrypt VM disks with Customer-Supplied Encryption Keys (CSEK) for critical workloads.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.DisksClient()
        agg = client.aggregated_list(project=project_id)
        no_csek: list[str] = []
        total = 0

        for _zone, response in agg:
            for disk in response.disks or []:
                total += 1
                encryption = getattr(disk, "disk_encryption_key", None)
                if encryption is None or not getattr(encryption, "sha256", None):
                    no_csek.append(getattr(disk, "name", "unknown"))

        if no_csek:
            result.status = CheckStatus.FAIL
            result.evidence = f"Disks without CSEK encryption ({len(no_csek)}/{total}): {', '.join(no_csek[:10])}"
            result.resource_ids = no_csek
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {total} disk(s) are encrypted with CSEK."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check disk encryption: {exc}"
    return result


def _check_4_8(project_id: str) -> CISCheckResult:
    """CIS 4.8 — Ensure Compute instances are launched with Shielded VM enabled."""
    result = CISCheckResult(
        check_id="4.8",
        title="Ensure Compute instances are launched with Shielded VM enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Shielded VM features (vTPM and Integrity Monitoring) on all Compute instances.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                shielded = getattr(instance, "shielded_instance_config", None)
                if shielded is None:
                    failing.append(getattr(instance, "name", "unknown"))
                else:
                    vtpm = getattr(shielded, "enable_vtpm", False)
                    integrity = getattr(shielded, "enable_integrity_monitoring", False)
                    if not vtpm or not integrity:
                        failing.append(getattr(instance, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances without Shielded VM ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {total} instance(s) have Shielded VM enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Shielded VM configuration: {exc}"
    return result


def _check_4_9(project_id: str) -> CISCheckResult:
    """CIS 4.9 — Ensure that Compute instances do not have public IP addresses."""
    result = CISCheckResult(
        check_id="4.9",
        title="Ensure that Compute instances do not have public IP addresses",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove external IP addresses from Compute instances. Use Cloud NAT or IAP for outbound/inbound access.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                for iface in getattr(instance, "network_interfaces", []) or []:
                    access_configs = list(getattr(iface, "access_configs", []) or [])
                    if access_configs:
                        for ac in access_configs:
                            nat_ip = getattr(ac, "nat_i_p", None) or getattr(ac, "nat_ip", None)
                            if nat_ip:
                                failing.append(getattr(instance, "name", "unknown"))
                                break
                        if failing and failing[-1] == getattr(instance, "name", "unknown"):
                            break

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances with public IPs ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No instances have public IP addresses across {total} instance(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check instance public IPs: {exc}"
    return result


def _check_4_11(project_id: str) -> CISCheckResult:
    """CIS 4.11 — Ensure that Compute instances have Confidential Computing enabled."""
    result = CISCheckResult(
        check_id="4.11",
        title="Ensure that Compute instances have Confidential Computing enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Confidential Computing on Compute instances for memory encryption.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient()
        agg = client.aggregated_list(project=project_id)
        failing: list[str] = []
        total = 0

        for _zone, response in agg:
            for instance in response.instances or []:
                total += 1
                confidential = getattr(instance, "confidential_instance_config", None)
                if confidential is None or not getattr(confidential, "enable_confidential_compute", False):
                    failing.append(getattr(instance, "name", "unknown"))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Instances without Confidential Computing ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {total} instance(s) have Confidential Computing enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-compute not installed. Install with: pip install google-cloud-compute"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Confidential Computing: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 5.x (Cloud Storage)
# ---------------------------------------------------------------------------


def _check_5_1(project_id: str) -> CISCheckResult:
    """CIS 5.1 — Ensure Cloud Storage buckets are not publicly accessible."""
    result = CISCheckResult(
        check_id="5.1",
        title="Ensure that Cloud Storage bucket is not anonymously or publicly accessible",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove allUsers and allAuthenticatedUsers from bucket IAM policies.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        storage = _import_google_cloud_module("storage")

        client = storage.Client(project=project_id)
        public_buckets: list[str] = []

        for bucket in client.list_buckets():
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public_buckets.append(bucket.name)
                        break
            except Exception as exc:
                # IAM check is best-effort per bucket
                logger.debug("Could not check IAM policy for bucket %s: %s", bucket.name, exc)

        if public_buckets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Publicly accessible buckets: {', '.join(public_buckets[:10])}"
            result.resource_ids = public_buckets
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No buckets with public (allUsers/allAuthenticatedUsers) IAM bindings found."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-storage not installed. Install with: pip install google-cloud-storage"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud Storage buckets: {exc}"
    return result


def _check_5_2(project_id: str) -> CISCheckResult:
    """CIS 5.2 — Ensure that Cloud Storage buckets have uniform bucket-level access enabled."""
    result = CISCheckResult(
        check_id="5.2",
        title="Ensure that Cloud Storage buckets have uniform bucket-level access enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable uniform bucket-level access on all Cloud Storage buckets to use IAM exclusively for access control.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        storage = _import_google_cloud_module("storage")

        client = storage.Client(project=project_id)
        failing: list[str] = []
        total = 0

        for bucket in client.list_buckets():
            total += 1
            iam_config = bucket.iam_configuration
            if not iam_config.uniform_bucket_level_access_enabled:
                failing.append(bucket.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Buckets without uniform access ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {total} bucket(s) have uniform bucket-level access enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-storage not installed. Install with: pip install google-cloud-storage"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check bucket uniform access: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 6.x (Cloud SQL)
# ---------------------------------------------------------------------------


def _check_6_1(project_id: str) -> CISCheckResult:
    """CIS 6.1 — Ensure Cloud SQL database instances require all incoming connections to use SSL."""
    result = CISCheckResult(
        check_id="6.1",
        title="Ensure Cloud SQL database instances require all incoming connections to use SSL",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable 'Require SSL' (requireSsl) on all Cloud SQL instances to encrypt connections in transit.",
        cis_section=_SQL_SECTION,
    )
    try:
        import googleapiclient.discovery

        sqladmin = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        resp = sqladmin.instances().list(project=project_id).execute()
        instances = resp.get("items", [])

        failing: list[str] = []
        for inst in instances:
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            ip_config = settings.get("ipConfiguration", {})
            require_ssl = ip_config.get("requireSsl", False)
            if not require_ssl:
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Cloud SQL instances not requiring SSL ({len(failing)}/{len(instances)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(instances)} Cloud SQL instance(s) require SSL connections."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud SQL SSL configuration: {exc}"
    return result


def _check_6_2(project_id: str) -> CISCheckResult:
    """CIS 6.2 — Ensure Cloud SQL database instances do not have public IPs."""
    result = CISCheckResult(
        check_id="6.2",
        title="Ensure that Cloud SQL database instances do not have public IPs",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove public IP addresses from Cloud SQL instances and use private IP or Cloud SQL Proxy instead.",
        cis_section=_SQL_SECTION,
    )
    try:
        import googleapiclient.discovery

        sqladmin = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        resp = sqladmin.instances().list(project=project_id).execute()
        instances = resp.get("items", [])

        failing: list[str] = []
        for inst in instances:
            name = inst.get("name", "unknown")
            ip_addresses = inst.get("ipAddresses", [])
            for ip in ip_addresses:
                if ip.get("type") == "PRIMARY":
                    failing.append(name)
                    break

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Cloud SQL instances with public IPs ({len(failing)}/{len(instances)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No Cloud SQL instances have public IP addresses across {len(instances)} instance(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud SQL public IPs: {exc}"
    return result


def _check_6_3(project_id: str) -> CISCheckResult:
    """CIS 6.3 — Ensure Cloud SQL database instances have automated backups enabled."""
    result = CISCheckResult(
        check_id="6.3",
        title="Ensure that Cloud SQL database instances have automated backups enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable automated backups on all Cloud SQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        import googleapiclient.discovery

        sqladmin = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        resp = sqladmin.instances().list(project=project_id).execute()
        instances = resp.get("items", [])

        failing: list[str] = []
        for inst in instances:
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            backup_config = settings.get("backupConfiguration", {})
            if not backup_config.get("enabled", False):
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Cloud SQL instances without automated backups ({len(failing)}/{len(instances)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(instances)} Cloud SQL instance(s) have automated backups enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud SQL backup configuration: {exc}"
    return result


def _check_6_4(project_id: str) -> CISCheckResult:
    """CIS 6.4 — Ensure Cloud SQL PostgreSQL instances have log_error_verbosity set to DEFAULT or stricter."""
    result = CISCheckResult(
        check_id="6.4",
        title="Ensure Cloud SQL for PostgreSQL instances have log_error_verbosity set to DEFAULT or stricter",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_error_verbosity database flag to DEFAULT or TERSE on PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        import googleapiclient.discovery

        sqladmin = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        resp = sqladmin.instances().list(project=project_id).execute()
        instances = resp.get("items", [])

        failing: list[str] = []
        acceptable_values = {"default", "terse"}
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_error_verbosity":
                    flag_value = flag.get("value", "").lower()
                    break
            if flag_value is None or flag_value not in acceptable_values:
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without proper log_error_verbosity: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_error_verbosity set to DEFAULT or stricter."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_error_verbosity: {exc}"
    return result


def _check_6_5(project_id: str) -> CISCheckResult:
    """CIS 6.5 — Ensure Cloud SQL PostgreSQL instances have log_connections enabled."""
    result = CISCheckResult(
        check_id="6.5",
        title="Ensure that Cloud SQL for PostgreSQL instances have log_connections database flag set to on",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_connections database flag to 'on' on all PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        import googleapiclient.discovery

        sqladmin = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        resp = sqladmin.instances().list(project=project_id).execute()
        instances = resp.get("items", [])

        failing: list[str] = []
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_connections":
                    flag_value = flag.get("value", "").lower()
                    break
            if flag_value != "on":
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without log_connections enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_connections enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_connections: {exc}"
    return result


def _check_6_6(project_id: str) -> CISCheckResult:
    """CIS 6.6 — Ensure Cloud SQL PostgreSQL instances have log_disconnections enabled."""
    result = CISCheckResult(
        check_id="6.6",
        title="Ensure that Cloud SQL for PostgreSQL instances have log_disconnections database flag set to on",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_disconnections database flag to 'on' on all PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        import googleapiclient.discovery

        sqladmin = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        resp = sqladmin.instances().list(project=project_id).execute()
        instances = resp.get("items", [])

        failing: list[str] = []
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_disconnections":
                    flag_value = flag.get("value", "").lower()
                    break
            if flag_value != "on":
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without log_disconnections enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_disconnections enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_disconnections: {exc}"
    return result


def _check_6_7(project_id: str) -> CISCheckResult:
    """CIS 6.7 — Ensure Cloud SQL PostgreSQL instances have log_min_duration_statement set to -1."""
    result = CISCheckResult(
        check_id="6.7",
        title="Ensure that Cloud SQL for PostgreSQL instances have log_min_duration_statement set to -1",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_min_duration_statement database flag to '-1' to disable logging of statement durations (prevents sensitive data leakage).",
        cis_section=_SQL_SECTION,
    )
    try:
        import googleapiclient.discovery

        sqladmin = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        resp = sqladmin.instances().list(project=project_id).execute()
        instances = resp.get("items", [])

        failing: list[str] = []
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_min_duration_statement":
                    flag_value = flag.get("value", "")
                    break
            if flag_value != "-1":
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without log_min_duration_statement=-1: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_min_duration_statement set to -1."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_min_duration_statement: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 7.x (BigQuery)
# ---------------------------------------------------------------------------


def _check_7_1(project_id: str) -> CISCheckResult:
    """CIS 7.1 — Ensure BigQuery datasets are not anonymously or publicly accessible."""
    result = CISCheckResult(
        check_id="7.1",
        title="Ensure that BigQuery datasets are not anonymously or publicly accessible",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove allUsers and allAuthenticatedUsers from BigQuery dataset IAM policies.",
        cis_section=_BIGQUERY_SECTION,
    )
    try:
        import googleapiclient.discovery

        bq = googleapiclient.discovery.build("bigquery", "v2", cache_discovery=False)
        datasets_resp = bq.datasets().list(projectId=project_id).execute()
        datasets = datasets_resp.get("datasets", [])

        public_datasets: list[str] = []
        for ds in datasets:
            ds_ref = ds.get("datasetReference", {})
            ds_id = ds_ref.get("datasetId", "unknown")
            ds_detail = bq.datasets().get(projectId=project_id, datasetId=ds_id).execute()
            access = ds_detail.get("access", [])
            for entry in access:
                special_group = entry.get("specialGroup", "")
                iam_member = entry.get("iamMember", "")
                if special_group in ("allUsers", "allAuthenticatedUsers") or iam_member in ("allUsers", "allAuthenticatedUsers"):
                    public_datasets.append(ds_id)
                    break

        if public_datasets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Publicly accessible BigQuery datasets: {', '.join(public_datasets[:10])}"
            result.resource_ids = public_datasets
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No BigQuery datasets are publicly accessible across {len(datasets)} dataset(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check BigQuery dataset access: {exc}"
    return result


def _check_7_2(project_id: str) -> CISCheckResult:
    """CIS 7.2 — Ensure BigQuery datasets have default table expiration configured."""
    result = CISCheckResult(
        check_id="7.2",
        title="Ensure that a default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set a default table expiration on all BigQuery datasets to automatically clean up unused tables.",
        cis_section=_BIGQUERY_SECTION,
    )
    try:
        import googleapiclient.discovery

        bq = googleapiclient.discovery.build("bigquery", "v2", cache_discovery=False)
        datasets_resp = bq.datasets().list(projectId=project_id).execute()
        datasets = datasets_resp.get("datasets", [])

        failing: list[str] = []
        for ds in datasets:
            ds_ref = ds.get("datasetReference", {})
            ds_id = ds_ref.get("datasetId", "unknown")
            ds_detail = bq.datasets().get(projectId=project_id, datasetId=ds_id).execute()
            expiration = ds_detail.get("defaultTableExpirationMs")
            if not expiration:
                failing.append(ds_id)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = (
                f"BigQuery datasets without default table expiration ({len(failing)}/{len(datasets)}): {', '.join(failing[:10])}"
            )
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(datasets)} BigQuery dataset(s) have default table expiration configured."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check BigQuery dataset expiration: {exc}"
    return result


def _check_7_3(project_id: str) -> CISCheckResult:
    """CIS 7.3 — Ensure BigQuery datasets are encrypted with Customer-Managed Keys (CMK)."""
    result = CISCheckResult(
        check_id="7.3",
        title="Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK)",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set a default KMS key on all BigQuery datasets so that new tables are automatically encrypted with CMEK.",
        cis_section=_BIGQUERY_SECTION,
    )
    try:
        import googleapiclient.discovery

        bq = googleapiclient.discovery.build("bigquery", "v2", cache_discovery=False)
        datasets_resp = bq.datasets().list(projectId=project_id).execute()
        datasets = datasets_resp.get("datasets", [])

        failing: list[str] = []
        for ds in datasets:
            ds_ref = ds.get("datasetReference", {})
            ds_id = ds_ref.get("datasetId", "unknown")
            ds_detail = bq.datasets().get(projectId=project_id, datasetId=ds_id).execute()
            default_encryption = ds_detail.get("defaultEncryptionConfiguration", {})
            if not default_encryption or not default_encryption.get("kmsKeyName"):
                failing.append(ds_id)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"BigQuery datasets without CMEK encryption ({len(failing)}/{len(datasets)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(datasets)} BigQuery dataset(s) are encrypted with CMEK."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check BigQuery dataset encryption: {exc}"
    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_benchmark(
    project_id: str | None = None,
    checks: list[str] | None = None,
) -> GCPCISReport:
    """Run CIS GCP Foundation Benchmark v3.0 checks.

    Args:
        project_id: GCP project ID. Falls back to GOOGLE_CLOUD_PROJECT env var.
        checks: Optional list of check IDs to run (e.g. ['1.5', '3.6']).
            Runs all checks if omitted.

    Returns:
        GCPCISReport with pass/fail results for each check.

    Raises:
        CloudDiscoveryError: if no GCP SDK packages are installed.
    """
    resolved_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    if not resolved_project:
        raise CloudDiscoveryError("GCP project ID required. Set GOOGLE_CLOUD_PROJECT env var or pass project_id.")

    # Verify at least one GCP SDK is importable
    _has_sdk = False
    for mod in ("google.cloud.compute_v1", "google.cloud.logging_v2", "google.cloud.storage", "googleapiclient"):
        try:
            __import__(mod)
            _has_sdk = True
            break
        except ImportError:
            continue

    if not _has_sdk:
        raise CloudDiscoveryError("At least one GCP SDK is required. Install with: pip install 'agent-bom[gcp]'")

    report = GCPCISReport(project_id=resolved_project)

    all_checks: list[tuple[str, Any]] = [
        ("1.1", lambda: _check_1_1(resolved_project)),
        ("1.2", lambda: _check_1_2(resolved_project)),
        ("1.3", lambda: _check_1_3(resolved_project)),
        ("1.4", lambda: _check_1_4(resolved_project)),
        ("1.5", lambda: _check_1_5(resolved_project)),
        ("1.6", lambda: _check_1_6(resolved_project)),
        ("1.7", lambda: _check_1_7(resolved_project)),
        ("1.8", lambda: _check_1_8(resolved_project)),
        ("1.9", lambda: _check_1_9(resolved_project)),
        ("1.10", lambda: _check_1_10(resolved_project)),
        ("1.11", lambda: _check_1_11(resolved_project)),
        ("1.12", lambda: _check_1_12(resolved_project)),
        ("1.13", lambda: _check_1_13(resolved_project)),
        ("1.14", lambda: _check_1_14(resolved_project)),
        ("1.15", lambda: _check_1_15(resolved_project)),
        ("2.1", lambda: _check_2_1(resolved_project)),
        ("2.2", lambda: _check_2_2(resolved_project)),
        ("2.3", lambda: _check_2_3(resolved_project)),
        ("2.4", lambda: _check_2_4(resolved_project)),
        ("2.5", lambda: _check_2_5(resolved_project)),
        ("2.6", lambda: _check_2_6(resolved_project)),
        ("2.7", lambda: _check_2_7(resolved_project)),
        ("2.8", lambda: _check_2_8(resolved_project)),
        ("2.9", lambda: _check_2_9(resolved_project)),
        ("2.10", lambda: _check_2_10(resolved_project)),
        ("2.11", lambda: _check_2_11(resolved_project)),
        ("2.12", lambda: _check_2_12(resolved_project)),
        ("3.1", lambda: _check_3_1(resolved_project)),
        ("3.2", lambda: _check_3_2(resolved_project)),
        ("3.3", lambda: _check_3_3(resolved_project)),
        ("3.4", lambda: _check_3_4(resolved_project)),
        ("3.5", lambda: _check_3_5(resolved_project)),
        ("3.6", lambda: _check_3_6(resolved_project)),
        ("3.7", lambda: _check_3_7(resolved_project)),
        ("3.8", lambda: _check_3_8(resolved_project)),
        ("3.9", lambda: _check_3_9(resolved_project)),
        ("3.10", lambda: _check_3_10(resolved_project)),
        ("4.1", lambda: _check_4_1(resolved_project)),
        ("4.2", lambda: _check_4_2(resolved_project)),
        ("4.3", lambda: _check_4_3(resolved_project)),
        ("4.4", lambda: _check_4_4(resolved_project)),
        ("4.5", lambda: _check_4_5(resolved_project)),
        ("4.6", lambda: _check_4_6(resolved_project)),
        ("4.7", lambda: _check_4_7(resolved_project)),
        ("4.8", lambda: _check_4_8(resolved_project)),
        ("4.9", lambda: _check_4_9(resolved_project)),
        ("4.11", lambda: _check_4_11(resolved_project)),
        ("5.1", lambda: _check_5_1(resolved_project)),
        ("5.2", lambda: _check_5_2(resolved_project)),
        ("6.1", lambda: _check_6_1(resolved_project)),
        ("6.2", lambda: _check_6_2(resolved_project)),
        ("6.3", lambda: _check_6_3(resolved_project)),
        ("6.4", lambda: _check_6_4(resolved_project)),
        ("6.5", lambda: _check_6_5(resolved_project)),
        ("6.6", lambda: _check_6_6(resolved_project)),
        ("6.7", lambda: _check_6_7(resolved_project)),
        ("7.1", lambda: _check_7_1(resolved_project)),
        ("7.2", lambda: _check_7_2(resolved_project)),
        ("7.3", lambda: _check_7_3(resolved_project)),
    ]

    for check_id, check_fn in all_checks:
        if checks and check_id not in checks:
            continue
        try:
            report.checks.append(check_fn())
        except Exception as exc:
            logger.warning("GCP CIS check %s failed with exception: %s", check_id, exc)
            report.checks.append(
                CISCheckResult(
                    check_id=check_id,
                    title=f"Check {check_id}",
                    status=CheckStatus.ERROR,
                    severity="unknown",
                    evidence=str(exc),
                )
            )

    # Structured remediation per #665.
    from agent_bom.cloud.cis_remediation import attach_all

    attach_all(report, cloud="gcp")

    return report
