"""CIS GCP 1.1-1.8: identity, service accounts and key hygiene."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import (
    _IAM_SECTION,
    _seams,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_1_1(project_id: str) -> CISCheckResult:
    """CIS 1.1 — Ensure corporate login credentials are used."""
    result = CISCheckResult(
        check_id="1.1",
        title="Corporate login credentials used",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove IAM bindings for members using gmail.com accounts. Use corporate/organisational login credentials instead.",
        cis_section=_IAM_SECTION,
    )
    try:
        crm = _seams()._discovery_client("cloudresourcemanager", "v1")
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
        result.evidence = f"Could not check IAM policy for gmail accounts: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_2(project_id: str) -> CISCheckResult:
    """CIS 1.2 — MFA enforced for all users."""
    return CISCheckResult(
        check_id="1.2",
        title="MFA enforced for all users",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        evidence="MFA enforcement is configured at the Google Workspace / Cloud Identity level and cannot be verified via project-level API calls. Manual verification required.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        recommendation="Enable 2-Step Verification enforcement in Google Workspace Admin Console under Security > 2-Step Verification.",
        cis_section=_IAM_SECTION,
    )


def _check_1_3(project_id: str) -> CISCheckResult:
    """CIS 1.3 — Ensure Security Key enforcement is enabled for all admin accounts."""
    return CISCheckResult(
        check_id="1.3",
        title="Security Key enforcement for admin accounts",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        evidence="Security Key enforcement is configured at the Google Workspace / Cloud Identity level and cannot be verified via project-level API calls. Manual verification required.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        recommendation="Enforce Security Key usage for all admin accounts in Google Workspace Admin Console.",
        cis_section=_IAM_SECTION,
    )


def _check_1_4(project_id: str) -> CISCheckResult:
    """CIS 1.4 — Ensure service account keys are not created for user-managed service accounts."""
    result = CISCheckResult(
        check_id="1.4",
        title="No user-managed service account keys",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Delete user-managed service account keys and use short-lived credentials via Workload Identity or impersonation instead."
        ),
        cis_section=_IAM_SECTION,
    )
    try:
        from google.oauth2 import service_account as _sa  # noqa: F401 — availability check

        iam_service = _seams()._discovery_client("iam", "v1")
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
        result.evidence = f"Could not check service account keys: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_5(project_id: str) -> CISCheckResult:
    """CIS 1.5 — Ensure primitive roles (Owner/Editor) are not used on the project."""
    result = CISCheckResult(
        check_id="1.5",
        title="No primitive roles (Owner/Editor) at project level",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Replace primitive Owner/Editor bindings with predefined or custom roles following least privilege.",
        cis_section=_IAM_SECTION,
    )
    primitive_roles = {"roles/owner", "roles/editor"}
    try:
        crm = _seams()._discovery_client("cloudresourcemanager", "v1")
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
        result.evidence = f"Could not check IAM policy: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_6(project_id: str) -> CISCheckResult:
    """CIS 1.6 — Ensure service account has no admin privileges."""
    result = CISCheckResult(
        check_id="1.6",
        title="Service accounts lack admin privileges",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=(
            "Remove roles/owner, roles/editor, and roles/iam.admin from service accounts. Use fine-grained predefined roles instead."
        ),
        cis_section=_IAM_SECTION,
    )
    admin_roles = {"roles/owner", "roles/editor", "roles/iam.admin"}
    try:
        crm = _seams()._discovery_client("cloudresourcemanager", "v1")
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
        result.evidence = f"Could not check service account admin privileges: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_7(project_id: str) -> CISCheckResult:
    """CIS 1.7 — Ensure user-managed service accounts do not have admin privileges."""
    result = CISCheckResult(
        check_id="1.7",
        title="User-managed service accounts lack admin privileges",
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
        crm = _seams()._discovery_client("cloudresourcemanager", "v1")
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
        result.evidence = f"Could not check user-managed service account admin privileges: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_8(project_id: str) -> CISCheckResult:
    """CIS 1.8 — Ensure rotation for user-managed service account keys is within 90 days."""
    result = CISCheckResult(
        check_id="1.8",
        title="User-managed service account keys rotated within 90 days",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Rotate user-managed service account keys every 90 days or less. Prefer short-lived credentials via Workload Identity.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_IAM_SECTION,
    )
    try:
        import datetime

        iam_service = _seams()._discovery_client("iam", "v1")
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
        result.evidence = f"Could not check service account key rotation: {sanitize_discovery_warning(exc)}"
    return result
