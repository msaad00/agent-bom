"""CIS Google Cloud Platform Foundation Benchmark v3.0 — live project checks.

Runs read-only GCP API calls against the CIS GCP Foundation Benchmark v3.0
covering IAM, Logging, Networking, and Storage.

Required roles (all read-only):
    roles/iam.securityReviewer
    roles/logging.viewer
    roles/compute.networkViewer
    roles/storage.objectViewer (for bucket IAM inspection)

Authentication uses Application Default Credentials:
    gcloud auth application-default login
    or GOOGLE_APPLICATION_CREDENTIALS env var.

Install: ``pip install 'agent-bom[gcp]'``
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from .aws_cis_benchmark import CheckStatus, CISCheckResult
from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


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
_STORAGE_SECTION = "5 - Cloud Storage"


# ---------------------------------------------------------------------------
# Individual checks — CIS 1.x (Identity and Access Management)
# ---------------------------------------------------------------------------


def _check_1_4(project_id: str) -> CISCheckResult:
    """CIS 1.4 — Ensure service account keys are not created for user-managed service accounts."""
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure service account keys are not created for user-managed service accounts",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Delete user-managed service account keys and use short-lived credentials via Workload Identity or impersonation instead.",
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
                user_members = [m for m in members if not m.startswith("serviceAccount:") or "gserviceaccount.com" not in m]
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
        recommendation="Create a log sink in Cloud Logging that exports all log entries (_Default or custom filter) to Cloud Storage, BigQuery, or Pub/Sub.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        from google.cloud import logging_v2

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
        from google.cloud import compute_v1

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
        from google.cloud import compute_v1

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
        from google.cloud import compute_v1

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
        from google.cloud import storage

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
            except Exception:
                pass  # IAM check is best-effort per bucket

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
        ("1.4", lambda: _check_1_4(resolved_project)),
        ("1.5", lambda: _check_1_5(resolved_project)),
        ("2.1", lambda: _check_2_1(resolved_project)),
        ("2.2", lambda: _check_2_2(resolved_project)),
        ("3.1", lambda: _check_3_1(resolved_project)),
        ("3.6", lambda: _check_3_6(resolved_project)),
        ("3.7", lambda: _check_3_7(resolved_project)),
        ("5.1", lambda: _check_5_1(resolved_project)),
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

    return report
