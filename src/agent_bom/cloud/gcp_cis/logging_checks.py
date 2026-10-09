"""CIS GCP 2.x: audit logging, sinks, log metrics and alerts."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import (
    _LOGGING_SECTION,
    _creds_kwargs,
    _gcp_managed_zones,
    _seams,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_2_1(project_id: str) -> CISCheckResult:
    """CIS 2.1 — Ensure Cloud Audit Logs is configured to log Admin Activity and Data Access."""
    result = CISCheckResult(
        check_id="2.1",
        title="Cloud Audit Logs configured for all services",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable DATA_READ and DATA_WRITE audit log types for all services in the project IAM policy.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        crm = _seams()._discovery_client("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        audit_configs = policy.get("auditConfigs", [])

        # Look for allServices audit config with DATA_READ + DATA_WRITE
        all_services_config = next((c for c in audit_configs if c.get("service") == "allServices"), None)

        if all_services_config:
            log_types = {al.get("logType") for al in all_services_config.get("auditLogConfigs", [])}
            missing = {"DATA_READ", "DATA_WRITE"} - log_types
            if missing:
                result.status = CheckStatus.FAIL
                result.evidence = f"Audit log types not enabled for allServices: {', '.join(sorted(missing))}"
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
        result.evidence = f"Could not check audit log configuration: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_2(project_id: str) -> CISCheckResult:
    """CIS 2.2 — Ensure a log sink is configured for all log entries."""
    result = CISCheckResult(
        check_id="2.2",
        title="Log sink exports all log entries",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Create a log sink in Cloud Logging that exports all log entries"
            " (_Default or custom filter) to Cloud Storage, BigQuery, or Pub/Sub."
        ),
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.ConfigServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log sinks: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_3(project_id: str) -> CISCheckResult:
    """CIS 2.3 — Ensure log metric filter and alerts exist for Project Ownership changes."""
    result = CISCheckResult(
        check_id="2.3",
        title="Log metric filter and alerts for Project Ownership changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for (protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee).',  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_4(project_id: str) -> CISCheckResult:
    """CIS 2.4 — Ensure log metric filter and alerts exist for Audit Configuration changes."""
    result = CISCheckResult(
        check_id="2.4",
        title="Log metric filter and alerts for Audit Configuration changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*.',  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_5(project_id: str) -> CISCheckResult:
    """CIS 2.5 — Ensure log metric filter and alerts exist for Custom Role changes."""
    result = CISCheckResult(
        check_id="2.5",
        title="Log metric filter and alerts for Custom Role changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="iam_role" AND (methodName="google.iam.admin.v1.CreateRole" OR methodName="google.iam.admin.v1.DeleteRole" OR methodName="google.iam.admin.v1.UpdateRole").',  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_6(project_id: str) -> CISCheckResult:
    """CIS 2.6 — Ensure log metric filter and alerts exist for VPC Network Firewall Rule changes."""
    result = CISCheckResult(
        check_id="2.6",
        title="Log metric filter and alerts for VPC firewall rule changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gce_firewall_rule" AND (methodName:"compute.firewalls.patch" OR methodName:"compute.firewalls.insert" OR methodName:"compute.firewalls.delete").',  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_7(project_id: str) -> CISCheckResult:
    """CIS 2.7 — Ensure log metric filter and alerts exist for VPC Network Route changes."""
    result = CISCheckResult(
        check_id="2.7",
        title="Log metric filter and alerts for VPC route changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gce_route" AND (methodName:"compute.routes.delete" OR methodName:"compute.routes.insert").',  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_8(project_id: str) -> CISCheckResult:
    """CIS 2.8 — Ensure log metric filter and alerts exist for VPC Network changes."""
    result = CISCheckResult(
        check_id="2.8",
        title="Log metric filter and alerts for VPC network changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gce_network" AND (methodName:"compute.networks.insert" OR methodName:"compute.networks.patch" OR methodName:"compute.networks.delete" OR methodName:"compute.networks.removePeering" OR methodName:"compute.networks.addPeering").',  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_9(project_id: str) -> CISCheckResult:
    """CIS 2.9 — Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes."""
    result = CISCheckResult(
        check_id="2.9",
        title="Log metric filter and alerts for Cloud Storage IAM changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions".',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_10(project_id: str) -> CISCheckResult:
    """CIS 2.10 — Ensure log metric filter and alerts exist for SQL instance configuration changes."""
    result = CISCheckResult(
        check_id="2.10",
        title="Log metric filter and alerts for SQL instance config changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for protoPayload.methodName="cloudsql.instances.update".',
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_11(project_id: str) -> CISCheckResult:
    """CIS 2.11 — Ensure log metric filter and alerts exist for DNS Zone changes."""
    result = CISCheckResult(
        check_id="2.11",
        title="Log metric filter and alerts for DNS zone changes",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation='Create a log metric filter for resource.type="dns_managed_zone" AND (methodName:"dns.managedZones.create" OR methodName:"dns.managedZones.patch" OR methodName:"dns.managedZones.update" OR methodName:"dns.managedZones.delete").',  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_LOGGING_SECTION,
    )
    try:
        logging_v2 = _seams()._import_google_cloud_module("logging_v2")

        client = logging_v2.MetricsServiceV2Client(**_creds_kwargs())
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
        result.evidence = f"Could not check log metrics: {sanitize_discovery_warning(exc)}"
    return result


def _check_2_12(project_id: str) -> CISCheckResult:
    """CIS 2.12 — Ensure Cloud DNS logging is enabled for all VPC networks."""
    result = CISCheckResult(
        check_id="2.12",
        title="Cloud DNS logging enabled for all VPC networks",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable DNS logging on all Cloud DNS managed zones by setting the logging configuration.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        zones = _gcp_managed_zones(project_id)

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
        result.evidence = f"Could not check Cloud DNS logging: {sanitize_discovery_warning(exc)}"
    return result
