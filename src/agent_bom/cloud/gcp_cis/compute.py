"""CIS GCP 4.x: virtual machine instance hardening."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import (
    _COMPUTE_SECTION,
    _creds_kwargs,
    _seams,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_4_1(project_id: str) -> CISCheckResult:
    """CIS 4.1 — Ensure instances are not configured to use default service account."""
    result = CISCheckResult(
        check_id="4.1",
        title="Instances not using default service account",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=(
            "Create and assign a custom service account to each VM instance instead of using the default Compute Engine service account."
        ),
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check instance service accounts: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_2(project_id: str) -> CISCheckResult:
    """CIS 4.2 — Ensure instances are not configured to use the default service account with full access."""
    result = CISCheckResult(
        check_id="4.2",
        title="Instances not using default service account with full API access",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove the default service account or restrict its scopes. Do not use https://www.googleapis.com/auth/cloud-platform scope with the default SA.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check instance service account scopes: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_3(project_id: str) -> CISCheckResult:
    """CIS 4.3 — Ensure 'Block Project-wide SSH Keys' is enabled for VM instances."""
    result = CISCheckResult(
        check_id="4.3",
        title="Block Project-wide SSH Keys enabled on VMs",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Set the 'block-project-ssh-keys' metadata key to 'true' on each VM instance to prevent project-wide SSH key access."
        ),
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check instance SSH key metadata: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_4(project_id: str) -> CISCheckResult:
    """CIS 4.4 — Ensure OS login is enabled for a project."""
    result = CISCheckResult(
        check_id="4.4",
        title="OS Login enabled for the project",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'enable-oslogin' metadata key to 'TRUE' at the project level.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.ProjectsClient(**_creds_kwargs())
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
        result.evidence = f"Could not check OS Login configuration: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_5(project_id: str) -> CISCheckResult:
    """CIS 4.5 — Ensure 'Enable connecting to serial ports' is not enabled for VM instances."""
    result = CISCheckResult(
        check_id="4.5",
        title="Serial-port connection disabled on VMs",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set 'serial-port-enable' metadata to 'false' or remove it from all VM instances.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check serial port configuration: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_6(project_id: str) -> CISCheckResult:
    """CIS 4.6 — Ensure IP forwarding is not enabled on instances."""
    result = CISCheckResult(
        check_id="4.6",
        title="IP forwarding disabled on instances",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Disable IP forwarding on instances unless explicitly required for NAT or routing functions.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check IP forwarding: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_7(project_id: str) -> CISCheckResult:
    """CIS 4.7 — Ensure VM disks for critical VMs are encrypted with CSEK."""
    result = CISCheckResult(
        check_id="4.7",
        title="Critical VM disks encrypted with CSEK",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Encrypt VM disks with Customer-Supplied Encryption Keys (CSEK) for critical workloads.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.DisksClient(**_creds_kwargs())
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
        result.evidence = f"Could not check disk encryption: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_8(project_id: str) -> CISCheckResult:
    """CIS 4.8 — Ensure Compute instances are launched with Shielded VM enabled."""
    result = CISCheckResult(
        check_id="4.8",
        title="Compute instances launched with Shielded VM",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Shielded VM features (vTPM and Integrity Monitoring) on all Compute instances.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check Shielded VM configuration: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_9(project_id: str) -> CISCheckResult:
    """CIS 4.9 — Ensure that Compute instances do not have public IP addresses."""
    result = CISCheckResult(
        check_id="4.9",
        title="Compute instances lack public IP addresses",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove external IP addresses from Compute instances. Use Cloud NAT or IAP for outbound/inbound access.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check instance public IPs: {sanitize_discovery_warning(exc)}"
    return result


def _check_4_11(project_id: str) -> CISCheckResult:
    """CIS 4.11 — Ensure that Compute instances have Confidential Computing enabled."""
    result = CISCheckResult(
        check_id="4.11",
        title="Confidential Computing enabled on instances",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Confidential Computing on Compute instances for memory encryption.",
        cis_section=_COMPUTE_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.InstancesClient(**_creds_kwargs())
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
        result.evidence = f"Could not check Confidential Computing: {sanitize_discovery_warning(exc)}"
    return result
