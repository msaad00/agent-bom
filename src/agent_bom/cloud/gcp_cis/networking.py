"""CIS GCP 3.x: networks, DNS, firewall rules and subnet flow logs."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import (
    _NETWORK_SECTION,
    _creds_kwargs,
    _gcp_managed_zones,
    _seams,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_3_1(project_id: str) -> CISCheckResult:
    """CIS 3.1 — Ensure the default VPC network does not exist in a project."""
    result = CISCheckResult(
        check_id="3.1",
        title="No default VPC network in the project",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Delete the 'default' VPC network and create custom VPC networks with explicit firewall rules.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.NetworksClient(**_creds_kwargs())
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
        result.evidence = f"Could not check VPC networks: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_2(project_id: str) -> CISCheckResult:
    """CIS 3.2 — Ensure legacy networks do not exist in the project."""
    result = CISCheckResult(
        check_id="3.2",
        title="No legacy networks in the project",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Delete legacy networks and create VPC networks with custom subnet mode instead.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.NetworksClient(**_creds_kwargs())
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
        result.evidence = f"Could not check for legacy networks: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_3(project_id: str) -> CISCheckResult:
    """CIS 3.3 — Ensure DNSSEC is enabled for Cloud DNS."""
    result = CISCheckResult(
        check_id="3.3",
        title="DNSSEC enabled for Cloud DNS",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable DNSSEC on all public Cloud DNS managed zones.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        zones = _gcp_managed_zones(project_id)

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
        result.evidence = f"Could not check DNSSEC configuration: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_4(project_id: str) -> CISCheckResult:
    """CIS 3.4 — Ensure RSASHA1 is not used for key-signing in DNSSEC."""
    result = CISCheckResult(
        check_id="3.4",
        title="RSASHA1 not used for DNSSEC key-signing key",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Use RSASHA256, RSASHA512, or ECDSAP256SHA256 for DNSSEC key-signing keys instead of RSASHA1.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        zones = _gcp_managed_zones(project_id)

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
        result.evidence = f"Could not check DNSSEC key-signing algorithm: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_5(project_id: str) -> CISCheckResult:
    """CIS 3.5 — Ensure RSASHA1 is not used for zone-signing in DNSSEC."""
    result = CISCheckResult(
        check_id="3.5",
        title="RSASHA1 not used for DNSSEC zone-signing key",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Use RSASHA256, RSASHA512, or ECDSAP256SHA256 for DNSSEC zone-signing keys instead of RSASHA1.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        zones = _gcp_managed_zones(project_id)

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
        result.evidence = f"Could not check DNSSEC zone-signing algorithm: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_8(project_id: str) -> CISCheckResult:
    """CIS 3.8 — Ensure Firewall Rules for ICMP are not open to the world."""
    result = CISCheckResult(
        check_id="3.8",
        title="ICMP firewall rules not open to the world",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Remove or restrict firewall rules that allow ICMP from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.FirewallsClient(**_creds_kwargs())
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
        result.evidence = f"Could not check firewall rules: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_10(project_id: str) -> CISCheckResult:
    """CIS 3.10 — Ensure private Google access is enabled for all subnets."""
    result = CISCheckResult(
        check_id="3.10",
        title="Private Google Access enabled on all subnets",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Private Google Access on all subnets to allow VMs without external IPs to reach Google APIs.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.SubnetworksClient(**_creds_kwargs())
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
        result.evidence = f"Could not check Private Google Access: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_9(project_id: str) -> CISCheckResult:
    """CIS 3.9 — Ensure VPC Flow Logs are enabled for every subnet."""
    result = CISCheckResult(
        check_id="3.9",
        title="VPC Flow Logs enabled on every subnet",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable VPC Flow Logs on all subnets for network monitoring and forensics.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.SubnetworksClient(**_creds_kwargs())
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
        result.evidence = f"Could not check VPC Flow Logs: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_6(project_id: str) -> CISCheckResult:
    """CIS 3.6 — Ensure SSH access is restricted from the internet."""
    result = CISCheckResult(
        check_id="3.6",
        title="SSH (port 22) restricted from the internet",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove or restrict firewall rules that allow TCP port 22 from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.FirewallsClient(**_creds_kwargs())
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
        result.evidence = f"Could not check firewall rules: {sanitize_discovery_warning(exc)}"
    return result


def _check_3_7(project_id: str) -> CISCheckResult:
    """CIS 3.7 — Ensure RDP access is restricted from the internet."""
    result = CISCheckResult(
        check_id="3.7",
        title="RDP (port 3389) restricted from the internet",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove or restrict firewall rules that allow TCP port 3389 from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        compute_v1 = _seams()._import_google_cloud_module("compute_v1")

        client = compute_v1.FirewallsClient(**_creds_kwargs())
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
        result.evidence = f"Could not check firewall rules: {sanitize_discovery_warning(exc)}"
    return result
