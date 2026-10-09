"""CIS Azure section 6 — network security group and Network Watcher checks."""

from __future__ import annotations

from typing import Any

from ..aws_cis_benchmark import CheckStatus, CISCheckResult
from ._base import (
    _NETWORK_SECTION,
    _pass_or_no_data,
)


def _check_6_1(network_client: Any) -> CISCheckResult:
    """CIS 6.1 — Ensure RDP access from the internet is restricted."""
    result = CISCheckResult(
        check_id="6.1",
        title="RDP access from internet restricted",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation=(
            "Remove or restrict NSG inbound rules allowing port 3389 from 0.0.0.0/0 or ::/0. Use Azure Bastion or Just-In-Time VM access."
        ),
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                if _is_internet_exposed(rule, "3389"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")

        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing RDP (3389) from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing RDP (3389) from 0.0.0.0/0 or ::/0."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules: {exc}"
    return result


def _check_6_2(network_client: Any) -> CISCheckResult:
    """CIS 6.2 — Ensure SSH access from the internet is restricted."""
    result = CISCheckResult(
        check_id="6.2",
        title="SSH access from internet restricted",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation=(
            "Remove or restrict NSG inbound rules allowing port 22 from 0.0.0.0/0 or ::/0. Use Azure Bastion or Just-In-Time VM access."
        ),
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                if _is_internet_exposed(rule, "22"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")

        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing SSH (22) from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing SSH (22) from 0.0.0.0/0 or ::/0."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules: {exc}"
    return result


def _check_6_3(network_client: Any) -> CISCheckResult:
    """CIS 6.3 — Ensure no SQL Databases allow ingress from 0.0.0.0/0 (Any IP)."""
    result = CISCheckResult(
        check_id="6.3",
        title="No SQL database allows ingress from any IP",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=(
            "Remove or restrict NSG inbound rules allowing port 1433 from 0.0.0.0/0 or ::/0."
            " Use private endpoints or service endpoints for SQL access."
        ),
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                if _is_internet_exposed(rule, "1433"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")

        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing SQL (1433) from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing SQL (1433) from 0.0.0.0/0 or ::/0."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules for SQL access: {exc}"
    return result


def _check_6_5(network_client: Any) -> CISCheckResult:
    """CIS 6.5 — Ensure Network Watcher is enabled."""
    result = CISCheckResult(
        check_id="6.5",
        title="Network Watcher enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Network Watcher in all regions where you have Azure resources deployed.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        watchers = list(network_client.network_watchers.list_all())
        if watchers:
            regions = [getattr(w, "location", "unknown") for w in watchers]
            result.status = CheckStatus.PASS
            result.evidence = f"Network Watcher enabled in {len(watchers)} region(s): {', '.join(sorted(set(regions)))}."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No Network Watcher instances found. Enable Network Watcher in all regions with deployed resources."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Network Watcher status: {exc}"
    return result


def _check_6_4(network_client: Any) -> CISCheckResult:
    """CIS 6.4 — Ensure that UDP access from the internet is restricted."""
    result = CISCheckResult(
        check_id="6.4",
        title="UDP access from internet restricted",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove or restrict NSG inbound rules allowing UDP from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                protocol = (getattr(rule, "protocol", "") or "").lower()
                if protocol not in ("udp", "*"):
                    continue
                if _is_internet_exposed(rule, "*"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")
        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing UDP from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing unrestricted UDP from the internet."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules for UDP access: {exc}"
    return result


def _check_6_6(network_client: Any) -> CISCheckResult:
    """CIS 6.6 — Ensure Web Application Firewall (WAF) is enabled."""
    result = CISCheckResult(
        check_id="6.6",
        title="Web Application Firewall enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable WAF on Application Gateway or Front Door for all public-facing web applications.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        app_gws = list(network_client.application_gateways.list_all())
        failing = []
        for gw in app_gws:
            gw_name = gw.name or "unknown"
            waf_config = getattr(gw, "web_application_firewall_configuration", None)
            if waf_config is None:
                failing.append(gw_name)
            else:
                enabled = getattr(waf_config, "enabled", False)
                if not enabled:
                    failing.append(gw_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Application Gateways without WAF enabled: {', '.join(failing)}"
            result.resource_ids = failing
        elif app_gws:
            _pass_or_no_data(result, len(app_gws), "Application Gateway", f"All {len(app_gws)} Application Gateway(s) have WAF enabled.")
        else:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No Application Gateways found; WAF check is not applicable."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Application Gateway WAF settings: {exc}"
    return result


def _is_internet_exposed(rule: Any, port: str) -> bool:
    """Return True if an NSG rule allows inbound access from any internet address on a given port."""
    direction = (getattr(rule, "direction", "") or "").lower()
    access = (getattr(rule, "access", "") or "").lower()
    if direction != "inbound" or access != "allow":
        return False

    source_prefix = (getattr(rule, "source_address_prefix", "") or "").strip()
    if source_prefix not in ("*", "0.0.0.0/0", "::/0", "Internet", "Any"):
        return False

    dest_port = (getattr(rule, "destination_port_range", "") or "").strip()
    return dest_port in ("*", port)
