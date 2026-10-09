"""CIS AWS 5.x — security group, NACL and VPC peering checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ._base import CheckStatus, CISCheckResult, logger

# ---------------------------------------------------------------------------
# Individual checks — CIS 5.x (Networking)
# ---------------------------------------------------------------------------

_NETWORKING_SECTION = "5 - Networking"


def _check_5_2(ec2_client: Any) -> CISCheckResult:
    """CIS 5.2 — No unrestricted ingress to admin ports (22, 3389)."""
    result = CISCheckResult(
        check_id="5.2",
        title="No unrestricted ingress to admin ports (22, 3389)",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_NETWORKING_SECTION,
        recommendation="Restrict SSH (22) and RDP (3389) to specific IP ranges.",
    )
    admin_ports = {22, 3389}
    open_sgs = []
    exposures: list[dict] = []

    paginator = ec2_client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                protocol = str(perm.get("IpProtocol", "tcp"))
                # Check if any admin port falls in this range
                if not any(from_port <= p <= to_port for p in admin_ports):
                    continue
                # Check for 0.0.0.0/0 or ::/0
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        open_sgs.append(f"{sg['GroupId']} (port {from_port}-{to_port})")
                        exposures.append(
                            {
                                "resource": sg["GroupId"],
                                "from_port": from_port,
                                "to_port": to_port,
                                "protocol": protocol,
                                "scope": "internet",
                            }
                        )
                        break
                for ip_range in perm.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        open_sgs.append(f"{sg['GroupId']} (port {from_port}-{to_port}, IPv6)")
                        exposures.append(
                            {
                                "resource": sg["GroupId"],
                                "from_port": from_port,
                                "to_port": to_port,
                                "protocol": protocol,
                                "scope": "internet",
                            }
                        )
                        break

    # Deduplicate
    open_sgs = list(dict.fromkeys(open_sgs))

    if open_sgs:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(open_sgs)} security group(s) with unrestricted admin access: {', '.join(open_sgs[:5])}"
        if len(open_sgs) > 5:
            result.evidence += f" (+{len(open_sgs) - 5} more)"
        result.resource_ids = open_sgs[:20]
        result.network_exposure = exposures[:50]
    else:
        result.evidence = "No security groups allow unrestricted ingress to SSH/RDP."
    return result


def _check_5_3(ec2_client: Any) -> CISCheckResult:
    """CIS 5.3 — Default security group restricts all traffic."""
    result = CISCheckResult(
        check_id="5.3",
        title="Default security group restricts all traffic",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_NETWORKING_SECTION,
        recommendation="Remove all inbound and outbound rules from default security groups.",
    )
    paginator = ec2_client.get_paginator("describe_security_groups")
    open_defaults = []

    for page in paginator.paginate(Filters=[{"Name": "group-name", "Values": ["default"]}]):
        for sg in page["SecurityGroups"]:
            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                # Check if egress is only the default "allow all" rule
                egress_only_default = len(sg.get("IpPermissionsEgress", [])) == 1 and sg["IpPermissionsEgress"][0].get("IpProtocol") == "-1"
                if sg.get("IpPermissions") or not egress_only_default:
                    open_defaults.append(f"{sg['GroupId']} (VPC: {sg.get('VpcId', 'unknown')})")

    if open_defaults:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(open_defaults)} default security group(s) with rules: {', '.join(open_defaults[:5])}"
        if len(open_defaults) > 5:
            result.evidence += f" (+{len(open_defaults) - 5} more)"
        result.resource_ids = open_defaults[:20]
    else:
        result.evidence = "All default security groups restrict all traffic."
    return result


def _check_5_5(ec2_client: Any) -> CISCheckResult:
    """CIS 5.5 — No security group allows all-ports ingress from any IP."""
    result = CISCheckResult(
        check_id="5.5",
        title="No security group allows all-ports ingress from any IP",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_NETWORKING_SECTION,
        recommendation="Remove security group rules that allow unrestricted ingress to all ports.",
    )
    open_sgs: list[str] = []

    paginator = ec2_client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                # Check for all-ports rules (protocol -1 means all)
                protocol = perm.get("IpProtocol", "")
                if protocol != "-1":
                    # Also catch from_port=0,to_port=65535
                    from_port = perm.get("FromPort", -1)
                    to_port = perm.get("ToPort", -1)
                    if not (from_port == 0 and to_port == 65535):
                        continue
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        open_sgs.append(sg["GroupId"])
                        break
                else:
                    for ip_range in perm.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            open_sgs.append(sg["GroupId"])
                            break

    open_sgs = list(dict.fromkeys(open_sgs))

    if open_sgs:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(open_sgs)} security group(s) allow unrestricted ingress to all ports: {', '.join(open_sgs[:5])}"
        if len(open_sgs) > 5:
            result.evidence += f" (+{len(open_sgs) - 5} more)"
        result.resource_ids = open_sgs[:20]
    else:
        result.evidence = "No security groups allow unrestricted ingress to all ports."
    return result


def _check_5_1(ec2_client: Any) -> CISCheckResult:
    """CIS 5.1 — No NACL allows unrestricted ingress to admin ports."""
    result = CISCheckResult(
        check_id="5.1",
        title="No NACL allows unrestricted ingress to admin ports",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_NETWORKING_SECTION,
        recommendation="Restrict NACLs to deny ingress from 0.0.0.0/0 and ::/0 to ports 22 and 3389.",
    )
    admin_ports = {22, 3389}
    open_nacls: list[str] = []

    try:
        paginator = ec2_client.get_paginator("describe_network_acls")
        for page in paginator.paginate():
            for nacl in page["NetworkAcls"]:
                nacl_id = nacl["NetworkAclId"]
                for entry in nacl.get("Entries", []):
                    # Only check inbound allow rules
                    if entry.get("Egress", True):
                        continue
                    if entry.get("RuleAction") != "allow":
                        continue
                    cidr = entry.get("CidrBlock", "")
                    ipv6_cidr = entry.get("Ipv6CidrBlock", "")
                    if cidr != "0.0.0.0/0" and ipv6_cidr != "::/0":
                        continue
                    # Check port range
                    port_range = entry.get("PortRange", {})
                    from_port = port_range.get("From", 0)
                    to_port = port_range.get("To", 65535)
                    if any(from_port <= p <= to_port for p in admin_ports):
                        open_nacls.append(nacl_id)
                        break
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        logger.debug("Could not check NACLs: %s (%s)", sanitize_text(exc), error_code)
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query Network ACLs: {error_code or exc}"
        return result

    open_nacls = list(dict.fromkeys(open_nacls))

    if open_nacls:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(open_nacls)} NACL(s) allow unrestricted admin port access: {', '.join(open_nacls[:5])}"
        if len(open_nacls) > 5:
            result.evidence += f" (+{len(open_nacls) - 5} more)"
        result.resource_ids = open_nacls[:20]
    else:
        result.evidence = "No Network ACLs allow unrestricted ingress to admin ports."
    return result


def _check_5_4(ec2_client: Any) -> CISCheckResult:
    """CIS 5.4 — VPC peering route tables least-privilege."""
    result = CISCheckResult(
        check_id="5.4",
        title="VPC peering route tables least-privilege",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_NETWORKING_SECTION,
        recommendation="Ensure VPC peering route table entries do not use overly broad CIDR ranges (e.g. 0.0.0.0/0).",
    )
    try:
        paginator = ec2_client.get_paginator("describe_route_tables")
        broad_routes: list[str] = []

        for page in paginator.paginate():
            for rt in page["RouteTables"]:
                rt_id = rt["RouteTableId"]
                for route in rt.get("Routes", []):
                    # Only check routes targeting a VPC peering connection
                    if not route.get("VpcPeeringConnectionId"):
                        continue
                    cidr = route.get("DestinationCidrBlock", "")
                    ipv6_cidr = route.get("DestinationIpv6CidrBlock", "")
                    if cidr == "0.0.0.0/0" or ipv6_cidr == "::/0":
                        broad_routes.append(f"{rt_id} -> {route['VpcPeeringConnectionId']}")

        if broad_routes:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(broad_routes)} peering route(s) with overly broad CIDR: {', '.join(broad_routes[:5])}"
            if len(broad_routes) > 5:
                result.evidence += f" (+{len(broad_routes) - 5} more)"
            result.resource_ids = broad_routes[:20]
        else:
            result.evidence = "All VPC peering routes use specific CIDR ranges."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        logger.debug("Could not check route tables: %s (%s)", sanitize_text(exc), error_code)
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query route tables: {error_code or exc}"
    return result
