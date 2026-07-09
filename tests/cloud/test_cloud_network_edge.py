"""Network-edge inventory (WAF, API Gateway, ENIs, NAT/IGW, subnets, IPs).

Covers AWS live discovery (mocked boto3) and the shared graph wiring: the
API_GATEWAY node populated from live inventory, the WAF ``PROTECTS`` edge that
mitigates a fronted resource's exposure verdict, and the ENI mapping that makes
instance ↔ subnet ↔ security-group traversable.
"""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


# ── AWS discovery (mocked boto3) ─────────────────────────────────────────
class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kw):
        return self._pages


class _AccessDeniedError(Exception):
    """Mimics a botocore access-denied error (matched by message text)."""

    def __init__(self):
        super().__init__("AccessDeniedException: not authorized")


class _Ec2Client:
    def __init__(self, *, deny: bool = False):
        self.deny = deny

    def get_paginator(self, op):
        if self.deny:
            raise _AccessDeniedError()
        pages = {
            "describe_route_tables": [
                {
                    "RouteTables": [
                        {
                            "RouteTableId": "rtb-1",
                            "VpcId": "vpc-1",
                            "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
                            "Associations": [{"SubnetId": "subnet-pub", "Main": False}],
                        }
                    ]
                }
            ],
            "describe_subnets": [
                {
                    "Subnets": [
                        {"SubnetId": "subnet-pub", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "us-east-1a"},
                        {"SubnetId": "subnet-priv", "VpcId": "vpc-1", "CidrBlock": "10.0.2.0/24", "AvailabilityZone": "us-east-1b"},
                    ]
                }
            ],
            "describe_network_interfaces": [
                {
                    "NetworkInterfaces": [
                        {
                            "NetworkInterfaceId": "eni-1",
                            "SubnetId": "subnet-pub",
                            "VpcId": "vpc-1",
                            "PrivateIpAddress": "10.0.1.5",
                            "Groups": [{"GroupId": "sg-1"}],
                            "Attachment": {"InstanceId": "i-1"},
                            "Association": {"PublicIp": "54.1.2.3"},
                        }
                    ]
                }
            ],
            "describe_nat_gateways": [{"NatGateways": [{"NatGatewayId": "nat-1", "VpcId": "vpc-1", "SubnetId": "subnet-pub"}]}],
            "describe_vpc_endpoints": [
                {"VpcEndpoints": [{"VpcEndpointId": "vpce-1", "ServiceName": "com.amazonaws.s3", "VpcId": "vpc-1"}]}
            ],
            "describe_network_acls": [{"NetworkAcls": [{"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": True}]}],
        }
        return _Paginator(pages.get(op, []))

    def describe_internet_gateways(self):
        if self.deny:
            raise _AccessDeniedError()
        return {"InternetGateways": [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1"}]}]}

    def describe_egress_only_internet_gateways(self):
        return {"EgressOnlyInternetGateways": []}

    def describe_addresses(self):
        if self.deny:
            raise _AccessDeniedError()
        return {"Addresses": [{"PublicIp": "52.9.9.9", "AllocationId": "eipalloc-1", "InstanceId": "i-1"}]}


class _WafClient:
    def __init__(self, *, deny: bool = False):
        self.deny = deny

    def list_web_acls(self, Scope, NextMarker=None):  # noqa: N803 — boto3 API param
        if self.deny:
            raise _AccessDeniedError()
        if NextMarker == "page2":
            if Scope == "REGIONAL":
                return {"WebACLs": [{"Name": "web-acl-2", "Id": "acl-id-2", "ARN": "arn:waf:regional-2"}]}
            return {"WebACLs": [{"Name": "cf-acl-2", "Id": "cf-id-2", "ARN": "arn:waf:cloudfront-2"}]}
        if Scope == "REGIONAL":
            return {
                "WebACLs": [{"Name": "web-acl", "Id": "acl-id", "ARN": "arn:waf:regional"}],
                "NextMarker": "page2",
            }
        return {
            "WebACLs": [{"Name": "cf-acl", "Id": "cf-id", "ARN": "arn:waf:cloudfront"}],
            "NextMarker": "page2",
        }

    def list_resources_for_web_acl(self, WebACLArn, NextMarker=None):  # noqa: N803
        if NextMarker == "assoc2":
            return {"ResourceArns": ["arn:alb:web-2"]}
        return {"ResourceArns": ["arn:alb:web"], "NextMarker": "assoc2"}


class _ApiGwClient:
    def get_paginator(self, _op):
        return _Paginator([{"items": [{"id": "rest1", "name": "rest-api", "endpointConfiguration": {"types": ["REGIONAL"]}}]}])

    def get_stages(self, restApiId):  # noqa: N803
        return {"item": [{"stageName": "prod"}]}


class _ApiGwV2Client:
    def get_apis(self, **_kw):
        return {"Items": [{"ApiId": "http1", "Name": "http-api", "ProtocolType": "HTTP", "ApiEndpoint": "https://x.execute-api"}]}


class _Session:
    def __init__(self, *, deny: bool = False):
        self.deny = deny

    def client(self, svc, **_kw):
        if svc == "ec2":
            return _Ec2Client(deny=self.deny)
        if svc == "wafv2":
            return _WafClient(deny=self.deny)
        if svc == "apigateway":
            return _ApiGwClient()
        if svc == "apigatewayv2":
            return _ApiGwV2Client()
        raise AssertionError(f"unexpected client {svc}")


def test_discover_waf_enumerates_acls_and_associations() -> None:
    from agent_bom.cloud import aws_inventory as aws

    warnings: list[str] = []
    acls = aws._discover_waf(_Session(), "us-east-1", account_id="111122223333", warnings=warnings, missing=[])
    regional = [a for a in acls if a["scope"] == "regional"]
    cloudfront = [a for a in acls if a["scope"] == "cloudfront"]
    assert len(regional) == 2
    assert len(cloudfront) == 2
    assert regional[0]["protected_targets"] == ["arn:alb:web", "arn:alb:web-2"]
    assert warnings == []


def test_discover_api_gateways_rest_and_v2() -> None:
    from agent_bom.cloud import aws_inventory as aws

    gws = aws._discover_api_gateways(_Session(), "us-east-1", account_id="111122223333", warnings=[], missing=[])
    protocols = {g["protocol"] for g in gws}
    assert protocols == {"REST", "HTTP"}
    rest = next(g for g in gws if g["protocol"] == "REST")
    assert rest["stages"] == ["prod"] and rest["internet_exposed"] is True


def test_discover_network_edge_enumerates_plumbing() -> None:
    from agent_bom.cloud import aws_inventory as aws

    edge = aws._discover_network_edge(_Session(), "us-east-1", account_id="111122223333", warnings=[], missing=[])
    assert len(edge["network_interfaces"]) == 1
    eni = edge["network_interfaces"][0]
    assert eni["instance_id"] == "i-1" and eni["subnet_id"] == "subnet-pub" and eni["security_group_ids"] == ["sg-1"]
    subnets = {s["id"]: s for s in edge["subnets"]}
    assert subnets["subnet-pub"]["is_public"] is True  # 0.0.0.0/0 → igw route
    assert subnets["subnet-priv"]["is_public"] is False
    assert len(edge["nat_gateways"]) == 1 and len(edge["internet_gateways"]) == 1
    assert len(edge["vpc_endpoints"]) == 1 and len(edge["route_tables"]) == 1 and len(edge["network_acls"]) == 1


def test_discover_ip_addresses_elastic_and_eni() -> None:
    from agent_bom.cloud import aws_inventory as aws

    enis = [{"id": "eni-1", "public_ip": "54.1.2.3", "instance_id": "i-1"}]
    ips = aws._discover_ip_addresses(_Session(), "us-east-1", account_id="x", network_interfaces=enis, warnings=[], missing=[])
    by_addr = {i["address"]: i for i in ips}
    assert by_addr["52.9.9.9"]["kind"] == "elastic"
    assert by_addr["54.1.2.3"]["kind"] == "public" and by_addr["54.1.2.3"]["attached_to"] == "i-1"


def test_missing_permission_warns_and_continues() -> None:
    from agent_bom.cloud import aws_inventory as aws

    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    acls = aws._discover_waf(_Session(deny=True), "us-east-1", account_id="x", warnings=warnings, missing=missing)
    assert acls == []  # degraded, not crashed
    assert warnings and any("wafv2:ListWebACLs" in w for w in warnings)
    assert any(m["permission"] == "wafv2:ListWebACLs" for m in missing)


def test_discover_inventory_payload_has_network_edge_keys() -> None:
    from agent_bom.cloud import aws_inventory as aws

    out = aws.discover_inventory(force=False)
    for key in (
        "web_acls",
        "api_gateways",
        "network_interfaces",
        "subnets",
        "nat_gateways",
        "internet_gateways",
        "vpc_endpoints",
        "route_tables",
        "network_acls",
        "ip_addresses",
    ):
        assert key in out, f"{key} missing from discover_inventory payload"


# ── Graph wiring ─────────────────────────────────────────────────────────
def _aws_inventory() -> dict:
    return {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "instances": [{"instance_id": "i-1", "name": "web", "vpc_id": "vpc-1", "subnet_id": "subnet-pub", "security_group_ids": ["sg-1"]}],
        "security_groups": [{"group_id": "sg-1", "name": "open", "vpc_id": "vpc-1", "internet_exposed": True, "network_exposure": []}],
        "subnets": [{"id": "subnet-pub", "name": "pub", "vpc_id": "vpc-1", "cidr": "10.0.1.0/24", "is_public": True}],
        "network_interfaces": [
            {
                "id": "eni-1",
                "name": "eni-1",
                "instance_id": "i-1",
                "subnet_id": "subnet-pub",
                "vpc_id": "vpc-1",
                "security_group_ids": ["sg-1"],
                "private_ip": "10.0.1.5",
                "public_ip": "54.1.2.3",
            }
        ],
        "elb_load_balancers": [
            {
                "name": "web-alb",
                "arn": "arn:alb:web",
                "scheme": "internet-facing",
                "internet_exposed": True,
                "location": "us-east-1",
                "vpc_id": "vpc-1",
            }
        ],
        "web_acls": [
            {"name": "web-acl", "id": "acl-id", "arn": "arn:waf:regional", "scope": "regional", "protected_targets": ["arn:alb:web"]}
        ],
        "api_gateways": [
            {
                "name": "rest-api",
                "id": "rest1",
                "protocol": "REST",
                "endpoint": "REGIONAL",
                "internet_exposed": True,
                "stages": ["prod"],
                "protected_targets": ["arn:alb:web"],
            }
        ],
    }


def test_api_gateway_node_populated_from_live_inventory() -> None:
    g = build_unified_graph_from_report({"cloud_inventory": _aws_inventory()})
    api_nodes = [n for n in g.nodes.values() if n.entity_type == EntityType.API_GATEWAY]
    assert len(api_nodes) == 1
    node = api_nodes[0]
    assert node.attributes["protocol"] == "REST"
    assert node.attributes["semantic_layer"] == "api_gateway"


def test_waf_node_and_protects_edge() -> None:
    g = build_unified_graph_from_report({"cloud_inventory": _aws_inventory()})
    edges = {(e.source, e.target, e.relationship.value) for e in g.edges}
    waf_id = "cloud_resource:aws:waf:web_acl:acl-id"
    alb_id = "cloud_resource:aws:elbv2:load_balancer:web-alb"
    assert waf_id in g.nodes
    assert (waf_id, alb_id, "protects") in edges


def test_eni_maps_instance_subnet_and_security_group() -> None:
    g = build_unified_graph_from_report({"cloud_inventory": _aws_inventory()})
    edges = {(e.source, e.target, e.relationship.value) for e in g.edges}
    eni_id = "cloud_resource:aws:network:network_interface:eni-1"
    inst_id = "cloud_resource:aws:ec2:instance:i-1"
    assert eni_id in g.nodes
    assert (eni_id, inst_id, "part_of") in edges
    assert (eni_id, "cloud_resource:aws:network:subnet:subnet-pub", "part_of") in edges
    assert (eni_id, "cloud_resource:aws:ec2:security-group:sg-1", "part_of") in edges


def test_eni_public_ip_emits_exposed_to_instance() -> None:
    g = build_unified_graph_from_report({"cloud_inventory": _aws_inventory()})
    eni_id = "cloud_resource:aws:network:network_interface:eni-1"
    inst_id = "cloud_resource:aws:ec2:instance:i-1"
    exposed = [
        e
        for e in g.edges
        if e.relationship == RelationshipType.EXPOSED_TO and e.source == eni_id and e.target == inst_id
    ]
    assert exposed
    assert exposed[0].evidence.get("reason") == "eni_public_ip"


def test_elastic_ip_emits_exposed_to_attached_instance() -> None:
    payload = _aws_inventory()
    payload["ip_addresses"] = [{"address": "52.9.9.9", "kind": "elastic", "attached_to": "i-1"}]
    g = build_unified_graph_from_report({"cloud_inventory": payload})
    ip_id = "cloud_resource:aws:network:ip_address:52.9.9.9"
    inst_id = "cloud_resource:aws:ec2:instance:i-1"
    exposed = [
        e
        for e in g.edges
        if e.relationship == RelationshipType.EXPOSED_TO and e.source == ip_id and e.target == inst_id
    ]
    assert exposed
    assert exposed[0].evidence.get("reason") == "elastic_ip_attachment"


def test_internet_facing_lb_emits_exposed_to_reachable_instance() -> None:
    g = build_unified_graph_from_report({"cloud_inventory": _aws_inventory()})
    lb_id = "cloud_resource:aws:elbv2:load_balancer:web-alb"
    inst_id = "cloud_resource:aws:ec2:instance:i-1"
    exposed = [
        e
        for e in g.edges
        if e.relationship == RelationshipType.EXPOSED_TO and e.source == lb_id and e.target == inst_id
    ]
    assert exposed
    assert exposed[0].evidence.get("reason") == "internet_facing_load_balancer"


def test_internet_facing_api_gateway_emits_exposed_to_frontend() -> None:
    g = build_unified_graph_from_report({"cloud_inventory": _aws_inventory()})
    api_id = "api_gateway:aws:rest1"
    alb_id = "cloud_resource:aws:elbv2:load_balancer:web-alb"
    exposed = [
        e
        for e in g.edges
        if e.relationship == RelationshipType.EXPOSED_TO and e.source == api_id and e.target == alb_id
    ]
    assert exposed
    assert exposed[0].evidence.get("reason") == "internet_facing_api_gateway"


def _exposed_vuln_graph(*, protected: bool) -> UnifiedGraph:
    g = UnifiedGraph()
    g.add_node(
        UnifiedNode(
            id="res",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="api backend",
            attributes={"internet_exposed": True, "resource_type": "instance"},
        )
    )
    g.add_node(UnifiedNode(id="vuln", entity_type=EntityType.VULNERABILITY, label="CVE-x", severity="high"))
    g.add_edge(UnifiedEdge(source="res", target="vuln", relationship=RelationshipType.VULNERABLE_TO))
    if protected:
        g.add_node(UnifiedNode(id="gw", entity_type=EntityType.API_GATEWAY, label="gateway"))
        g.add_edge(UnifiedEdge(source="gw", target="res", relationship=RelationshipType.PROTECTS))
    return g


def test_waf_fronted_exposure_verdict_differs_from_unprotected() -> None:
    unprotected = _exposed_vuln_graph(protected=False)
    protected = _exposed_vuln_graph(protected=True)

    apply_cnapp_overlay(unprotected)
    apply_cnapp_overlay(protected)

    bare = unprotected.nodes["res"]
    fronted = protected.nodes["res"]

    # Unprotected: full toxic escalation. Protected: mitigated, lower risk.
    assert bare.attributes.get("toxic_exposed_vulnerable") is True
    assert bare.risk_score >= 9.0
    assert fronted.attributes.get("exposure_mitigated") is True
    assert fronted.attributes.get("toxic_exposed_vulnerable_mitigated") is True
    assert fronted.attributes.get("toxic_exposed_vulnerable") is None
    assert fronted.risk_score < bare.risk_score
