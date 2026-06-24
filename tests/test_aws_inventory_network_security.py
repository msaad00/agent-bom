"""AWS ELB/VPC/KMS/Secrets Manager inventory: discovery + graph nodes."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _inventory() -> dict:
    return {
        "status": "ok",
        "provider": "aws",
        "account_id": "111122223333",
        "elb_load_balancers": [
            {
                "name": "web-alb",
                "arn": "arn:lb",
                "scheme": "internet-facing",
                "lb_type": "application",
                "internet_exposed": True,
                "location": "us-east-1",
            }
        ],
        "vpcs": [
            {
                "name": "vpc-1",
                "display_name": "main-vpc",
                "vpc_id": "vpc-1",
                "cidr": "10.0.0.0/16",
                "is_default": False,
                "location": "us-east-1",
            }
        ],
        "kms_keys": [{"name": "key-1", "arn": "arn:key", "enabled": True, "rotation_enabled": False, "location": "us-east-1"}],
        "secrets": [{"name": "db-creds", "arn": "arn:sec", "rotation_enabled": False, "location": "us-east-1"}],
    }


def _build():
    g = build_unified_graph_from_report({"cloud_inventory": _inventory()})
    return g, {(e.source, e.target, e.relationship.value) for e in g.edges}


def test_internet_facing_elb_flagged_exposed() -> None:
    g, _ = _build()
    lb = g.nodes["cloud_resource:aws:elbv2:load_balancer:web-alb"]
    assert lb.attributes["internet_exposed"] is True


def test_vpc_kms_secret_nodes_created_and_owned() -> None:
    g, edges = _build()
    for nid in (
        "cloud_resource:aws:ec2:virtual_network:vpc-1",
        "cloud_resource:aws:kms:key:key-1",
        "cloud_resource:aws:secretsmanager:secret:db-creds",
    ):
        assert nid in g.nodes
        assert ("account:aws:111122223333", nid, "owns") in edges


# ── Discovery (mocked boto3) ─────────────────────────────────────────────
class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kw):
        return self._pages


class _Client:
    def __init__(self, svc):
        self.svc = svc

    def get_paginator(self, op):
        if self.svc == "elbv2":
            return _Paginator(
                [
                    {
                        "LoadBalancers": [
                            {
                                "LoadBalancerName": "alb1",
                                "LoadBalancerArn": "arn:alb",
                                "Scheme": "internet-facing",
                                "Type": "application",
                                "DNSName": "alb1.aws",
                                "VpcId": "vpc-1",
                            }
                        ]
                    }
                ]
            )
        if self.svc == "kms":
            return _Paginator([{"Keys": [{"KeyId": "k-cmk", "KeyArn": "arn:k-cmk"}, {"KeyId": "k-aws", "KeyArn": "arn:k-aws"}]}])
        if self.svc == "secretsmanager":
            return _Paginator([{"SecretList": [{"Name": "s1", "ARN": "arn:s1", "RotationEnabled": True}]}])
        return _Paginator([])

    def describe_vpcs(self):
        return {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16", "IsDefault": True, "Tags": [{"Key": "Name", "Value": "prod"}]}]}

    def describe_key(self, KeyId):  # noqa: N803 — boto3 API param
        return {"KeyMetadata": {"KeyManager": "AWS" if KeyId == "k-aws" else "CUSTOMER", "Enabled": True}}

    def get_key_rotation_status(self, KeyId):  # noqa: N803
        return {"KeyRotationEnabled": True}


class _Session:
    def client(self, svc, **_kw):
        return _Client(svc)


def test_discovery_parses_network_security_services() -> None:
    from agent_bom.cloud import aws_inventory as aws

    s, w = _Session(), []
    elb = aws._discover_elb(s, "us-east-1", account_id="111122223333", warnings=w)
    assert elb[0]["internet_exposed"] is True
    vpcs = aws._discover_vpcs(s, "us-east-1", account_id="111122223333", warnings=w)
    assert vpcs[0]["name"] == "vpc-1" and vpcs[0]["display_name"] == "prod" and vpcs[0]["is_default"] is True
    secrets = aws._discover_secrets(s, "us-east-1", account_id="111122223333", warnings=w)
    assert secrets[0]["rotation_enabled"] is True
    assert w == []


def test_kms_skips_aws_managed_keys() -> None:
    from agent_bom.cloud import aws_inventory as aws

    keys = aws._discover_kms(_Session(), "us-east-1", account_id="111122223333", warnings=[])
    names = {k["name"] for k in keys}
    assert "k-cmk" in names and "k-aws" not in names  # AWS-managed key excluded


def test_discover_inventory_returns_every_new_collection() -> None:
    from agent_bom.cloud import aws_inventory as aws

    out = aws.discover_inventory(force=False)
    for k in ("elb_load_balancers", "vpcs", "kms_keys", "secrets"):
        assert k in out, f"{k} missing from discover_inventory return"
