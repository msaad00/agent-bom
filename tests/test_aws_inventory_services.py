"""AWS RDS/DynamoDB/Lambda/EKS inventory: discovery + graph nodes."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


# ── Graph ────────────────────────────────────────────────────────────────
def _inventory() -> dict:
    return {
        "status": "ok",
        "provider": "aws",
        "account_id": "111122223333",
        "rds_instances": [
            {
                "name": "prod-db",
                "arn": "arn:aws:rds:us-east-1:111122223333:db:prod-db",
                "engine": "postgres",
                "publicly_accessible": True,
                "encrypted": False,
                "location": "us-east-1",
            }
        ],
        "dynamodb_tables": [
            {
                "name": "sessions",
                "arn": "arn:aws:dynamodb:us-east-1:111122223333:table/sessions",
                "encrypted": True,
                "location": "us-east-1",
            }
        ],
        "lambda_functions": [
            {
                "name": "ingest",
                "arn": "arn:aws:lambda:us-east-1:111122223333:function:ingest",
                "runtime": "python3.12",
                "location": "us-east-1",
            }
        ],
        "eks_clusters": [
            {
                "name": "main",
                "arn": "arn:aws:eks:us-east-1:111122223333:cluster/main",
                "endpoint_public": True,
                "internet_exposed": True,
                "location": "us-east-1",
            }
        ],
    }


def _build():
    g = build_unified_graph_from_report({"cloud_inventory": _inventory()})
    return g, {(e.source, e.target, e.relationship.value) for e in g.edges}


def test_rds_and_dynamo_are_data_stores() -> None:
    g, _ = _build()
    rds = g.nodes["cloud_resource:aws:rds:database:prod-db"]
    ddb = g.nodes["cloud_resource:aws:dynamodb:database:sessions"]
    assert rds.entity_type.value == "data_store" and rds.attributes["is_data_store"] is True
    assert rds.attributes["internet_exposed"] is True  # publicly_accessible
    assert rds.attributes["engine"] == "postgres"
    assert ddb.attributes["encrypted"] is True


def test_lambda_and_eks_are_cloud_resources() -> None:
    g, _ = _build()
    assert g.nodes["cloud_resource:aws:lambda:function:ingest"].entity_type.value == "cloud_resource"
    eks = g.nodes["cloud_resource:aws:eks:container_cluster:main"]
    assert eks.attributes["internet_exposed"] is True  # public endpoint


def test_all_new_resources_owned_by_account() -> None:
    _, edges = _build()
    for nid in (
        "cloud_resource:aws:rds:database:prod-db",
        "cloud_resource:aws:dynamodb:database:sessions",
        "cloud_resource:aws:lambda:function:ingest",
        "cloud_resource:aws:eks:container_cluster:main",
    ):
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
        if self.svc == "rds":
            return _Paginator(
                [
                    {
                        "DBInstances": [
                            {
                                "DBInstanceIdentifier": "db1",
                                "DBInstanceArn": "arn:db1",
                                "Engine": "mysql",
                                "PubliclyAccessible": True,
                                "StorageEncrypted": False,
                                "Endpoint": {"Address": "db1.rds.aws"},
                            }
                        ]
                    }
                ]
            )
        if self.svc == "lambda":
            return _Paginator(
                [
                    {
                        "Functions": [
                            {
                                "FunctionName": "fn1",
                                "FunctionArn": "arn:fn1",
                                "Runtime": "nodejs20.x",
                                "Role": "arn:role",
                                "VpcConfig": {"VpcId": "vpc-1"},
                            }
                        ]
                    }
                ]
            )
        if self.svc == "dynamodb":
            return _Paginator([{"TableNames": ["t1"]}])
        if self.svc == "eks":
            return _Paginator([{"clusters": ["c1"]}])
        return _Paginator([])

    def describe_table(self, TableName):  # noqa: N803 — boto3 API param name
        return {"Table": {"TableArn": "arn:t1", "SSEDescription": {"Status": "ENABLED"}, "ItemCount": 5}}

    def describe_cluster(self, name):
        return {"cluster": {"name": name, "arn": "arn:c1", "version": "1.30", "resourcesVpcConfig": {"endpointPublicAccess": True}}}


class _Session:
    def client(self, svc, **_kw):
        return _Client(svc)


def test_discovery_parses_each_service() -> None:
    from agent_bom.cloud import aws_inventory as aws

    s = _Session()
    w: list[str] = []
    rds = aws._discover_rds(s, "us-east-1", account_id="111122223333", warnings=w)
    assert rds[0]["engine"] == "mysql" and rds[0]["publicly_accessible"] is True
    lam = aws._discover_lambda(s, "us-east-1", account_id="111122223333", warnings=w)
    assert lam[0]["runtime"] == "nodejs20.x" and lam[0]["in_vpc"] is True
    ddb = aws._discover_dynamodb(s, "us-east-1", account_id="111122223333", warnings=w)
    assert ddb[0]["encrypted"] is True and ddb[0]["item_count"] == 5
    eks = aws._discover_eks(s, "us-east-1", account_id="111122223333", warnings=w)
    assert eks[0]["endpoint_public"] is True and eks[0]["version"] == "1.30"
    assert w == []


def test_discover_inventory_returns_every_new_collection() -> None:
    """Regression for the collected-but-not-returned bug class: assert each new
    key is present in the discover_inventory return (not just the discovery fn)."""
    from agent_bom.cloud import aws_inventory as aws

    keys = aws.discover_inventory.__doc__  # cheap import guard
    assert keys is not None
    # The empty/no-cred path still carries every key.
    out = aws.discover_inventory(force=False)  # disabled path returns the empty template
    for k in ("rds_instances", "lambda_functions", "dynamodb_tables", "eks_clusters"):
        assert k in out, f"{k} missing from discover_inventory return"
