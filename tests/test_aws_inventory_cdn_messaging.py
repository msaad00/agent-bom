"""AWS CloudFront/ECR/Redshift/SNS/SQS inventory: discovery + graph nodes."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _inventory() -> dict:
    return {
        "status": "ok",
        "provider": "aws",
        "account_id": "111122223333",
        "cloudfront_distributions": [
            {
                "name": "E123",
                "arn": "arn:cf",
                "domain_name": "d1.cloudfront.net",
                "enabled": True,
                "internet_exposed": True,
                "location": "global",
            }
        ],
        "ecr_repositories": [
            {
                "name": "app",
                "arn": "arn:ecr",
                "uri": "1.dkr.ecr.us-east-1.amazonaws.com/app",
                "scan_on_push": True,
                "tag_immutable": True,
                "location": "us-east-1",
            }
        ],
        "redshift_clusters": [
            {"name": "warehouse", "engine": "redshift", "publicly_accessible": True, "encrypted": False, "location": "us-east-1"}
        ],
        "messaging": [
            {"name": "events", "arn": "arn:aws:sns:us-east-1:111122223333:events", "messaging_type": "sns-topic", "location": "us-east-1"},
            {"name": "jobs", "arn": "arn:aws:sqs:us-east-1:111122223333:jobs", "messaging_type": "sqs-queue", "location": "us-east-1"},
        ],
    }


def _build():
    g = build_unified_graph_from_report({"cloud_inventory": _inventory()})
    return g, {(e.source, e.target, e.relationship.value) for e in g.edges}


def test_cloudfront_is_internet_exposed_cdn() -> None:
    g, _ = _build()
    cf = g.nodes["cloud_resource:aws:cloudfront:cdn:E123"]
    assert cf.attributes["internet_exposed"] is True


def test_redshift_is_exposed_data_store() -> None:
    g, _ = _build()
    rs = g.nodes["cloud_resource:aws:redshift:data_warehouse:warehouse"]
    assert rs.entity_type.value == "data_store"
    assert rs.attributes["internet_exposed"] is True  # publicly_accessible


def test_ecr_and_messaging_nodes_owned() -> None:
    g, edges = _build()
    for nid in (
        "cloud_resource:aws:ecr:container_registry:app",
        "cloud_resource:aws:messaging:messaging:events",
        "cloud_resource:aws:messaging:messaging:jobs",
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
        if self.svc == "cloudfront":
            return _Paginator(
                [
                    {
                        "DistributionList": {
                            "Items": [
                                {
                                    "Id": "E1",
                                    "ARN": "arn:cf",
                                    "DomainName": "d.cf.net",
                                    "Enabled": True,
                                    "Origins": {"Items": [{"DomainName": "b.s3.aws"}]},
                                }
                            ]
                        }
                    }
                ]
            )
        if self.svc == "ecr":
            return _Paginator(
                [
                    {
                        "repositories": [
                            {
                                "repositoryName": "app",
                                "repositoryArn": "arn:ecr",
                                "repositoryUri": "uri",
                                "imageScanningConfiguration": {"scanOnPush": True},
                                "imageTagMutability": "IMMUTABLE",
                            }
                        ]
                    }
                ]
            )
        if self.svc == "redshift":
            return _Paginator(
                [
                    {
                        "Clusters": [
                            {
                                "ClusterIdentifier": "wh",
                                "PubliclyAccessible": True,
                                "Encrypted": False,
                                "Endpoint": {"Address": "wh.redshift.aws"},
                                "NodeType": "ra3",
                            }
                        ]
                    }
                ]
            )
        if self.svc == "sns":
            return _Paginator([{"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:111122223333:t1"}]}])
        if self.svc == "sqs":
            return _Paginator([{"QueueUrls": ["https://sqs.us-east-1.aws/111122223333/q1"]}])
        return _Paginator([])


class _Session:
    def client(self, svc, **_kw):
        return _Client(svc)


def test_discovery_parses_cdn_registry_warehouse_messaging() -> None:
    from agent_bom.cloud import aws_inventory as aws

    s, w = _Session(), []
    cf = aws._discover_cloudfront(s, account_id="111122223333", warnings=w)
    assert cf[0]["internet_exposed"] is True and cf[0]["origins"] == ["b.s3.aws"]
    ecr = aws._discover_ecr(s, "us-east-1", account_id="111122223333", warnings=w)
    assert ecr[0]["scan_on_push"] is True and ecr[0]["tag_immutable"] is True
    rs = aws._discover_redshift(s, "us-east-1", account_id="111122223333", warnings=w)
    assert rs[0]["publicly_accessible"] is True and rs[0]["engine"] == "redshift"
    msg = aws._discover_messaging(s, "us-east-1", account_id="111122223333", warnings=w)
    types = {m["messaging_type"] for m in msg}
    assert types == {"sns-topic", "sqs-queue"}
    assert w == []


def test_discover_inventory_returns_every_new_collection() -> None:
    from agent_bom.cloud import aws_inventory as aws

    out = aws.discover_inventory(force=False)
    for k in ("cloudfront_distributions", "ecr_repositories", "redshift_clusters", "messaging"):
        assert k in out, f"{k} missing from discover_inventory return"
