"""AWS Organizations: discovery (mocked) + the org→OU→account→SCP graph."""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report


# ── Graph ────────────────────────────────────────────────────────────────
def _org() -> dict:
    return {
        "status": "ok",
        "org_id": "o-abc",
        "master_account_id": "111111111111",
        "feature_set": "ALL",
        "organizational_units": [
            {"id": "r-root", "name": "Root", "parent_id": "", "is_root": True},
            {"id": "ou-prod", "name": "Production", "parent_id": "r-root", "is_root": False},
        ],
        "accounts": [{"id": "222222222222", "name": "prod-app", "status": "ACTIVE", "ou_id": "ou-prod"}],
        "scps": [{"id": "p-deny", "name": "DenyRoot", "aws_managed": False, "targets": ["ou-prod", "222222222222"]}],
    }


def _edges():
    g = build_unified_graph_from_report({"aws_organization": _org()})
    return g, {(e.source, e.target, e.relationship.value) for e in g.edges}


def test_org_ou_account_contains_hierarchy() -> None:
    g, edges = _edges()
    assert "org:aws:o-abc" in g.nodes
    assert ("org:aws:ou:r-root", "org:aws:ou:ou-prod", "contains") in edges
    assert ("org:aws:ou:ou-prod", "account:aws:222222222222", "contains") in edges


def test_scp_governs_targets() -> None:
    _, edges = _edges()
    assert ("org:aws:o-abc", "policy:aws:scp:p-deny", "owns") in edges
    assert ("policy:aws:scp:p-deny", "org:aws:ou:ou-prod", "governs") in edges
    assert ("policy:aws:scp:p-deny", "account:aws:222222222222", "governs") in edges  # 12-digit → account


def test_account_node_id_matches_inventory_scheme() -> None:
    # The org's account uses the SAME id a per-account scan emits, so they stitch.
    g, _ = _edges()
    assert "account:aws:222222222222" in g.nodes


def test_non_ok_payload_is_noop() -> None:
    g = build_unified_graph_from_report({"aws_organization": {"status": "not_in_org"}})
    assert not [k for k in g.nodes if k.startswith("org:aws")]


# ── Discovery (mocked boto3 organizations) ───────────────────────────────
class _Paginator:
    def __init__(self, key, items):
        self._key = key
        self._items = items

    def paginate(self, **_kw):
        return [{self._key: self._items}]


class _OrgClient:
    def describe_organization(self):
        return {"Organization": {"Id": "o-xyz", "MasterAccountId": "111111111111", "FeatureSet": "ALL"}}

    def list_roots(self):
        return {"Roots": [{"Id": "r-1", "Name": "Root"}]}

    def get_paginator(self, op):
        if op == "list_organizational_units_for_parent":
            return _Paginator("OrganizationalUnits", [{"Id": "ou-1", "Name": "Prod"}])
        if op == "list_accounts_for_parent":
            return _Paginator("Accounts", [{"Id": "222222222222", "Name": "app", "Status": "ACTIVE"}])
        if op == "list_policies":
            return _Paginator("Policies", [{"Id": "p-1", "Name": "Deny", "AwsManaged": False}])
        if op == "list_targets_for_policy":
            return _Paginator("Targets", [{"TargetId": "ou-1"}])
        return _Paginator("X", [])


class _Session:
    def client(self, svc):
        return _OrgClient()


@pytest.fixture(autouse=True)
def _stub_boto3(monkeypatch):
    boto3 = types.ModuleType("boto3")
    boto3.Session = lambda **_kw: _Session()
    errs = types.ModuleType("botocore.exceptions")
    errs.NoCredentialsError = type("NoCredentialsError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.exceptions", errs)


def test_discovery_walks_org_ou_accounts_scps() -> None:
    from agent_bom.cloud.aws_organizations import discover_organization

    out = discover_organization(force=True)
    assert out["status"] == "ok"
    assert out["org_id"] == "o-xyz"
    # root + 1 OU
    assert {o["id"] for o in out["organizational_units"]} == {"r-1", "ou-1"}
    assert out["accounts"][0]["ou_id"] in {"r-1", "ou-1"}
    assert out["scps"][0]["targets"] == ["ou-1"]


def test_not_in_org_is_graceful() -> None:
    from agent_bom.cloud.aws_organizations import discover_organization

    class _NoOrg(_OrgClient):
        def describe_organization(self):
            raise type("AWSOrganizationsNotInUseException", (Exception,), {})()

    class _NoOrgSession:
        def client(self, svc):
            return _NoOrg()

    sys.modules["boto3"].Session = lambda **_kw: _NoOrgSession()
    out = discover_organization(force=True)
    assert out["status"] == "not_in_org"
    assert out["accounts"] == []
