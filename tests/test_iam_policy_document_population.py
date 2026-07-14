"""Populate raw IAM policy documents onto graph POLICY nodes so the
effective-permissions overlay runs REAL policy evaluation on real scans.

Before this wiring the inventory->graph boundary only carried a scanner-derived
``privilege_level``; the raw policy document was fetched during discovery and
then dropped, leaving ``effective_permissions`` unable to evaluate and forcing
it onto the name/keyword heuristic. These tests pin the full path:

    inventory discovery (retains document)
        -> builder ``_policy_entries`` (carries document)
        -> POLICY node ``policy_document`` attribute
        -> effective-permissions REAL evaluation (``policy_evaluation`` basis)
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.builder import _policy_entries, build_unified_graph_from_report
from agent_bom.graph.types import EntityType

_ALLOW_STAR = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
_READ_ONLY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


class _Paginator:
    def __init__(self, pages: list[dict[str, Any]]):
        self._pages = pages

    def paginate(self, **_kw: Any) -> list[dict[str, Any]]:
        return self._pages


# ── inventory discovery retains the raw policy document ──────────────────────
class _InventoryIam:
    """Minimal IAM client for attached + inline customer-managed policies."""

    def get_paginator(self, op: str) -> _Paginator:
        if op == "list_attached_role_policies":
            return _Paginator([{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/team-custom", "PolicyName": "team-custom"}]}])
        if op == "list_role_policies":
            return _Paginator([{"PolicyNames": ["inline-utility"]}])
        return _Paginator([])

    def get_policy(self, PolicyArn: str) -> dict[str, Any]:  # noqa: N803 — boto3 param name
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn: str, VersionId: str) -> dict[str, Any]:  # noqa: N803
        return {"PolicyVersion": {"Document": _ALLOW_STAR}}

    def get_role_policy(self, RoleName: str, PolicyName: str) -> dict[str, Any]:  # noqa: N803
        return {"PolicyDocument": _READ_ONLY}


def test_attached_customer_managed_policy_retains_document() -> None:
    from agent_bom.cloud import aws_inventory as inv

    policies = inv._attached_policies(_InventoryIam(), "role", "batch-helper-role", warnings=[])
    assert policies, "expected the attached customer-managed policy"
    assert policies[0]["policy_document"] == _ALLOW_STAR
    assert policies[0]["privilege_level"] == "admin"


def test_attached_aws_managed_policy_has_no_document() -> None:
    from agent_bom.cloud import aws_inventory as inv

    class _AwsManagedIam(_InventoryIam):
        def get_paginator(self, op: str) -> _Paginator:
            if op == "list_attached_role_policies":
                arn = "arn:aws:iam::aws:policy/AdministratorAccess"
                return _Paginator([{"AttachedPolicies": [{"PolicyArn": arn, "PolicyName": "AdministratorAccess"}]}])
            return _Paginator([])

    policies = inv._attached_policies(_AwsManagedIam(), "role", "r", warnings=[])
    # AWS-managed policies are classified by name without a fetch; no document to carry.
    assert policies[0]["privilege_level"] == "admin"
    assert policies[0].get("policy_document") is None


def test_inline_policy_retains_document() -> None:
    from agent_bom.cloud import aws_inventory as inv

    policies = inv._inline_policies(_InventoryIam(), "role", "batch-helper-role", warnings=[])
    assert policies, "expected the inline policy"
    assert policies[0]["policy_document"] == _READ_ONLY
    assert policies[0]["attachment_type"] == "inline"


# ── builder carries the document from principal dict onto the POLICY node ─────
def test_policy_entries_carries_document() -> None:
    principal = {
        "policies": [
            {"policy_id": "p/inline", "policy_name": "team-utility", "privilege_level": "unknown", "policy_document": _ALLOW_STAR},
            {"policy_id": "p/none", "policy_name": "no-doc", "privilege_level": "unknown"},
        ]
    }
    entries = _policy_entries(principal)
    assert entries[0]["policy_document"] == _ALLOW_STAR
    assert "policy_document" not in entries[1]


# ── end-to-end: scanned inline wildcard policy -> admin via EVALUATION ────────
def _inventory_report(policy_document: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_sources": ["aws-inventory"],
        "cloud_inventory": {
            "status": "ok",
            "provider": "aws",
            "account_id": "111122223333",
            "roles": [
                {
                    "name": "batch-helper-role",
                    "arn": "arn:aws:iam::111122223333:role/batch-helper-role",
                    "principal_type": "role",
                    "privilege_level": "unknown",  # benign: scanner did NOT flag admin
                    "policies": [
                        {
                            "policy_id": "batch-helper-role/inline-utility",
                            "policy_name": "team-utility-policy",  # benign name, no admin keyword
                            "attachment_type": "inline",
                            "privilege_level": "unknown",
                            "policy_document": policy_document,
                        }
                    ],
                }
            ],
        },
    }


def test_scanned_wildcard_policy_flagged_admin_via_evaluation_end_to_end() -> None:
    graph = build_unified_graph_from_report(_inventory_report(_ALLOW_STAR))

    policy_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.POLICY]
    assert policy_nodes, "expected a POLICY node built from inventory"
    assert any(n.attributes.get("policy_document") == _ALLOW_STAR for n in policy_nodes), "raw document must reach the POLICY node"

    role = next(n for n in graph.nodes.values() if n.entity_type == EntityType.ROLE)
    # The benignly-named policy is caught ONLY because the overlay evaluated the
    # real document — the name/keyword heuristic (#3888 could only catch in theory)
    # would have missed it.
    assert role.attributes.get("admin_equivalent") is True
    assert role.attributes.get("admin_equivalence_basis") == "policy_evaluation"


def test_scanned_benign_read_only_policy_not_flagged_admin_end_to_end() -> None:
    # Control: same benign name, but a read-only document -> a real evaluation
    # verdict of NOT admin (recorded basis is still policy_evaluation, not a guess).
    graph = build_unified_graph_from_report(_inventory_report(_READ_ONLY))
    role = next(n for n in graph.nodes.values() if n.entity_type == EntityType.ROLE)
    assert role.attributes.get("admin_equivalent") is not True
    assert role.attributes.get("admin_equivalence_basis") == "policy_evaluation"
