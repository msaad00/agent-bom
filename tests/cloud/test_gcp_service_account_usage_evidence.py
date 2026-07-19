"""GCP CIEM last-mile: service-account usage evidence feeds nhi_governance.

Before this change ``_discover_service_accounts`` emitted only
name/email/disabled/privilege_level, so a GCP service account could NEVER produce
an over-grant / dormant CIEM finding — ``nhi_governance`` governs
``SERVICE_ACCOUNT`` but had no ``last_used_at`` / ``usage_evidence`` to evaluate,
so the fail-closed rules never fired. These tests pin:

1. The inventory record now carries ``usage_evidence`` shaped exactly like the
   AWS Access-Advisor payload the graph builder already consumes.
2. Fed through the real builder, a GCP SA with an available, never-used grant
   produces a CIEM over-privilege finding.
3. Absent usage evidence (no read-only GCP usage source wired) stays UNEVALUABLE
   — no last_used_at, no access-advisor edges, no fabricated finding (fail-closed).
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import patch

from agent_bom.cloud import gcp_inventory
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.nhi_governance import build_ciem_over_privilege_findings
from agent_bom.graph.types import EntityType


class _FakeSA:
    def __init__(self, email: str, display_name: str, unique_id: str, disabled: bool = False) -> None:
        self.email = email
        self.display_name = display_name
        self.unique_id = unique_id
        self.disabled = disabled


def _install_fake_iam(accounts: list[_FakeSA]) -> Any:
    class _FakeIAMClient:
        def __init__(self, credentials: Any = None) -> None:
            pass

        def list_service_accounts(self, request: Any) -> list[Any]:
            return list(accounts)

    class _FakeReq:
        def __init__(self, name: str) -> None:
            self.name = name

    iam_mod = types.ModuleType("google.cloud.iam_admin_v1")
    iam_mod.IAMClient = _FakeIAMClient  # type: ignore[attr-defined]
    iam_mod.ListServiceAccountsRequest = _FakeReq  # type: ignore[attr-defined]
    return patch.dict(
        sys.modules,
        {
            "google": types.ModuleType("google"),
            "google.cloud": types.ModuleType("google.cloud"),
            "google.cloud.iam_admin_v1": iam_mod,
        },
    )


def test_discover_emits_usage_evidence_deferred_by_default() -> None:
    accounts = [_FakeSA("svc@p.iam.gserviceaccount.com", "Svc", "u-1")]
    with _install_fake_iam(accounts):
        records = gcp_inventory._discover_service_accounts(
            "proj-1", credentials=None, warnings=[], iam_bindings={}
        )
    assert len(records) == 1
    usage = records[0]["usage_evidence"]
    # Fail-closed default: usage is unevaluable (no wired GCP usage source), NOT
    # fabricated as "used" or "unused".
    assert usage["state"] != "available"
    assert usage["records"] == []


def test_discover_emits_usage_evidence_from_resolver() -> None:
    accounts = [_FakeSA("svc@p.iam.gserviceaccount.com", "Svc", "u-1")]

    def resolver(email: str, roles: list[str]) -> dict[str, Any]:
        return {
            "state": "available",
            "records": [
                {"service_namespace": "storage.googleapis.com", "state": "available", "last_accessed_at": None},
                {"service_namespace": "compute.googleapis.com", "state": "available", "last_accessed_at": "2026-01-01T00:00:00Z"},
            ],
        }

    with _install_fake_iam(accounts):
        records = gcp_inventory._discover_service_accounts(
            "proj-1", credentials=None, warnings=[], iam_bindings={}, usage_resolver=resolver
        )
    usage = records[0]["usage_evidence"]
    assert usage["state"] == "available"
    assert {r["service_namespace"] for r in usage["records"]} == {
        "storage.googleapis.com",
        "compute.googleapis.com",
    }


def _gcp_inventory_with_sa(usage_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": "gcp",
        "status": "ok",
        "project_id": "proj-1",
        "service_accounts": [
            {
                "principal_type": "service-account",
                "name": "Over-Permissioned",
                "arn": "overperm@p.iam.gserviceaccount.com",
                "principal_id": "u-2",
                "email": "overperm@p.iam.gserviceaccount.com",
                "disabled": False,
                "account_id": "proj-1",
                "roles": ["roles/editor"],
                "policies": [],
                "trust_principals": [],
                "privilege_level": "write",
                "usage_evidence": usage_evidence,
            }
        ],
    }


def test_gcp_sa_with_usage_evidence_produces_ciem_finding() -> None:
    usage = {
        "state": "available",
        "records": [
            {"service_namespace": "storage.googleapis.com", "state": "available", "last_accessed_at": None},
            {"service_namespace": "compute.googleapis.com", "state": "available", "last_accessed_at": "2026-01-01T00:00:00Z"},
        ],
    }
    graph = build_unified_graph_from_report({"cloud_inventory": _gcp_inventory_with_sa(usage)})

    sa_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.SERVICE_ACCOUNT]
    assert sa_nodes, "GCP service account should become a SERVICE_ACCOUNT node"

    findings = build_ciem_over_privilege_findings(graph)
    ciem = [f for f in findings if f.evidence.get("ciem") == "over_privilege"]
    assert len(ciem) == 1, [f.title for f in findings]
    assert ciem[0].evidence["cloud_provider"] == "gcp"
    # unused_permissions is a list of GCP service identifiers; assert exact set
    # membership (not a URL substring — CodeQL's url-sanitization heuristic
    # misfires on the .googleapis.com shape otherwise).
    # unused_permissions is a list of GCP service identifiers; use set-method
    # assertions (not the ``in`` operator) so CodeQL's url-substring heuristic
    # does not misfire on the ``.googleapis.com`` shape.
    unused = set(ciem[0].evidence["unused_permissions"])
    assert unused.issuperset({"storage.googleapis.com"})
    # The used service must NOT be flagged.
    assert unused.isdisjoint({"compute.googleapis.com"})


def test_gcp_sa_without_usage_evidence_stays_unevaluable() -> None:
    usage = {
        "state": "unavailable",
        "diagnostic": "gcp_service_account_usage_source_not_configured",
        "records": [],
    }
    graph = build_unified_graph_from_report({"cloud_inventory": _gcp_inventory_with_sa(usage)})

    sa_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.SERVICE_ACCOUNT]
    assert sa_nodes
    # No last_used_at was fabricated from absent telemetry.
    assert "last_used_at" not in sa_nodes[0].attributes
    # Fail-closed: no over-privilege finding is invented without usage evidence.
    findings = build_ciem_over_privilege_findings(graph)
    assert [f for f in findings if f.evidence.get("ciem") == "over_privilege"] == []
