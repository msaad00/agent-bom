"""Microsoft Entra ID (Azure AD) NHI discovery + graph projection.

All tests inject a fake Microsoft Graph client — no live calls are ever made.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.nhi_overlay import (
    apply_nhi_overlay,
    apply_nhi_overlay_from_report,
    merge_discovery_results,
    serialize_discovery_result,
)
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.identity.entra_nhi import discover_entra_non_human_identities
from agent_bom.identity.okta_nhi import NHIDiscoveryStatus


class _FakeGraphClient:
    """Stand-in exposing the same read-only surface as ``EntraClient``."""

    def __init__(self, service_principals=None, applications=None, fail_sps=False, fail_apps=False):
        self._sps = service_principals or []
        self._apps = applications or []
        self._fail_sps = fail_sps
        self._fail_apps = fail_apps

    def list_service_principals(self):
        if self._fail_sps:
            raise RuntimeError("403 Forbidden")
        return self._sps

    def list_applications(self):
        if self._fail_apps:
            raise RuntimeError("403 Forbidden")
        return self._apps


def _service_principal(sp_id, app_id, name, sp_type="Application", enabled=True):
    return {
        "id": sp_id,
        "appId": app_id,
        "displayName": name,
        "servicePrincipalType": sp_type,
        "accountEnabled": enabled,
        "createdDateTime": "2026-01-01T00:00:00Z",
    }


def _human_service_principal(sp_id, app_id, name):
    # Legacy/SSO entry — must be filtered out of NHI discovery.
    return {
        "id": sp_id,
        "appId": app_id,
        "displayName": name,
        "servicePrincipalType": "Legacy",
    }


def _application(obj_id, app_id, name, secret_end="2026-09-01T00:00:00Z", cert_end=None, scope_id="read_file"):
    app = {
        "id": obj_id,
        "appId": app_id,
        "displayName": name,
        "createdDateTime": "2026-01-01T00:00:00Z",
        "passwordCredentials": [{"endDateTime": secret_end}] if secret_end else [],
        "keyCredentials": [{"endDateTime": cert_end}] if cert_end else [],
        "requiredResourceAccess": [{"resourceAccess": [{"id": scope_id, "type": "Scope"}]}] if scope_id else [],
    }
    return app


# ── Enumeration → records ────────────────────────────────────────────────────


def test_discovers_service_principals_with_credential_expiry_filters_human():
    client = _FakeGraphClient(
        service_principals=[
            _service_principal("SP1", "app-1", "billing-svc"),
            _human_service_principal("SP2", "app-2", "human-sso"),
        ],
        applications=[_application("OBJ1", "app-1", "billing-svc", secret_end="2026-09-01T00:00:00Z")],
    )
    result = discover_entra_non_human_identities(client=client)

    assert result.status is NHIDiscoveryStatus.OK
    assert result.ok is True
    assert len(result.identities) == 1  # human Legacy SP filtered out

    sp = result.identities[0]
    assert sp.identity_id == "SP1"
    assert sp.name == "billing-svc"
    assert sp.identity_type == "service_principal"
    assert sp.provider == "entra"
    assert sp.credential_expires_at == "2026-09-01T00:00:00Z"
    assert "read_file" in sp.scopes
    # No secret material is ever captured.
    assert "passwordCredentials" not in sp.raw_identity
    assert "secret" not in sp.to_dict()


def test_earliest_credential_expiry_wins_across_secret_and_cert():
    client = _FakeGraphClient(
        service_principals=[_service_principal("SP1", "app-1", "svc")],
        applications=[
            _application("OBJ1", "app-1", "svc", secret_end="2027-01-01T00:00:00Z", cert_end="2026-03-01T00:00:00Z"),
        ],
    )
    result = discover_entra_non_human_identities(client=client)
    assert result.identities[0].credential_expires_at == "2026-03-01T00:00:00Z"


def test_orphan_app_registration_with_credentials_is_reported():
    # App with credentials but no service principal in the tenant is still an NHI.
    client = _FakeGraphClient(
        service_principals=[],
        applications=[_application("OBJ9", "app-9", "ci-app", secret_end="2026-12-01T00:00:00Z")],
    )
    result = discover_entra_non_human_identities(client=client)
    assert result.status is NHIDiscoveryStatus.OK
    assert [i.identity_type for i in result.identities] == ["app_registration"]
    assert result.identities[0].credential_expires_at == "2026-12-01T00:00:00Z"


def test_empty_tenant_is_ok_with_no_identities():
    result = discover_entra_non_human_identities(client=_FakeGraphClient())
    assert result.status is NHIDiscoveryStatus.OK
    assert result.identities == ()


def test_partial_api_failure_still_returns_other_identities():
    client = _FakeGraphClient(service_principals=[_service_principal("SP1", "app-1", "svc")], fail_apps=True)
    result = discover_entra_non_human_identities(client=client)
    assert result.status is NHIDiscoveryStatus.OK
    assert [i.identity_id for i in result.identities] == ["SP1"]
    assert any("application listing failed" in w for w in result.warnings)


def test_total_api_failure_is_error_status_not_raise():
    client = _FakeGraphClient(fail_sps=True, fail_apps=True)
    result = discover_entra_non_human_identities(client=client)
    assert result.status is NHIDiscoveryStatus.ERROR
    assert result.identities == ()
    assert len(result.warnings) == 2


# ── Flag gating ──────────────────────────────────────────────────────────────


def test_flag_off_returns_disabled_without_network(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_ENTRA_DISCOVERY", raising=False)
    monkeypatch.delenv("AGENT_BOM_ENTRA_TOKEN", raising=False)
    result = discover_entra_non_human_identities()
    assert result.status is NHIDiscoveryStatus.DISABLED
    assert result.identities == ()
    assert any("disabled" in w.lower() for w in result.warnings)


def test_flag_on_but_missing_credentials(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ENTRA_DISCOVERY", "1")
    monkeypatch.delenv("AGENT_BOM_ENTRA_TOKEN", raising=False)
    result = discover_entra_non_human_identities()
    assert result.status is NHIDiscoveryStatus.MISSING_CREDENTIALS
    assert result.identities == ()
    assert "AGENT_BOM_ENTRA_TOKEN" in result.warnings[0]


def test_flag_on_with_creds_uses_no_network_when_client_injected(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ENTRA_DISCOVERY", "true")
    monkeypatch.setenv("AGENT_BOM_ENTRA_TOKEN", "bearer-xxx")
    monkeypatch.setenv("AGENT_BOM_ENTRA_TENANT_ID", "tenant-abc")
    result = discover_entra_non_human_identities(
        client=_FakeGraphClient(service_principals=[_service_principal("SP1", "app-1", "svc")]),
    )
    assert result.status is NHIDiscoveryStatus.OK
    assert len(result.identities) == 1
    assert result.org_url == "tenant-abc"


# ── Graph projection ─────────────────────────────────────────────────────────


def _graph_with_tool() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default")
    graph.add_node(UnifiedNode(id="tool:srv:read_file", entity_type=EntityType.TOOL, label="read_file"))
    return graph


def test_overlay_projects_entra_nhis_as_managed_identity_nodes_with_tool_scope():
    client = _FakeGraphClient(
        service_principals=[_service_principal("SP1", "app-1", "billing-svc")],
        applications=[_application("OBJ1", "app-1", "billing-svc", scope_id="read_file")],
    )
    result = discover_entra_non_human_identities(client=client)

    graph = _graph_with_tool()
    stats = apply_nhi_overlay(graph, result.identities)
    assert stats["nodes_added"] == 1

    mi_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
    assert len(mi_nodes) == 1
    assert mi_nodes[0].attributes["discovered"] is True
    assert mi_nodes[0].attributes["provider"] == "entra"

    scoped = [(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.SCOPED_TO]
    assert (mi_nodes[0].id, "tool:srv:read_file") in scoped


# ── Report serialization + builder wiring ────────────────────────────────────


def test_serialize_result_carries_no_secret_material():
    client = _FakeGraphClient(
        service_principals=[_service_principal("SP1", "app-1", "svc")],
        applications=[_application("OBJ1", "app-1", "svc", secret_end="2026-09-01T00:00:00Z")],
    )
    payload = serialize_discovery_result(discover_entra_non_human_identities(client=client))
    assert payload["status"] == "ok"
    assert payload["provider"] == "entra"
    assert len(payload["identities"]) == 1
    serialized = repr(payload)
    assert "passwordCredentials" not in serialized
    assert "keyCredentials" not in serialized


def test_apply_nhi_overlay_from_report_emits_managed_identity_nodes():
    client = _FakeGraphClient(
        service_principals=[_service_principal("SP1", "app-1", "billing-svc")],
        applications=[_application("OBJ1", "app-1", "billing-svc", scope_id="read_file")],
    )
    merged = merge_discovery_results([discover_entra_non_human_identities(client=client)])
    report_json = {"identity_discovery": merged}

    graph = _graph_with_tool()
    stats = apply_nhi_overlay_from_report(graph, report_json)
    assert stats["nodes_added"] == 1

    mi_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
    assert len(mi_nodes) == 1
    assert mi_nodes[0].attributes["provider"] == "entra"
    scoped = [(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.SCOPED_TO]
    assert (mi_nodes[0].id, "tool:srv:read_file") in scoped


def test_builder_wiring_emits_managed_identity_from_discovery_report():
    # Full builder path: an "identity_discovery" block on the report must surface
    # as MANAGED_IDENTITY nodes after build_unified_graph_from_report runs.
    from agent_bom.graph.builder import build_unified_graph_from_report

    client = _FakeGraphClient(
        service_principals=[_service_principal("SP1", "app-1", "billing-svc")],
        applications=[_application("OBJ1", "app-1", "billing-svc")],
    )
    merged = merge_discovery_results([discover_entra_non_human_identities(client=client)])
    report_json = {
        "scan_id": "scan-1",
        "tenant_id": "default",
        "identity_discovery": merged,
    }
    graph = build_unified_graph_from_report(report_json)
    mi_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
    assert len(mi_nodes) == 1
    assert mi_nodes[0].attributes["provider"] == "entra"
    assert mi_nodes[0].attributes["identity_id"] == "SP1"


def test_apply_nhi_overlay_from_report_noop_when_block_absent():
    graph = _graph_with_tool()
    stats = apply_nhi_overlay_from_report(graph, {})
    assert stats == {"nodes_added": 0, "edges_added": 0}
    assert not [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]


def test_merge_aggregates_multiple_providers():
    entra = _FakeGraphClient(service_principals=[_service_principal("SP1", "app-1", "svc")], applications=[])
    merged = merge_discovery_results(
        [
            discover_entra_non_human_identities(client=entra),
            discover_entra_non_human_identities(client=_FakeGraphClient()),  # empty → ok, 0
        ]
    )
    assert merged["status"] == "ok"
    assert len(merged["identities"]) == 1
    assert len(merged["providers"]) == 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
