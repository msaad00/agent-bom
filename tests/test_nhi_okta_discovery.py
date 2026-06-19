"""Okta non-human-identity (NHI) discovery + graph projection.

All tests inject a fake Okta client — no live calls are ever made.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.nhi_overlay import apply_nhi_overlay, apply_nhi_overlay_from_result
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.identity.okta_nhi import (
    NHIDiscoveryStatus,
    discover_okta_non_human_identities,
)


class _FakeOktaClient:
    """Stand-in exposing the same read-only surface as ``OktaClient``."""

    def __init__(self, apps=None, tokens=None, fail_apps=False, fail_tokens=False):
        self._apps = apps or []
        self._tokens = tokens or []
        self._fail_apps = fail_apps
        self._fail_tokens = fail_tokens

    def list_oauth2_service_apps(self):
        if self._fail_apps:
            raise RuntimeError("403 Forbidden")
        return self._apps

    def list_api_tokens(self):
        if self._fail_tokens:
            raise RuntimeError("403 Forbidden")
        return self._tokens


def _service_app(app_id, label):
    return {
        "id": app_id,
        "label": label,
        "name": "oidc_client",
        "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "created": "2026-01-01T00:00:00Z",
        "lastUpdated": "2026-06-01T00:00:00Z",
        "settings": {
            "oauthClient": {
                "client_id": f"0oa{app_id}",
                "application_type": "service",
                "grant_types": ["client_credentials", "read_file"],
            }
        },
    }


def _human_app(app_id, label):
    # SAML/SSO human app — must be filtered out of NHI discovery.
    return {
        "id": app_id,
        "label": label,
        "status": "ACTIVE",
        "signOnMode": "SAML_2_0",
        "settings": {},
    }


def _api_token(token_id, name, user_id="00uHUMAN"):
    return {
        "id": token_id,
        "name": name,
        "status": "ACTIVE",
        "userId": user_id,
        "created": "2026-02-01T00:00:00Z",
        "lastUpdated": "2026-06-10T00:00:00Z",
        "expiresAt": "2026-09-01T00:00:00Z",
    }


# ── Enumeration → records ────────────────────────────────────────────────────


def test_discovers_service_accounts_and_api_tokens_filters_human_apps():
    client = _FakeOktaClient(
        apps=[_service_app("APP1", "billing-svc"), _human_app("APP2", "okta-dashboard")],
        tokens=[_api_token("TOK1", "ci-token")],
    )
    result = discover_okta_non_human_identities(client=client)

    assert result.status is NHIDiscoveryStatus.OK
    assert result.ok is True
    by_type = {i.identity_type for i in result.identities}
    assert by_type == {"service_account", "api_token"}
    assert len(result.identities) == 2  # human SAML app filtered out

    svc = next(i for i in result.identities if i.identity_type == "service_account")
    assert svc.identity_id == "APP1"
    assert svc.name == "billing-svc"
    assert svc.created_at == "2026-01-01T00:00:00Z"
    assert "client_credentials" in svc.scopes

    tok = next(i for i in result.identities if i.identity_type == "api_token")
    assert tok.identity_id == "TOK1"
    assert tok.owner == "00uHUMAN"
    assert tok.credential_expires_at == "2026-09-01T00:00:00Z"


def test_empty_org_is_ok_with_no_identities():
    result = discover_okta_non_human_identities(client=_FakeOktaClient())
    assert result.status is NHIDiscoveryStatus.OK
    assert result.identities == ()


def test_partial_api_failure_still_returns_other_identities():
    client = _FakeOktaClient(apps=[_service_app("APP1", "svc")], fail_tokens=True)
    result = discover_okta_non_human_identities(client=client)
    assert result.status is NHIDiscoveryStatus.OK
    assert [i.identity_type for i in result.identities] == ["service_account"]
    assert any("API-token listing failed" in w for w in result.warnings)


def test_total_api_failure_is_error_status_not_raise():
    client = _FakeOktaClient(fail_apps=True, fail_tokens=True)
    result = discover_okta_non_human_identities(client=client)
    assert result.status is NHIDiscoveryStatus.ERROR
    assert result.identities == ()
    assert len(result.warnings) == 2


# ── Flag gating ──────────────────────────────────────────────────────────────


def test_flag_off_returns_disabled_without_network(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_OKTA_DISCOVERY", raising=False)
    monkeypatch.delenv("AGENT_BOM_OKTA_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OKTA_ORG_URL", raising=False)
    result = discover_okta_non_human_identities()
    assert result.status is NHIDiscoveryStatus.DISABLED
    assert result.identities == ()
    assert any("disabled" in w.lower() for w in result.warnings)


def test_flag_on_but_missing_credentials(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "1")
    monkeypatch.delenv("AGENT_BOM_OKTA_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OKTA_ORG_URL", raising=False)
    result = discover_okta_non_human_identities()
    assert result.status is NHIDiscoveryStatus.MISSING_CREDENTIALS
    assert result.identities == ()
    warning = result.warnings[0]
    assert "AGENT_BOM_OKTA_TOKEN" in warning
    assert "AGENT_BOM_OKTA_ORG_URL" in warning


def test_flag_on_with_creds_uses_no_network_when_client_injected(monkeypatch):
    # Flag on + creds present, but an injected client means OktaClient (and thus
    # any HTTP) is never constructed.
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "true")
    monkeypatch.setenv("AGENT_BOM_OKTA_TOKEN", "ssws-xxx")
    monkeypatch.setenv("AGENT_BOM_OKTA_ORG_URL", "https://example.okta.com")
    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("A", "svc")]))
    assert result.status is NHIDiscoveryStatus.OK
    assert len(result.identities) == 1


# ── Graph projection ─────────────────────────────────────────────────────────


def _graph_with_tool() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default")
    graph.add_node(UnifiedNode(id="tool:srv:read_file", entity_type=EntityType.TOOL, label="read_file"))
    return graph


def test_overlay_projects_nhis_as_managed_identity_nodes_with_tool_scope():
    client = _FakeOktaClient(
        apps=[_service_app("APP1", "billing-svc")],
        tokens=[_api_token("TOK1", "ci-token")],
    )
    result = discover_okta_non_human_identities(client=client)

    graph = _graph_with_tool()
    stats = apply_nhi_overlay(graph, result.identities)
    assert stats["nodes_added"] == 2

    mi_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
    assert len(mi_nodes) == 2
    assert all(n.attributes["discovered"] is True for n in mi_nodes)
    assert all(n.attributes["provider"] == "okta" for n in mi_nodes)

    # The service app's "read_file" grant matches the tool node → SCOPED_TO edge.
    scoped = [(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.SCOPED_TO]
    svc_node = next(n for n in mi_nodes if n.attributes["identity_type"] == "service_account")
    assert (svc_node.id, "tool:srv:read_file") in scoped


def test_overlay_is_idempotent():
    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("APP1", "svc")]))
    graph = _graph_with_tool()
    first = apply_nhi_overlay(graph, result.identities)
    second = apply_nhi_overlay(graph, result.identities)
    assert first["nodes_added"] == 1
    assert second["nodes_added"] == 0


def test_overlay_from_result_noop_when_disabled():
    graph = _graph_with_tool()
    disabled = discover_okta_non_human_identities()  # flag off
    stats = apply_nhi_overlay_from_result(graph, disabled)
    assert stats == {"nodes_added": 0, "edges_added": 0}
    assert not [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]


def test_managed_identity_nodes_are_consumable_by_effective_permissions():
    from agent_bom.graph.effective_permissions import _PRINCIPAL_TYPES

    # The discovered NHI uses MANAGED_IDENTITY, which the effective-permissions
    # engine already treats as a principal — so discovered identities feed it.
    assert EntityType.MANAGED_IDENTITY in _PRINCIPAL_TYPES

    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("APP1", "svc")]))
    graph = _graph_with_tool()
    apply_nhi_overlay(graph, result.identities)
    principals = [n for n in graph.nodes.values() if n.entity_type in _PRINCIPAL_TYPES]
    assert len(principals) == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
