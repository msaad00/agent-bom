"""Deployment labels describe source receipts, never backend or enforcement policy."""

from types import SimpleNamespace

import pytest

from agent_bom.api.models import JobStatus
from agent_bom.api.routes import compliance


@pytest.fixture
def derive(monkeypatch):
    monkeypatch.setattr(compliance, "_tenant_id", lambda request: "mode-tenant")
    monkeypatch.setattr(compliance, "_get_fleet_store", lambda: SimpleNamespace(list_by_tenant=lambda tenant: []))
    monkeypatch.setattr(
        compliance, "_get_policy_store", lambda: SimpleNamespace(list_policies=lambda **kw: [], list_audit_entries=lambda **kw: [])
    )
    monkeypatch.setattr(compliance, "_tenant_has_proxy_alerts", lambda tenant: False)
    return lambda results: compliance._derive_deployment_context(
        None, [SimpleNamespace(status=JobStatus.DONE, result=result) for result in results]
    )


@pytest.mark.parametrize("source", ["sbom", "external_scan", "image", "unknown_collector"])
def test_imported_agent_or_mcp_context_does_not_establish_local_scan(derive, source):
    context = derive([{"scan_sources": [source], "has_agent_context": True, "has_mcp_context": True}])
    assert context["has_local_scan"] is False
    assert context["deployment_mode"] == "ingest"
    assert context["has_agent_context"] is True
    assert context["has_mcp_context"] is True


def test_no_observations_are_unknown(derive):
    assert derive([])["deployment_mode"] == "unknown"


@pytest.mark.parametrize(
    ("sources", "mode", "flag"),
    [
        (["agent_discovery"], "local", "has_local_scan"),
        (["filesystem"], "local", "has_local_scan"),
        (["github_actions"], "ci", "has_ci_cd_scan"),
        (["k8s"], "cluster", "has_cluster_scan"),
        (["agent_discovery", "github_actions"], "hybrid", "has_local_scan"),
    ],
)
def test_explicit_source_receipts_describe_collection(derive, sources, mode, flag):
    context = derive([{"scan_sources": sources}])
    assert context["deployment_mode"] == mode
    assert context[flag] is True
