"""Wiring tests: opt-in estate enrichment actually populates the scan report.

The cloud-inventory and NHI-discovery connectors were fully built + unit-tested
but had no caller on the normal scan path, so ``cloud_inventory_data`` /
``identity_discovery_data`` were always None and the graph builder's consumers
were dead. These tests prove the wire now fires (flags on -> report populated ->
graph gains nodes) and that the default path is unchanged (flags off -> no
network, fields stay None).
"""

from __future__ import annotations

from typing import Any

import agent_bom.scan_enrichment as enrich
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json

_FLAGS = (
    "AGENT_BOM_CLOUD_INVENTORY",
    "AGENT_BOM_AZURE_INVENTORY",
    "AGENT_BOM_GCP_INVENTORY",
    "AGENT_BOM_OKTA_DISCOVERY",
    "AGENT_BOM_ENTRA_DISCOVERY",
    "AGENT_BOM_AUDIT_TRAIL",
)


def _clear_flags(monkeypatch: Any) -> None:
    for flag in _FLAGS:
        monkeypatch.delenv(flag, raising=False)


def _entity_types(report: AIBOMReport) -> dict[str, int]:
    report_json = to_json(report)
    graph = build_unified_graph_from_report(report_json, scan_id="s1", tenant_id="default")
    counts: dict[str, int] = {}
    for node in graph.nodes.values():
        key = getattr(node.entity_type, "value", node.entity_type)
        counts[str(key)] = counts.get(str(key), 0) + 1
    return counts


# ── Default OFF: no enrichment, no network ──────────────────────────────────


def test_flags_off_leaves_report_unenriched(monkeypatch):
    _clear_flags(monkeypatch)
    called = []
    monkeypatch.setattr(enrich, "collect_cloud_inventory", lambda: called.append("inv") or [])
    monkeypatch.setattr(enrich, "collect_identity_discovery", lambda: called.append("nhi") or None)

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)

    assert report.cloud_inventory_data is None
    assert report.identity_discovery_data is None


# ── Audit-trail: opt-in, read-only behavioral edges ─────────────────────────


def test_audit_trail_flag_off_is_noop(monkeypatch):
    """With AGENT_BOM_AUDIT_TRAIL unset no reader runs and the field stays None."""
    _clear_flags(monkeypatch)
    import agent_bom.cloud.audit_trail as at

    def _boom(*a, **k):
        raise AssertionError("collect_audit_trail must not run when the flag is off")

    monkeypatch.setattr(at, "collect_audit_trail", _boom)
    assert enrich.collect_audit_trail() == []

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)
    assert report.cloud_audit_trail_data is None


def test_audit_trail_flag_on_attaches_payload_and_projects_edges(monkeypatch):
    """Flag on + a credentialed provider -> ok payload attached -> graph gains edges."""
    _clear_flags(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL", "1")

    import agent_bom.cloud.audit_trail as at
    import agent_bom.cloud.auth_probe as probe

    # Only AWS resolves credentials; azure/gcp are skipped (no reader call).
    monkeypatch.setattr(probe, "provider_has_credentials", lambda p: (p == "aws", "test"))

    ok_payload = {
        "status": "ok",
        "provider": "aws",
        "account": "123456789012",
        "behavioral_edges": [
            {
                "principal": "alice",
                "action": "GetObject",
                "resource": "bucket/secret-data",
                "relationship": "accessed",
                "count": 3,
                "last_seen": "2026-06-24T10:00:00+00:00",
                "failure_count": 0,
                "is_sensitive_resource": True,
            }
        ],
        "behavioral_findings": [],
        "event_count": 3,
        "warnings": [],
    }

    seen_providers: list[str] = []

    def _fake_collect(*, provider, **kwargs):
        seen_providers.append(provider)
        return ok_payload if provider == "aws" else {"status": "skipped", "provider": provider}

    monkeypatch.setattr(at, "collect_audit_trail", _fake_collect)

    payloads = enrich.collect_audit_trail()
    assert payloads == [ok_payload]
    # azure/gcp credentialless -> their reader is never invoked.
    assert seen_providers == ["aws"]

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)
    assert report.cloud_audit_trail_data == [ok_payload]

    # The builder's existing consumer turns the edge into observed-reach nodes.
    report_json = to_json(report)
    assert report_json["cloud_audit_trail"] == [ok_payload]
    counts = _entity_types(report)
    assert counts.get("user", 0) >= 1, counts
    assert counts.get("cloud_resource", 0) >= 1, counts


def test_audit_trail_reader_crash_does_not_break_scan(monkeypatch):
    _clear_flags(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL", "1")
    import agent_bom.cloud.audit_trail as at
    import agent_bom.cloud.auth_probe as probe

    monkeypatch.setattr(probe, "provider_has_credentials", lambda p: (p == "aws", "test"))
    monkeypatch.setattr(at, "collect_audit_trail", lambda **k: (_ for _ in ()).throw(RuntimeError("boom")))

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)  # must not raise
    assert report.cloud_audit_trail_data is None


def test_collectors_make_no_call_when_flags_off(monkeypatch):
    """The collectors themselves must not invoke any connector with flags off."""
    _clear_flags(monkeypatch)
    # If a connector were called it would raise via the boom sentinel below.
    import agent_bom.cloud.aws_inventory as aws

    def _boom(*a, **k):
        raise AssertionError("discover_inventory must not run when the flag is off")

    monkeypatch.setattr(aws, "discover_inventory", _boom)
    assert enrich.collect_cloud_inventory() == []
    assert enrich.collect_identity_discovery() is None


# ── Flag ON: cloud inventory is collected, assigned, and projected ──────────


def test_cloud_inventory_flag_on_populates_report_and_graph(monkeypatch):
    _clear_flags(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_CLOUD_INVENTORY", "1")

    fake_payload = {
        "provider": "aws",
        "status": "ok",
        "account_id": "123456789012",
        "region": "us-east-1",
        "buckets": [{"name": "b1", "public": True, "region": "us-east-1", "arn": "arn:aws:s3:::b1"}],
        "instances": [],
        "security_groups": [],
        "roles": [],
        "users": [],
        "warnings": [],
    }
    import agent_bom.cloud.aws_inventory as aws

    monkeypatch.setattr(aws, "discover_inventory", lambda *a, **k: fake_payload)

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)

    assert report.cloud_inventory_data == [fake_payload]
    counts = _entity_types(report)
    assert counts.get("cloud_resource", 0) >= 1, counts


# ── Flag ON: NHI discovery is collected, merged, assigned, and projected ────


def test_nhi_flag_on_populates_report_and_graph(monkeypatch):
    _clear_flags(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "1")

    from agent_bom.identity.okta_nhi import (
        DiscoveredNonHumanIdentity,
        NHIDiscoveryResult,
        NHIDiscoveryStatus,
    )

    identity = DiscoveredNonHumanIdentity(
        identity_id="okta:app:1",
        provider="okta",
        identity_type="service_account",
        name="svc-deploy",
        scopes=("tools.read",),
        credential_expires_at="2026-01-01T00:00:00Z",
    )
    result = NHIDiscoveryResult(status=NHIDiscoveryStatus.OK, identities=(identity,))

    import agent_bom.identity as identity_pkg

    monkeypatch.setattr(identity_pkg, "discover_okta_non_human_identities", lambda *a, **k: result)
    # Entra flag is off -> its connector should not be reached.
    monkeypatch.setattr(
        identity_pkg,
        "discover_entra_non_human_identities",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("entra must not run")),
    )

    block = enrich.collect_identity_discovery()
    assert block is not None
    assert block["status"] == "ok"
    assert any(i["identity_id"] == "okta:app:1" for i in block["identities"])

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    report.identity_discovery_data = block
    counts = _entity_types(report)
    assert counts.get("managed_identity", 0) >= 1, counts


def test_enrich_helper_assigns_both_blocks(monkeypatch):
    _clear_flags(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_CLOUD_INVENTORY", "1")
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "1")
    monkeypatch.setattr(enrich, "collect_cloud_inventory", lambda: [{"provider": "aws", "status": "ok"}])
    monkeypatch.setattr(enrich, "collect_identity_discovery", lambda: {"status": "ok", "identities": []})

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)

    assert report.cloud_inventory_data == [{"provider": "aws", "status": "ok"}]
    assert report.identity_discovery_data == {"status": "ok", "identities": []}


def test_connector_crash_does_not_break_enrichment(monkeypatch):
    """A connector raising must be swallowed; the report stays usable."""
    _clear_flags(monkeypatch)
    monkeypatch.setattr(enrich, "collect_cloud_inventory", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(enrich, "collect_identity_discovery", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="s1")
    enrich.enrich_report_with_estate_discovery(report)  # must not raise

    assert report.cloud_inventory_data is None
    assert report.identity_discovery_data is None
