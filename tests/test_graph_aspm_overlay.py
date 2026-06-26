"""Tests for the ASPM (Application Security Posture Management) overlay.

The overlay organises the AppSec findings already in the graph AROUND the
application they belong to: it derives APPLICATION roots from finding source
paths, attaches findings via BELONGS_TO, rolls up per-app risk, dedupes the same
CVE/rule across sources, and flags reachability from existing attack-path data.
It is a pure correlation layer (no scanners) — deterministic, idempotent, and a
no-op when the report carries no findings.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from agent_bom.graph.aspm_overlay import apply_aspm_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

NOW = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)


def _finding(
    *,
    source: str,
    severity: str = "high",
    cve_id: str | None = None,
    title: str = "",
    location: str = "",
    name: str = "pkg",
    identifier: str | None = None,
    asset_type: str = "package",
    reachability: str = "",
    is_actionable: bool = False,
) -> dict:
    """Build a minimal ``Finding.to_dict()``-shaped payload."""
    return {
        "source": source,
        "severity": severity,
        "effective_severity": severity,
        "cve_id": cve_id,
        "title": title or (cve_id or "finding"),
        "finding_type": "CVE" if cve_id else "SAST",
        "reachability": reachability,
        "is_actionable": is_actionable,
        "asset": {
            "name": name,
            "asset_type": asset_type,
            "identifier": identifier,
            "location": location,
            "stable_id": identifier or f"stable:{name}:{location}",
            "canonical_id": identifier or f"stable:{name}:{location}",
        },
    }


def _app_node(graph: UnifiedGraph, app_key: str) -> UnifiedNode:
    node = graph.get_node(f"application:{app_key}")
    assert node is not None, f"no application node for {app_key} (have {sorted(graph.nodes)})"
    return node


# ── No-op safety ─────────────────────────────────────────────────────────


def test_empty_findings_is_byte_identical_noop():
    graph = UnifiedGraph(scan_id="s1")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    before = copy.deepcopy(graph.to_dict())

    for report in ({}, {"findings": []}, {"findings": [123, "x"]}):
        result = apply_aspm_overlay(graph, report, NOW)
        assert result == {"applications": 0, "correlated_findings": 0, "deduplicated": 0, "reachable": 0}
        assert graph.to_dict() == before


def test_findings_without_derivable_app_are_skipped():
    graph = UnifiedGraph(scan_id="s1")
    # No location and no asset name → no app derivable.
    report = {"findings": [_finding(source="SAST", location="", name="")]}
    result = apply_aspm_overlay(graph, report, NOW)
    assert result["applications"] == 0
    assert not [n for n in graph.nodes if n.startswith("application:")]


# ── Application derivation + aggregation ───────────────────────────────────


def test_findings_group_into_the_right_apps():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "findings": [
            _finding(source="SBOM", location="services/billing/requirements.txt", name="requests", cve_id="CVE-2024-1"),
            _finding(source="SAST", location="services/billing/app/main.py", name="main.py", title="sql-injection"),
            _finding(source="SECRET_SCAN", location="services/checkout/config.yaml", name="config", title="aws-key"),
        ]
    }
    result = apply_aspm_overlay(graph, report, NOW)

    assert result["correlated_findings"] == 3
    app_ids = sorted(n for n in graph.nodes if n.startswith("application:"))
    assert app_ids == ["application:services/billing", "application:services/checkout"]

    billing = _app_node(graph, "services/billing")
    checkout = _app_node(graph, "services/checkout")
    assert billing.attributes["finding_count"] == 2
    assert checkout.attributes["finding_count"] == 1


def test_manifest_file_collapses_to_its_directory_root():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "findings": [
            _finding(source="SBOM", location="apps/web/package.json", name="lodash", cve_id="CVE-2024-2"),
            _finding(source="SBOM", location="apps/web/package-lock.json", name="lodash", cve_id="CVE-2024-2"),
        ]
    }
    apply_aspm_overlay(graph, report, NOW)
    assert _app_node(graph, "apps/web").attributes["app_key"] == "apps/web"


def test_per_app_risk_rollup_counts_and_score():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "findings": [
            _finding(source="SBOM", location="svc/api/go.mod", name="a", cve_id="CVE-1", severity="critical"),
            _finding(source="SBOM", location="svc/api/go.mod", name="b", cve_id="CVE-2", severity="high"),
            _finding(source="SAST", location="svc/api/h.go", name="h.go", title="xss", severity="medium"),
        ]
    }
    apply_aspm_overlay(graph, report, NOW)
    app = _app_node(graph, "svc/api")
    counts = app.attributes["severity_counts"]
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 0
    # 8.0 (crit) + 6.0 (high) + 4.0 (med) = 18.0
    assert app.attributes["aspm_risk_score"] == pytest.approx(18.0)
    # App severity = worst bucket present.
    assert app.severity == "critical"


def test_belongs_to_edges_attach_existing_finding_nodes():
    graph = UnifiedGraph(scan_id="s1")
    # The vuln node must already exist for a BELONGS_TO edge to be drawn.
    graph.add_node(UnifiedNode(id="vuln:CVE-2024-9", entity_type=EntityType.VULNERABILITY, label="CVE-2024-9", severity="high"))
    report = {"findings": [_finding(source="SBOM", location="svc/pay/pom.xml", name="log4j", cve_id="CVE-2024-9")]}
    apply_aspm_overlay(graph, report, NOW)

    belongs = [
        e
        for e in graph.edges
        if e.relationship == RelationshipType.BELONGS_TO and e.source == "vuln:CVE-2024-9" and e.target == "application:svc/pay"
    ]
    assert len(belongs) == 1


def test_finding_without_existing_node_is_counted_but_no_dangling_edge():
    graph = UnifiedGraph(scan_id="s1")
    # No vuln node added → finding counted in roll-up, but no BELONGS_TO edge.
    report = {"findings": [_finding(source="SBOM", location="svc/x/go.mod", name="z", cve_id="CVE-X")]}
    apply_aspm_overlay(graph, report, NOW)
    assert _app_node(graph, "svc/x").attributes["finding_count"] == 1
    assert not [e for e in graph.edges if e.relationship == RelationshipType.BELONGS_TO]


# ── Cross-finding dedup ────────────────────────────────────────────────────


def test_same_cve_across_two_sources_counted_once_with_both_in_provenance():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "findings": [
            _finding(source="SBOM", location="svc/api/go.mod", name="openssl", identifier="pkg:generic/openssl@1.0", cve_id="CVE-7"),
            _finding(source="CONTAINER", location="svc/api/go.mod", name="openssl", identifier="pkg:generic/openssl@1.0", cve_id="CVE-7"),
        ]
    }
    result = apply_aspm_overlay(graph, report, NOW)

    assert result["correlated_findings"] == 2
    assert result["deduplicated"] == 1
    app = _app_node(graph, "svc/api")
    # Two source reports of the same (component, CVE) collapse to one finding.
    assert app.attributes["finding_count"] == 1
    # Both reporting sources retained as provenance.
    assert app.attributes["finding_sources"] == ["container", "sbom"]


def test_different_components_same_cve_not_deduped():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "findings": [
            _finding(source="SBOM", location="svc/api/go.mod", name="a", identifier="pkg:a@1", cve_id="CVE-9"),
            _finding(source="SBOM", location="svc/api/go.mod", name="b", identifier="pkg:b@1", cve_id="CVE-9"),
        ]
    }
    result = apply_aspm_overlay(graph, report, NOW)
    assert result["deduplicated"] == 0
    assert _app_node(graph, "svc/api").attributes["finding_count"] == 2


def test_dedup_keeps_worst_severity():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "findings": [
            _finding(source="SBOM", location="svc/api/go.mod", name="x", identifier="pkg:x@1", cve_id="CVE-5", severity="low"),
            _finding(source="CONTAINER", location="svc/api/go.mod", name="x", identifier="pkg:x@1", cve_id="CVE-5", severity="critical"),
        ]
    }
    apply_aspm_overlay(graph, report, NOW)
    app = _app_node(graph, "svc/api")
    assert app.attributes["finding_count"] == 1
    assert app.attributes["severity_counts"]["critical"] == 1
    assert app.attributes["severity_counts"]["low"] == 0


# ── Reachability hook ──────────────────────────────────────────────────────


def test_reachable_flag_set_when_attack_path_data_present():
    from agent_bom.graph.container import AttackPath

    graph = UnifiedGraph(scan_id="s1")
    graph.add_node(UnifiedNode(id="vuln:CVE-R", entity_type=EntityType.VULNERABILITY, label="CVE-R", severity="high"))
    graph.attack_paths.append(
        AttackPath(
            source="agent:a",
            target="vuln:CVE-R",
            hops=["agent:a", "server:s", "vuln:CVE-R"],
            edges=["uses", "vulnerable_to"],
            composite_risk=9.0,
            summary="chain",
        )
    )
    report = {"findings": [_finding(source="SBOM", location="svc/api/go.mod", name="p", cve_id="CVE-R")]}
    result = apply_aspm_overlay(graph, report, NOW)
    assert result["reachable"] == 1
    assert _app_node(graph, "svc/api").attributes["reachable_finding_count"] == 1


def test_exposed_node_marks_finding_reachable():
    graph = UnifiedGraph(scan_id="s1")
    graph.add_node(
        UnifiedNode(
            id="vuln:CVE-E",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-E",
            severity="high",
            attributes={"internet_exposed": True},
        )
    )
    report = {"findings": [_finding(source="SBOM", location="svc/api/go.mod", name="p", cve_id="CVE-E")]}
    result = apply_aspm_overlay(graph, report, NOW)
    assert result["reachable"] == 1


def test_no_reachability_signal_defaults_unknown():
    graph = UnifiedGraph(scan_id="s1")
    report = {"findings": [_finding(source="SAST", location="svc/api/main.py", name="main.py", title="bug")]}
    result = apply_aspm_overlay(graph, report, NOW)
    assert result["reachable"] == 0
    assert _app_node(graph, "svc/api").attributes["reachable_finding_count"] == 0


def test_finding_reachability_hint_marks_reachable():
    graph = UnifiedGraph(scan_id="s1")
    report = {"findings": [_finding(source="SBOM", location="svc/api/go.mod", name="p", cve_id="CVE-H", reachability="reachable")]}
    result = apply_aspm_overlay(graph, report, NOW)
    assert result["reachable"] == 1


# ── Owner derivation ───────────────────────────────────────────────────────


def test_owner_from_codeowners_longest_prefix_match():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "codeowners": {"services": "@platform", "services/billing": "@payments"},
        "findings": [
            _finding(source="SBOM", location="services/billing/go.mod", name="p", cve_id="CVE-1"),
            _finding(source="SBOM", location="services/search/go.mod", name="q", cve_id="CVE-2"),
        ],
    }
    apply_aspm_overlay(graph, report, NOW)
    assert _app_node(graph, "services/billing").attributes["owner"] == "@payments"
    assert _app_node(graph, "services/search").attributes["owner"] == "@platform"


def test_owner_from_codeowners_list_form():
    graph = UnifiedGraph(scan_id="s1")
    report = {
        "codeowners": [{"path": "svc/api", "owners": ["@a", "@b"]}],
        "findings": [_finding(source="SBOM", location="svc/api/go.mod", name="p", cve_id="CVE-1")],
    }
    apply_aspm_overlay(graph, report, NOW)
    assert _app_node(graph, "svc/api").attributes["owner"] == "@a, @b"


# ── Determinism + idempotency ──────────────────────────────────────────────


def _report():
    return {
        "codeowners": {"services/billing": "@payments"},
        "findings": [
            _finding(source="SBOM", location="services/billing/go.mod", name="a", identifier="pkg:a@1", cve_id="CVE-1", severity="high"),
            _finding(
                source="CONTAINER",
                location="services/billing/go.mod",
                name="a",
                identifier="pkg:a@1",
                cve_id="CVE-1",
                severity="critical",
            ),
            _finding(source="SAST", location="services/billing/main.go", name="main.go", title="xss", severity="medium"),
            _finding(source="SECRET_SCAN", location="services/checkout/config.yaml", name="cfg", title="key", severity="high"),
        ],
    }


def test_applying_twice_is_idempotent():
    graph = UnifiedGraph(scan_id="s1")
    graph.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))

    first = apply_aspm_overlay(graph, _report(), NOW)
    snapshot = copy.deepcopy(graph.to_dict())
    second = apply_aspm_overlay(graph, _report(), NOW)

    assert graph.to_dict() == snapshot
    # Second application creates no new application nodes.
    assert second["applications"] == 0
    assert first["correlated_findings"] == second["correlated_findings"]


def test_deterministic_across_input_order():
    report_a = _report()
    report_b = _report()
    report_b["findings"].reverse()

    g1 = UnifiedGraph(scan_id="s1")
    g1.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1"))
    g2 = UnifiedGraph(scan_id="s1")
    g2.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1"))

    apply_aspm_overlay(g1, report_a, NOW)
    apply_aspm_overlay(g2, report_b, NOW)

    def app_attrs(g: UnifiedGraph) -> dict:
        return {nid: n.attributes for nid, n in sorted(g.nodes.items()) if nid.startswith("application:")}

    assert app_attrs(g1) == app_attrs(g2)


def test_belongs_to_edges_deduped_across_applies():
    graph = UnifiedGraph(scan_id="s1")
    graph.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1"))
    report = {"findings": [_finding(source="SBOM", location="svc/api/go.mod", name="p", cve_id="CVE-1")]}
    apply_aspm_overlay(graph, report, NOW)
    apply_aspm_overlay(graph, report, NOW)
    belongs = [e for e in graph.edges if e.relationship == RelationshipType.BELONGS_TO]
    assert len(belongs) == 1


# ── Builder integration ────────────────────────────────────────────────────


def test_builder_invokes_aspm_overlay():
    from agent_bom.graph.builder import build_unified_graph_from_report

    report = {
        "scan_id": "build-1",
        "agents": [],
        "findings": [
            _finding(source="SBOM", location="services/billing/go.mod", name="p", cve_id="CVE-1", severity="high"),
        ],
    }
    graph = build_unified_graph_from_report(report)
    assert graph.get_node("application:services/billing") is not None


def test_builder_no_findings_emits_no_application_nodes():
    from agent_bom.graph.builder import build_unified_graph_from_report

    graph = build_unified_graph_from_report({"scan_id": "build-2", "agents": []})
    assert not [n for n in graph.nodes if n.startswith("application:")]


def test_belongs_to_edge_dedup_helper_path():
    """A duplicate BELONGS_TO edge from add_edge is merged, not appended."""
    graph = UnifiedGraph(scan_id="s1")
    graph.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1"))
    graph.add_node(UnifiedNode(id="application:svc", entity_type=EntityType.APPLICATION, label="svc"))
    edge = UnifiedEdge(source="vuln:CVE-1", target="application:svc", relationship=RelationshipType.BELONGS_TO)
    graph.add_edge(edge)
    graph.add_edge(edge)
    assert len([e for e in graph.edges if e.relationship == RelationshipType.BELONGS_TO]) == 1
