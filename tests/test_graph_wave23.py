"""Wave 2-3 tests — pagination, RBAC tenant isolation, saved presets,
graph delta webhooks, OCSF neighbor enrichment.
"""

from __future__ import annotations

import asyncio
import sqlite3
import warnings

import pytest

from agent_bom.db.graph_store import _init_db, load_graph, save_graph
from agent_bom.graph import (
    EntityType,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.builder import build_unified_graph_from_report


def _test_graph(scan_id="s1", tenant_id=""):
    g = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    for i in range(20):
        g.add_node(UnifiedNode(id=f"agent:{i}", entity_type=EntityType.AGENT, label=f"agent-{i}"))
    g.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))
    for i in range(20):
        g.add_edge(UnifiedEdge(source=f"agent:{i}", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO))
    return g


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    yield conn
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# Wave 2A: Pagination
# ═══════════════════════════════════════════════════════════════════════════


class TestPagination:
    def test_paginate_helper(self):
        from agent_bom.api.routes.graph import _paginate

        items = list(range(100))
        page, meta = _paginate(items, offset=10, limit=25)
        assert len(page) == 25
        assert page[0] == 10
        assert meta["total"] == 100
        assert meta["offset"] == 10
        assert meta["limit"] == 25
        assert meta["has_more"] is True

    def test_paginate_last_page(self):
        from agent_bom.api.routes.graph import _paginate

        items = list(range(30))
        page, meta = _paginate(items, offset=20, limit=25)
        assert len(page) == 10
        assert meta["has_more"] is False

    def test_paginate_empty(self):
        from agent_bom.api.routes.graph import _paginate

        page, meta = _paginate([], offset=0, limit=10)
        assert len(page) == 0
        assert meta["total"] == 0
        assert meta["has_more"] is False


# ═══════════════════════════════════════════════════════════════════════════
# Wave 2B: RBAC tenant isolation
# ═══════════════════════════════════════════════════════════════════════════


class TestTenantIsolation:
    def test_different_tenants_isolated(self, db):
        g1 = UnifiedGraph(scan_id="s1", tenant_id="tenant-a")
        g1.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
        save_graph(db, g1)

        g2 = UnifiedGraph(scan_id="s1", tenant_id="tenant-b")
        g2.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="b"))
        save_graph(db, g2)

        loaded_a = load_graph(db, scan_id="s1", tenant_id="tenant-a")
        loaded_b = load_graph(db, scan_id="s1", tenant_id="tenant-b")

        assert "agent:a" in loaded_a.nodes
        assert "agent:b" not in loaded_a.nodes
        assert "agent:b" in loaded_b.nodes
        assert "agent:a" not in loaded_b.nodes

    def test_default_tenant(self, db):
        g = UnifiedGraph(scan_id="s1")
        g.add_node(UnifiedNode(id="agent:x", entity_type=EntityType.AGENT, label="x"))
        save_graph(db, g)

        loaded = load_graph(db, scan_id="s1", tenant_id="")
        assert "agent:x" in loaded.nodes


# ═══════════════════════════════════════════════════════════════════════════
# Wave 3A: Graph delta webhooks
# ═══════════════════════════════════════════════════════════════════════════


class TestDeltaAlerts:
    def test_new_critical_vuln_alert(self):
        from agent_bom.graph.webhooks import compute_delta_alerts

        old = UnifiedGraph(scan_id="s1")
        old.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))

        new = UnifiedGraph(scan_id="s2")
        new.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
        new.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))

        alerts = compute_delta_alerts(old, new)
        vuln_alerts = [a for a in alerts if a["type"] == "new_vulnerability"]
        assert len(vuln_alerts) == 1
        assert vuln_alerts[0]["severity"] == "critical"
        assert "CVE-1" in vuln_alerts[0]["title"]

    def test_no_alert_for_existing_vuln(self):
        from agent_bom.graph.webhooks import compute_delta_alerts

        old = UnifiedGraph(scan_id="s1")
        old.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))

        new = UnifiedGraph(scan_id="s2")
        new.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))

        alerts = compute_delta_alerts(old, new)
        vuln_alerts = [a for a in alerts if a["type"] == "new_vulnerability"]
        assert len(vuln_alerts) == 0

    def test_no_alert_for_low_severity(self):
        from agent_bom.graph.webhooks import compute_delta_alerts

        old = UnifiedGraph(scan_id="s1")
        new = UnifiedGraph(scan_id="s2")
        new.add_node(UnifiedNode(id="vuln:CVE-2", entity_type=EntityType.VULNERABILITY, label="CVE-2", severity="low"))

        alerts = compute_delta_alerts(old, new)
        vuln_alerts = [a for a in alerts if a["type"] == "new_vulnerability"]
        assert len(vuln_alerts) == 0

    def test_agent_removed_alert(self):
        from agent_bom.graph.webhooks import compute_delta_alerts

        old = UnifiedGraph(scan_id="s1")
        old.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
        old.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="b"))

        new = UnifiedGraph(scan_id="s2")
        new.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))

        alerts = compute_delta_alerts(old, new)
        removed = [a for a in alerts if a["type"] == "agent_removed"]
        assert len(removed) == 1
        assert "agent:b" in removed[0]["node_ids"]

    def test_first_scan_no_old_graph(self):
        from agent_bom.graph.webhooks import compute_delta_alerts

        new = UnifiedGraph(scan_id="s1")
        new.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="high"))

        alerts = compute_delta_alerts(None, new)
        assert len(alerts) >= 1

    def test_format_alerts_for_siem(self):
        from agent_bom.graph.webhooks import compute_delta_alerts, format_alerts_for_siem

        new = UnifiedGraph(scan_id="s1")
        new.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))

        alerts = compute_delta_alerts(None, new)
        ocsf_events = format_alerts_for_siem(alerts, "0.75.14")
        assert len(ocsf_events) >= 1
        assert ocsf_events[0]["class_uid"] == 2004
        assert ocsf_events[0]["severity_id"] == 5
        assert ocsf_events[0]["metadata"]["product"]["version"] == "0.75.14"

    def test_delta_alerts_include_dispatch_fields(self):
        from agent_bom.graph.webhooks import compute_delta_alerts

        new = UnifiedGraph(scan_id="s1")
        new.add_node(
            UnifiedNode(
                id="vuln:CVE-1",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-1",
                severity="critical",
                risk_score=9.5,
                attributes={"cvss_score": 9.8},
            )
        )

        alerts = compute_delta_alerts(None, new)
        assert alerts
        first = alerts[0]
        assert first["detector"] == "graph_new_vulnerability"
        assert first["message"] == first["title"]
        assert first["details"]["risk_score"] == 9.5
        assert first["details"]["cvss_score"] == 9.8

    def test_dispatch_delta_alerts_without_outbound_channels(self, monkeypatch):
        from agent_bom.graph.webhooks import compute_delta_alerts, dispatch_delta_alerts

        monkeypatch.delenv("AGENT_BOM_GRAPH_DELTA_WEBHOOK", raising=False)
        monkeypatch.delenv("AGENT_BOM_ALERT_WEBHOOK", raising=False)
        monkeypatch.delenv("AGENT_BOM_GRAPH_DELTA_SLACK_WEBHOOK", raising=False)
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

        new = UnifiedGraph(scan_id="s1")
        new.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))

        alerts = compute_delta_alerts(None, new)
        result = dispatch_delta_alerts(alerts, product_version="0.76.0")
        assert result["configured"] is False
        assert result["attempted"] == len(alerts)
        assert result["delivered"] == 0
        assert result["queued"] == 0
        assert result["ocsf_event_count"] == len(alerts)

    def test_dispatch_delta_alerts_to_configured_channels(self, monkeypatch):
        import agent_bom.alerts.dispatcher as dispatcher_mod
        from agent_bom.graph.webhooks import compute_delta_alerts, dispatch_delta_alerts

        class FakeDispatcher:
            last = None

            def __init__(self):
                self.webhooks = []
                self.slacks = []
                self.dispatched = []
                FakeDispatcher.last = self

            def add_webhook(self, url, headers=None):
                self.webhooks.append((url, headers))

            def add_slack(self, webhook_url):
                self.slacks.append(webhook_url)

            async def dispatch(self, alert):
                self.dispatched.append(alert)
                return 1 + len(self.webhooks) + len(self.slacks)

        monkeypatch.setattr(dispatcher_mod, "AlertDispatcher", FakeDispatcher)
        monkeypatch.setenv("AGENT_BOM_GRAPH_DELTA_WEBHOOK", "https://hooks.example.test/graph")
        monkeypatch.setenv("AGENT_BOM_GRAPH_DELTA_SLACK_WEBHOOK", "https://hooks.slack.test/services/example")

        new = UnifiedGraph(scan_id="s1")
        new.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))

        alerts = compute_delta_alerts(None, new)
        result = dispatch_delta_alerts(alerts, product_version="0.76.0")

        assert result["configured"] is True
        assert result["outbound_channels"] == 2
        assert result["delivered"] == len(alerts) * 2
        assert FakeDispatcher.last is not None
        assert FakeDispatcher.last.webhooks == [("https://hooks.example.test/graph", None)]
        assert FakeDispatcher.last.slacks == ["https://hooks.slack.test/services/example"]
        assert FakeDispatcher.last.dispatched
        assert FakeDispatcher.last.dispatched[0]["type"] == "new_vulnerability"

    def test_dispatch_delta_alerts_in_active_loop_is_queued_not_overcounted(self, monkeypatch):
        import agent_bom.alerts.dispatcher as dispatcher_mod
        from agent_bom.graph.webhooks import compute_delta_alerts, dispatch_delta_alerts

        class FakeDispatcher:
            last = None

            def __init__(self):
                self.webhooks = []
                self.slacks = []
                self.dispatched = []
                FakeDispatcher.last = self

            def add_webhook(self, url, headers=None):
                self.webhooks.append((url, headers))

            def add_slack(self, webhook_url):
                self.slacks.append(webhook_url)

            async def dispatch(self, alert):
                self.dispatched.append(alert)
                return 1 + len(self.webhooks) + len(self.slacks)

            def dispatch_sync(self, alert):
                asyncio.get_running_loop().create_task(self.dispatch(alert))

        monkeypatch.setattr(dispatcher_mod, "AlertDispatcher", FakeDispatcher)
        monkeypatch.setenv("AGENT_BOM_GRAPH_DELTA_WEBHOOK", "https://hooks.example.test/graph")
        monkeypatch.setenv("AGENT_BOM_GRAPH_DELTA_SLACK_WEBHOOK", "https://hooks.slack.test/services/example")

        new = UnifiedGraph(scan_id="s1")
        new.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))
        alerts = compute_delta_alerts(None, new)

        async def _run():
            result = dispatch_delta_alerts(alerts, product_version="0.76.0")
            await asyncio.sleep(0)
            return result

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = asyncio.run(_run())

        assert result["configured"] is True
        assert result["delivered"] == 0
        assert result["queued"] == len(alerts) * 2
        assert FakeDispatcher.last is not None
        assert FakeDispatcher.last.dispatched
        assert not any("was never awaited" in str(w.message) for w in caught)


# ═══════════════════════════════════════════════════════════════════════════
# Wave 3B: OCSF neighbor enrichment
# ═══════════════════════════════════════════════════════════════════════════


class TestComplianceAggregation:
    def test_compliance_tags_aggregated_by_framework(self):
        g = UnifiedGraph(scan_id="compliance-test")
        g.add_node(
            UnifiedNode(
                id="vuln:CVE-1",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-1",
                severity="critical",
                compliance_tags=["OWASP-A06", "MITRE-T1059", "NIST-AI-RMF-MAP-1.1"],
            )
        )
        g.add_node(
            UnifiedNode(
                id="vuln:CVE-2",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-2",
                severity="high",
                compliance_tags=["OWASP-A01", "CIS-1.1"],
            )
        )
        g.add_node(
            UnifiedNode(
                id="misconfig:cis:2.1",
                entity_type=EntityType.MISCONFIGURATION,
                label="MFA not enabled",
                severity="high",
                compliance_tags=["CIS-2.1", "NIST-AC-2"],
            )
        )

        # Verify tags exist on nodes
        assert len(g.nodes["vuln:CVE-1"].compliance_tags) == 3

        # Test compliance_view filter
        owasp_view = g.compliance_view(framework="OWASP")
        owasp_nodes = list(owasp_view.nodes.values())
        assert len(owasp_nodes) == 2  # CVE-1 and CVE-2 both have OWASP tags

        cis_view = g.compliance_view(framework="CIS")
        cis_nodes = list(cis_view.nodes.values())
        assert len(cis_nodes) == 2  # CVE-2 and misconfig both have CIS tags

    def test_compliance_view_all_frameworks(self):
        g = UnifiedGraph()
        g.add_node(UnifiedNode(id="v1", entity_type=EntityType.VULNERABILITY, label="v1", compliance_tags=["OWASP-A01"]))
        g.add_node(UnifiedNode(id="v2", entity_type=EntityType.VULNERABILITY, label="v2", compliance_tags=[]))
        g.add_node(UnifiedNode(id="a1", entity_type=EntityType.AGENT, label="a1"))

        all_compliance = g.compliance_view()
        # Only v1 has tags
        assert len(all_compliance.nodes) == 1
        assert "v1" in all_compliance.nodes


class TestOCSFNeighborEnrichment:
    def test_ocsf_event_includes_graph_context(self):
        report = {
            "scan_id": "enrich-test",
            "agents": [
                {
                    "name": "claude",
                    "type": "claude-desktop",
                    "status": "configured",
                    "mcp_servers": [
                        {
                            "name": "srv",
                            "command": "npx",
                            "transport": "stdio",
                            "surface": "mcp-server",
                            "packages": [
                                {
                                    "name": "express",
                                    "version": "4.18.0",
                                    "ecosystem": "npm",
                                    "vulnerabilities": [{"id": "CVE-1", "severity": "high"}],
                                },
                            ],
                            "tools": [],
                            "credential_env_vars": ["API_KEY"],
                        },
                    ],
                },
            ],
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-1",
                    "severity": "high",
                    "package_name": "express",
                    "package_version": "4.18.0",
                    "ecosystem": "npm",
                    "affected_agents": ["claude"],
                    "affected_servers": ["srv"],
                },
            ],
        }

        g = build_unified_graph_from_report(report)
        events = g.to_ocsf_events("0.75.14", enrich_neighbors=True)

        assert len(events) == 1
        ctx = events[0].get("graph_context")
        assert ctx is not None
        assert ctx["blast_radius"] >= 0
        assert isinstance(ctx["affected_packages"], list)

    def test_ocsf_event_without_enrichment(self):
        g = UnifiedGraph()
        g.add_node(UnifiedNode(id="vuln:X", entity_type=EntityType.VULNERABILITY, label="X", severity="high"))

        events = g.to_ocsf_events(enrich_neighbors=False)
        assert len(events) == 1
        assert "graph_context" not in events[0]
