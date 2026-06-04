import { describe, expect, it } from "vitest";

import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createFocusedGraphFilters } from "@/components/lineage-filter";
import {
  EntityType,
  RelationshipType,
  type UnifiedEdge,
  type UnifiedGraphData,
  type UnifiedNode,
} from "@/lib/graph-schema";

const createdAt = "2026-06-01T00:00:00Z";

function node(id: string, entityType: EntityType, label: string, severity = "none"): UnifiedNode {
  return {
    id,
    entity_type: entityType,
    label,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: severity === "critical" ? 9.4 : 0,
    severity,
    severity_id: severity === "critical" ? 5 : 0,
    first_seen: createdAt,
    last_seen: createdAt,
    attributes: {},
    compliance_tags: [],
    data_sources: ["test"],
    dimensions: {},
  };
}

function edge(source: string, target: string, relationship: RelationshipType): UnifiedEdge {
  return {
    id: `${source}->${relationship}->${target}`,
    source,
    target,
    relationship,
    direction: "directed",
    weight: 1,
    traversable: true,
    first_seen: createdAt,
    last_seen: createdAt,
    evidence: {},
    activity_id: 1,
  };
}

describe("buildUnifiedFlowGraph", () => {
  it("keeps agent and finding endpoints in focused relevant-path windows", () => {
    const graph: UnifiedGraphData = {
      scan_id: "scan-path",
      tenant_id: "default",
      created_at: createdAt,
      nodes: [
        node("agent:desktop", EntityType.AGENT, "Desktop Agent", "high"),
        node("server:filesystem", EntityType.SERVER, "filesystem MCP", "high"),
        node("pkg:filesystem", EntityType.PACKAGE, "filesystem-package", "high"),
        node("cve:filesystem", EntityType.VULNERABILITY, "CVE-2026-1001", "critical"),
      ],
      edges: [
        edge("agent:desktop", "server:filesystem", RelationshipType.USES),
        edge("server:filesystem", "pkg:filesystem", RelationshipType.DEPENDS_ON),
        edge("pkg:filesystem", "cve:filesystem", RelationshipType.VULNERABLE_TO),
      ],
      attack_paths: [
        {
          source: "agent:desktop",
          target: "cve:filesystem",
          hops: ["agent:desktop", "server:filesystem", "pkg:filesystem", "cve:filesystem"],
          edges: [],
          composite_risk: 9.4,
          summary: "Desktop Agent can reach a critical package vulnerability.",
          credential_exposure: [],
          tool_exposure: [],
          vuln_ids: ["CVE-2026-1001"],
        },
      ],
      interaction_risks: [],
      stats: {
        total_nodes: 4,
        total_edges: 3,
        node_types: {},
        severity_counts: {},
        relationship_types: {},
        attack_path_count: 1,
        interaction_risk_count: 0,
        max_attack_path_risk: 9.4,
        highest_interaction_risk: 0,
      },
    };

    const flow = buildUnifiedFlowGraph(graph, createFocusedGraphFilters("Desktop Agent"));
    expect(flow.nodes.map((entry) => entry.id).sort()).toEqual([
      "agent:desktop",
      "cve:filesystem",
      "pkg:filesystem",
      "server:filesystem",
    ]);
    expect(flow.summary).toMatchObject({ agents: 1, findings: 1, critical: 1 });
    expect(flow.edges.find((entry) => entry.id.includes("vulnerable_to"))?.data).toMatchObject({
      relationship: "vulnerable_to",
      relationshipLabel: "Has CVE",
      evidenceMode: "static",
    });
  });
});
