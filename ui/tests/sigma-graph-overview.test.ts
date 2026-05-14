import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import type { UnifiedGraphData, UnifiedNode, UnifiedEdge } from "@/lib/graph-schema";
import { EntityType, NodeStatus, RelationshipType } from "@/lib/graph-schema";
import {
  buildSigmaGraphOverviewModel,
  buildSigmaGraphOverviewModelFromUnifiedGraph,
} from "@/lib/sigma-graph-overview";

function node(id: string, data: Partial<LineageNodeData> = {}): Node<LineageNodeData> {
  return {
    id,
    position: { x: data.nodeType === "agent" ? 0 : 100, y: data.nodeType === "agent" ? 0 : 80 },
    data: {
      label: id,
      nodeType: "package",
      ...data,
    },
  };
}

function edge(id: string, source: string, target: string, relationship = "depends_on"): Edge {
  return {
    id,
    source,
    target,
    data: { relationship },
    style: { strokeWidth: 2 },
  };
}

function unifiedNode(
  id: string,
  entityType: EntityType,
  overrides: Partial<UnifiedNode> = {},
): UnifiedNode {
  return {
    id,
    entity_type: entityType,
    label: id,
    category_uid: 5,
    class_uid: 4001,
    type_uid: 0,
    status: NodeStatus.ACTIVE,
    risk_score: 0,
    severity: "unknown",
    severity_id: 0,
    first_seen: "2026-05-14T00:00:00Z",
    last_seen: "2026-05-14T00:00:00Z",
    attributes: {},
    compliance_tags: [],
    data_sources: ["fixture"],
    dimensions: {},
    ...overrides,
  };
}

function unifiedEdge(
  id: string,
  source: string,
  target: string,
  relationship: RelationshipType,
  overrides: Partial<UnifiedEdge> = {},
): UnifiedEdge {
  return {
    id,
    source,
    target,
    relationship,
    direction: "directed",
    weight: 1,
    traversable: true,
    first_seen: "2026-05-14T00:00:00Z",
    last_seen: "2026-05-14T00:00:00Z",
    evidence: {},
    activity_id: 0,
    ...overrides,
  };
}

function unifiedGraph(
  nodes: UnifiedNode[],
  edges: UnifiedEdge[],
): UnifiedGraphData {
  return {
    scan_id: "scan-fixture",
    tenant_id: "tenant-fixture",
    created_at: "2026-05-14T00:00:00Z",
    nodes,
    edges,
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: {},
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
  };
}

describe("sigma graph overview", () => {
  it("adapts lineage graph data into a graphology model for Sigma", () => {
    const model = buildSigmaGraphOverviewModel(
      [
        node("agent-a", { nodeType: "agent", label: "analyst-agent" }),
        node("pkg-a", { nodeType: "package", label: "requests", riskScore: 82 }),
        node("cve-a", {
          nodeType: "vulnerability",
          label: "CVE-2026-0001",
          severity: "critical",
          highlighted: true,
        }),
      ],
      [
        edge("agent-pkg", "agent-a", "pkg-a", "uses"),
        edge("pkg-cve", "pkg-a", "cve-a", "vulnerable_to"),
        edge("missing", "pkg-a", "does-not-exist", "depends_on"),
      ],
    );

    expect(model.graph.order).toBe(3);
    expect(model.graph.size).toBe(2);
    expect(model.graph.getNodeAttribute("agent-a", "forceLabel")).toBe(true);
    expect(model.graph.getNodeAttribute("cve-a", "highlighted")).toBe(true);
    expect(model.graph.getNodeAttribute("cve-a", "size")).toBeGreaterThan(
      model.graph.getNodeAttribute("pkg-a", "size"),
    );
    expect(model.graph.getEdgeAttribute("pkg-cve", "relationship")).toBe("vulnerable_to");
    expect(model.graph.hasEdge("missing")).toBe(false);
    expect(model.summary.criticalFindings).toBe(1);
  });

  it("preserves dimmed state and edge highlighting for focused overview data", () => {
    const model = buildSigmaGraphOverviewModel(
      [
        node("agent-a", { nodeType: "agent", highlighted: true }),
        node("pkg-a", { nodeType: "package" }),
        node("pkg-b", { nodeType: "package", dimmed: true }),
      ],
      [edge("focused", "agent-a", "pkg-a", "uses"), edge("dimmed", "pkg-a", "pkg-b", "depends_on")],
    );

    expect(model.graph.getNodeAttribute("pkg-b", "hidden")).toBe(true);
    expect(model.graph.getEdgeAttribute("focused", "highlighted")).toBe(true);
    expect(model.graph.getEdgeAttribute("dimmed", "hidden")).toBe(true);
  });

  it("adapts canonical unified graph data before building the Sigma model", () => {
    const model = buildSigmaGraphOverviewModelFromUnifiedGraph(
      unifiedGraph(
        [
          unifiedNode("agent-a", EntityType.AGENT, { label: "agent-a" }),
          unifiedNode("server-a", EntityType.SERVER, { label: "mcp-server" }),
          unifiedNode("pkg-a", EntityType.PACKAGE, { label: "requests", risk_score: 41 }),
          unifiedNode("cve-a", EntityType.VULNERABILITY, {
            label: "CVE-2026-0001",
            risk_score: 95,
            severity: "critical",
            severity_id: 5,
          }),
        ],
        [
          unifiedEdge("agent-server", "agent-a", "server-a", RelationshipType.USES),
          unifiedEdge("server-pkg", "server-a", "pkg-a", RelationshipType.DEPENDS_ON),
          unifiedEdge("pkg-cve", "pkg-a", "cve-a", RelationshipType.VULNERABLE_TO, {
            weight: 3,
          }),
          unifiedEdge("dangling", "pkg-a", "missing-node", RelationshipType.DEPENDS_ON),
        ],
      ),
    );

    expect(model.graph.order).toBe(4);
    expect(model.graph.size).toBe(3);
    expect(model.graph.getNodeAttribute("agent-a", "nodeType")).toBe("agent");
    expect(model.graph.getNodeAttribute("cve-a", "severity")).toBe("critical");
    expect(model.graph.getEdgeAttribute("pkg-cve", "relationship")).toBe("vulnerable_to");
    expect(model.graph.hasEdge("dangling")).toBe(false);
    expect(model.summary.criticalFindings).toBe(1);
  });
});
