import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import {
  buildLargeGraphOverviewModel,
  LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
  LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
  shouldUseLargeGraphOverview,
  summarizeLargeGraphOverview,
} from "@/lib/large-graph-overview";

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

describe("large graph overview", () => {
  it("only promotes broad, unfocused graph views to the canvas renderer", () => {
    expect(
      shouldUseLargeGraphOverview({
        nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD,
        edgeCount: 20,
      }),
    ).toBe(true);
    expect(
      shouldUseLargeGraphOverview({
        nodeCount: 24,
        edgeCount: LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD,
      }),
    ).toBe(true);
    expect(
      shouldUseLargeGraphOverview({
        nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD + 10,
        edgeCount: 20,
        selectedAttackPath: true,
      }),
    ).toBe(false);
    expect(
      shouldUseLargeGraphOverview({
        nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD + 10,
        edgeCount: 20,
        reachabilityActive: true,
      }),
    ).toBe(false);
    expect(
      shouldUseLargeGraphOverview({
        nodeCount: LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD + 10,
        edgeCount: 20,
        captureMode: true,
      }),
    ).toBe(false);
  });

  it("converts lineage nodes and relationship edges into drawable model attributes", () => {
    const model = buildLargeGraphOverviewModel(
      [
        node("agent-a", { nodeType: "agent", label: "analyst-agent" }),
        node("pkg-a", { nodeType: "package", label: "requests", riskScore: 82 }),
        node("cve-a", { nodeType: "vulnerability", label: "CVE-2026-0001", severity: "critical" }),
      ],
      [
        edge("agent-pkg", "agent-a", "pkg-a", "uses"),
        edge("pkg-cve", "pkg-a", "cve-a", "vulnerable_to"),
        edge("missing", "pkg-a", "does-not-exist", "depends_on"),
      ],
    );

    expect(model.nodes).toHaveLength(3);
    expect(model.edges).toHaveLength(2);
    expect(model.nodeById.get("agent-a")?.forceLabel).toBe(true);
    expect(model.nodeById.get("cve-a")?.size).toBeGreaterThan(
      model.nodeById.get("pkg-a")?.size ?? 0,
    );
    expect(model.edges.find((entry) => entry.id === "pkg-cve")?.relationship).toBe("vulnerable_to");
    expect(model.edges.some((entry) => entry.id === "missing")).toBe(false);
  });

  it("summarizes findings and dominant relationship families for the graph header", () => {
    const nodes = [
      node("agent-a", { nodeType: "agent" }),
      node("cred-a", { nodeType: "credential" }),
      node("tool-a", { nodeType: "tool" }),
      node("cve-a", { nodeType: "vulnerability", severity: "critical" }),
      node("misconfig-a", { nodeType: "misconfiguration", severity: "high" }),
    ];
    const edges = [
      edge("e1", "agent-a", "cred-a", "exposes_cred"),
      edge("e2", "cred-a", "tool-a", "reaches_tool"),
      edge("e3", "tool-a", "cve-a", "vulnerable_to"),
      edge("e4", "misconfig-a", "tool-a", "vulnerable_to"),
    ];

    expect(summarizeLargeGraphOverview(nodes, edges)).toMatchObject({
      nodes: 5,
      edges: 4,
      findings: 2,
      criticalFindings: 1,
      credentials: 1,
      tools: 1,
      topRelationships: [
        { relationship: "vulnerable_to", count: 2 },
        { relationship: "exposes_cred", count: 1 },
        { relationship: "reaches_tool", count: 1 },
      ],
    });
  });
});
