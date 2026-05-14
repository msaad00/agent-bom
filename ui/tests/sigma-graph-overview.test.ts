import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import { buildSigmaGraphOverviewModel } from "@/lib/sigma-graph-overview";

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
});
