import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import {
  aggregateSiblings,
  CLUSTER_ID_PREFIX,
  EXPANDED_AGGREGATION_THRESHOLD,
  FOCUSED_AGGREGATION_THRESHOLD,
  isClusterPillNode,
} from "@/lib/sibling-aggregator";
import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";

function makeNode(id: string, nodeType: LineageNodeType, label = id): Node<LineageNodeData> {
  return {
    id,
    type: `${nodeType}Node`,
    position: { x: 0, y: 0 },
    data: { label, nodeType },
  };
}

function makeEdge(source: string, target: string, relationship = "uses"): Edge {
  return {
    id: `${source}=>${target}=>${relationship}`,
    source,
    target,
    data: { relationship },
  };
}

describe("aggregateSiblings", () => {
  it("collapses fan-outs at or above threshold into a single pill", () => {
    const nodes: Node<LineageNodeData>[] = [
      makeNode("server-a", "server"),
      ...Array.from({ length: 7 }, (_, i) => makeNode(`pkg-${i}`, "package", `pkg-${i}`)),
    ];
    const edges = nodes.slice(1).map((child) => makeEdge("server-a", child.id, "uses"));

    const result = aggregateSiblings(nodes, edges, { thresholdN: 5 });

    // Original nodes minus the 7 packages, plus 1 cluster pill.
    expect(result.nodes.length).toBe(1 + 1);
    const pill = result.nodes.find((n) => n.id.startsWith(CLUSTER_ID_PREFIX));
    expect(pill).toBeDefined();
    expect(isClusterPillNode(pill!)).toBe(true);
    expect(pill!.data.label).toBe("+7 packages");
    expect(result.clusters.size).toBe(1);
    // Only the parent→pill edge remains.
    expect(result.edges.length).toBe(1);
    expect(result.edges[0]!.target).toBe(pill!.id);
  });

  it("leaves fan-outs below threshold untouched", () => {
    const nodes: Node<LineageNodeData>[] = [
      makeNode("server-a", "server"),
      ...Array.from({ length: 4 }, (_, i) => makeNode(`pkg-${i}`, "package")),
    ];
    const edges = nodes.slice(1).map((child) => makeEdge("server-a", child.id, "uses"));

    const result = aggregateSiblings(nodes, edges, { thresholdN: 5 });

    expect(result.nodes).toHaveLength(5);
    expect(result.edges).toHaveLength(4);
    expect(result.clusters.size).toBe(0);
  });

  it("does not collapse children that have multiple parents", () => {
    const nodes: Node<LineageNodeData>[] = [
      makeNode("server-a", "server"),
      makeNode("server-b", "server"),
      ...Array.from({ length: 6 }, (_, i) => makeNode(`pkg-${i}`, "package")),
    ];
    // pkg-0 is shared between server-a and server-b → not collapsible.
    const edges: Edge[] = [
      makeEdge("server-a", "pkg-0", "uses"),
      makeEdge("server-b", "pkg-0", "uses"),
      ...nodes.slice(2).slice(1).map((child) => makeEdge("server-a", child.id, "uses")),
    ];

    const result = aggregateSiblings(nodes, edges, { thresholdN: 5 });
    // 5 single-parent siblings → still below the threshold of 5? Actually
    // exactly five collapsible → collapses. We assert pkg-0 remains.
    const remaining = result.nodes.map((n) => n.id);
    expect(remaining).toContain("pkg-0");
  });

  it("keeps siblings expanded when their cluster id is in expandedClusterIds", () => {
    const nodes: Node<LineageNodeData>[] = [
      makeNode("server-a", "server"),
      ...Array.from({ length: 6 }, (_, i) => makeNode(`pkg-${i}`, "package")),
    ];
    const edges = nodes.slice(1).map((child) => makeEdge("server-a", child.id, "uses"));

    const initial = aggregateSiblings(nodes, edges, { thresholdN: 5 });
    const pillId = [...initial.clusters.keys()][0]!;

    const expanded = aggregateSiblings(nodes, edges, {
      thresholdN: 5,
      expandedClusterIds: new Set([pillId]),
    });

    expect(expanded.clusters.size).toBe(0);
    expect(expanded.nodes).toHaveLength(7);
    expect(expanded.edges).toHaveLength(6);
  });

  it("uses different thresholds for focused vs expanded presets", () => {
    expect(FOCUSED_AGGREGATION_THRESHOLD).toBeLessThan(EXPANDED_AGGREGATION_THRESHOLD);
  });

  it("groups by edge kind so different relationships do not merge", () => {
    const nodes: Node<LineageNodeData>[] = [
      makeNode("agent-a", "agent"),
      ...Array.from({ length: 6 }, (_, i) => makeNode(`tool-${i}`, "tool")),
      ...Array.from({ length: 6 }, (_, i) => makeNode(`cred-${i}`, "credential")),
    ];
    const edges: Edge[] = [
      ...Array.from({ length: 6 }, (_, i) =>
        makeEdge("agent-a", `tool-${i}`, "provides_tool"),
      ),
      ...Array.from({ length: 6 }, (_, i) =>
        makeEdge("agent-a", `cred-${i}`, "exposes_cred"),
      ),
    ];

    const result = aggregateSiblings(nodes, edges, { thresholdN: 5 });

    // Two clusters: one per relationship.
    expect(result.clusters.size).toBe(2);
  });
});
