import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import {
  aggregateSiblings,
  type ClusterPillData,
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

function sbomFindingGraph(): { nodes: Node<LineageNodeData>[]; edges: Edge[] } {
  const nodes = [makeNode("package:pillow@9", "package"), makeNode("source:sbom", "sourceFile"),
    ...Array.from({ length: 22 }, (_, i) => makeNode(`finding:${i}`, "vulnerability", `CVE-fixture-${i}`))];
  const edges = nodes.slice(2).flatMap((node) => [
    { ...makeEdge("package:pillow@9", node.id, "has_cve"), data: { relationship: "has_cve", evidence: { reference: `advisory:${node.id}` } } },
    { ...makeEdge("source:sbom", node.id, "contains"), data: { relationship: "contains", evidence: { reference: `source:${node.id}` } } },
  ]);
  return { nodes, edges };
}

it("groups 22 leaf findings by package while preserving both parent memberships and every receipt", () => {
  const { nodes, edges } = sbomFindingGraph();
  const before = structuredClone({ nodes, edges });
  const result = aggregateSiblings(nodes, edges, { thresholdN: 20 });
  expect(result.clusters.size).toBe(1);
  expect(result.nodes).toHaveLength(3);
  expect(result.edges).toHaveLength(2);
  const [id, group] = [...result.clusters.entries()][0]!;
  expect(group.parentId).toBe("package:pillow@9");
  expect(group.members).toEqual(nodes.slice(2).map((node) => node.id));
  expect(new Set(result.edges.map((edge) => edge.source))).toEqual(new Set(["package:pillow@9", "source:sbom"]));
  expect(result.edges.flatMap((edge) => edge.data?.originalEdgeIds).sort()).toEqual(edges.map((edge) => edge.id).sort());
  for (const edge of result.edges) {
    expect(edge.target).toBe(id);
    expect(edge.data?.isClusterEdge).toBe(true);
    expect(edge.data?.traversable).toBe(false);
    expect(edge.data?.members).toHaveLength(22);
  }
  const pill = result.nodes.find((node) => node.id === id)!;
  expect((pill.data as ClusterPillData).memberEdges).toEqual(edges);
  expect({ nodes, edges }).toEqual(before);
  const expanded = aggregateSiblings(nodes, edges, { thresholdN: 20, expandedClusterIds: new Set([id]) });
  expect(expanded.clusters.size).toBe(0);
  expect(expanded.nodes).toEqual(nodes);
  expect(expanded.edges).toEqual(edges);
});

it("never hides multi-package findings or outgoing evidence behind a package group", () => {
  const { nodes, edges } = sbomFindingGraph();
  nodes.push(makeNode("package:other", "package"), makeNode("identity", "serviceAccount"));
  edges.push(makeEdge("package:other", "finding:0", "has_cve"), makeEdge("finding:1", "identity", "reaches"));
  const result = aggregateSiblings(nodes, edges, { thresholdN: 20 });
  const group = [...result.clusters.values()][0]!;
  expect(group.members).toHaveLength(20);
  expect(result.nodes.map((node) => node.id)).toContain("finding:0");
  expect(result.nodes.map((node) => node.id)).toContain("finding:1");
  const visible = new Set(result.nodes.map((node) => node.id));
  expect(result.edges.every((edge) => visible.has(edge.source) && visible.has(edge.target))).toBe(true);
});

it("deduplicates membership and retains differing source-file membership on expansion", () => {
  const { nodes, edges } = sbomFindingGraph();
  nodes.push(makeNode("source:second", "sourceFile"));
  edges.push({ ...makeEdge("package:pillow@9", "finding:0", "has_cve"), id: "independent-receipt", data: { relationship: "has_cve", evidence: "second observation" } });
  edges.push(makeEdge("source:second", "finding:0", "contains"));
  const result = aggregateSiblings(nodes, edges, { thresholdN: 20 });
  const [id, group] = [...result.clusters.entries()][0]!;
  expect(group.members).toHaveLength(22);
  expect(result.edges.find((edge) => edge.source === "source:second")?.data?.members).toEqual(["finding:0"]);
  expect(result.edges.find((edge) => edge.source === "source:second")?.label).toBe("1 member");
  const expanded = aggregateSiblings(nodes, edges, { thresholdN: 20, expandedClusterIds: new Set([id]) });
  expect(expanded.edges).toEqual(edges);
});


it("does not collapse a non-leaf parent and leave its evidence edge dangling", () => {
  const nodes = [makeNode("server", "server"), ...Array.from({length: 5}, (_, i) => makeNode(`package:${i}`, "package")), makeNode("finding", "vulnerability")];
  const edges = nodes.slice(1, 6).map((node) => makeEdge("server", node.id, "contains"));
  edges.push(makeEdge("package:0", "finding", "has_cve"));
  const result = aggregateSiblings(nodes, edges, {thresholdN: 5});
  expect(result.nodes).toEqual(nodes);
  expect(result.edges).toEqual(edges);
});
