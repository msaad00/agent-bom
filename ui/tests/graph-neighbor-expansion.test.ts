import { describe, expect, it } from "vitest";

import { mergeGraphNeighborExpansions, boundedInvestigationGraph } from "@/lib/graph-neighbor-expansion";
import { EntityType, RelationshipType, type UnifiedGraphData } from "@/lib/graph-schema";

const graph = {
  scan_id: "scan-1",
  tenant_id: "tenant-1",
  created_at: "2026-08-25T00:00:00Z",
  nodes: [{ id: "agent:1", entity_type: EntityType.AGENT, label: "Agent" }],
  edges: [],
  attack_paths: [],
  interaction_risks: [],
  stats: {},
} as unknown as UnifiedGraphData;

describe("mergeGraphNeighborExpansions", () => {
  it("adds returned nodes and edges to the displayed projection without duplicates", () => {
    const expanded = mergeGraphNeighborExpansions(graph, [{
      node_id: "agent:1",
      scan_id: "scan-1",
      found: true,
      direction: "both",
      limit: 24,
      total_neighbors: 3,
      truncated: true,
      neighbors: [
        graph.nodes[0]!,
        { id: "server:1", entity_type: EntityType.SERVER, label: "MCP server" } as typeof graph.nodes[number],
      ],
      edges: [{ id: "edge:1", source: "agent:1", target: "server:1", relationship: RelationshipType.USES }] as never[],
    }]);

    expect(expanded.nodes.map((node) => node.id)).toEqual(["agent:1", "server:1"]);
    expect(expanded.edges.map((edge) => edge.id)).toEqual(["edge:1"]);
    expect(expanded.scan_id).toBe("scan-1");
  });
});

describe("bounded investigation", () => {
  it.each([10, 1000, 10000])("retains selected-path evidence within the %i-node fixture", (size) => {
    const nodes = Array.from({ length: size }, (_, index) => ({ ...graph.nodes[0]!, id: `n-${index}` }));
    const edges = nodes.slice(1).map((node, index) => ({ id: `e-${index}`, source: nodes[index]!.id, target: node.id, relationship: RelationshipType.USES }));
    const input = { ...graph, nodes, edges } as UnifiedGraphData;
    const result = boundedInvestigationGraph(input, [`n-${size - 1}`], 0);
    expect(result.graph.nodes.length).toBeLessThanOrEqual(100);
    expect(result.graph.nodes.some(node => node.id === `n-${size - 1}`)).toBe(true);
    const ids = new Set(result.graph.nodes.map(node => node.id));
    expect(result.graph.edges.every(edge => ids.has(edge.source) && ids.has(edge.target))).toBe(true);
    expect(result.omittedNodes).toBe(size - ids.size);
    expect(result.graph.stats).toBe(input.stats);
    if (size > 100) {
      const next = boundedInvestigationGraph(input, [`n-${size - 1}`], 1);
      expect(next.graph.nodes.map(node => node.id)).not.toEqual(result.graph.nodes.map(node => node.id));
      expect(next.graph.nodes.some(node => node.id === `n-${size - 1}`)).toBe(true);
    }
  });
});
