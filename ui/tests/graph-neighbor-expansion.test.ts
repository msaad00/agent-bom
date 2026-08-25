import { describe, expect, it } from "vitest";

import { mergeGraphNeighborExpansions } from "@/lib/graph-neighbor-expansion";
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
