import { describe, expect, it } from "vitest";

import { buildContextFlowGraph, type ContextGraphData } from "@/lib/context-graph";
import { RELATIONSHIP_COLOR_MAP, RelationshipType } from "@/lib/graph-schema";

describe("buildContextFlowGraph", () => {
  it("prefers canonical entity and relationship fields when present", () => {
    const data: ContextGraphData = {
      nodes: [
        {
          id: "iam_role:prod",
          kind: "iam_role",
          entity_type: "service_account",
          label: "prod-role",
          metadata: {},
        },
        {
          id: "agent:desktop",
          kind: "agent",
          entity_type: "agent",
          label: "desktop",
          metadata: {},
        },
      ],
      edges: [
        {
          source: "iam_role:prod",
          target: "agent:desktop",
          kind: "attached_to",
          relationship: "member_of",
          weight: 1,
          metadata: {},
        },
      ],
      lateral_paths: [],
      interaction_risks: [],
      stats: {
        total_nodes: 2,
        total_edges: 1,
        agent_count: 1,
        shared_server_count: 0,
        shared_credential_count: 0,
        lateral_path_count: 0,
        max_lateral_depth: 0,
        highest_path_risk: 0,
        interaction_risk_count: 0,
      },
    };

    const graph = buildContextFlowGraph(data);

    const identityNode = graph.nodes.find((node) => node.id === "iam_role:prod");
    expect(identityNode?.type).toBe("serviceAccountNode");
    expect(identityNode?.data.nodeType).toBe("serviceAccount");
    expect(graph.edges[0]?.data).toMatchObject({ relationship: "member_of" });
    expect(graph.edges[0]?.style?.stroke).toBe(RELATIONSHIP_COLOR_MAP[RelationshipType.MEMBER_OF]);
  });
});
