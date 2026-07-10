import { describe, expect, it } from "vitest";

import { buildContextFlowGraph, displayContextDescription, topLateralPathForAgent, type ContextGraphData, type LateralPath } from "@/lib/context-graph";
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
    expect(graph.focusedPath).toBeNull();
  });

  it("strips untrusted MCP metadata prefix from tool descriptions", () => {
    expect(displayContextDescription("[UNTRUSTED MCP METADATA] send a message")).toBe("send a message");
    expect(displayContextDescription("[UNTRUSTED MCP METADATA] ")).toBeUndefined();
  });

  it("scopes the canvas to the highest-risk lateral path when topPathOnly is enabled", () => {
    const paths: LateralPath[] = [
      {
        source: "agent:desktop",
        target: "vuln:critical",
        hops: ["agent:desktop", "server:chat", "vuln:critical"],
        edges: [],
        composite_risk: 9.6,
        summary: "desktop -> chat -> critical",
        credential_exposure: [],
        tool_exposure: [],
        vuln_ids: ["CVE-CRIT"],
      },
      {
        source: "agent:desktop",
        target: "vuln:low",
        hops: ["agent:desktop", "server:notes", "vuln:low"],
        edges: [],
        composite_risk: 3.1,
        summary: "desktop -> notes -> low",
        credential_exposure: [],
        tool_exposure: [],
        vuln_ids: ["CVE-LOW"],
      },
    ];
    const data: ContextGraphData = {
      nodes: [
        { id: "agent:desktop", kind: "agent", label: "desktop", metadata: {} },
        { id: "server:chat", kind: "server", label: "chat", metadata: {} },
        { id: "server:notes", kind: "server", label: "notes", metadata: {} },
        { id: "vuln:critical", kind: "vulnerability", label: "CVE-CRIT", metadata: { severity: "critical" } },
        { id: "vuln:low", kind: "vulnerability", label: "CVE-LOW", metadata: { severity: "low" } },
      ],
      edges: [
        { source: "agent:desktop", target: "server:chat", kind: "uses", weight: 1, metadata: {} },
        { source: "server:chat", target: "vuln:critical", kind: "vulnerable_to", weight: 1, metadata: {} },
        { source: "agent:desktop", target: "server:notes", kind: "uses", weight: 1, metadata: {} },
        { source: "server:notes", target: "vuln:low", kind: "vulnerable_to", weight: 1, metadata: {} },
      ],
      lateral_paths: paths,
      interaction_risks: [],
      stats: {
        total_nodes: 5,
        total_edges: 4,
        agent_count: 1,
        shared_server_count: 0,
        shared_credential_count: 0,
        lateral_path_count: 2,
        max_lateral_depth: 2,
        highest_path_risk: 9.6,
        interaction_risk_count: 0,
      },
    };

    expect(topLateralPathForAgent(paths, "desktop")?.composite_risk).toBe(9.6);
    const focused = buildContextFlowGraph(data, "desktop", { topPathOnly: true });
    expect(focused.focusedPath?.vuln_ids).toEqual(["CVE-CRIT"]);
    expect(focused.nodes.map((node) => node.id)).toEqual([
      "agent:desktop",
      "server:chat",
      "vuln:critical",
    ]);
  });
});
