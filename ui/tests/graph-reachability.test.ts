import { describe, expect, it } from "vitest";

import { summarizeReachability } from "@/lib/graph-reachability";
import { EntityType, RelationshipType, type UnifiedEdge, type UnifiedNode } from "@/lib/graph-schema";

function node(id: string, entityType: EntityType, label: string, riskScore = 0): UnifiedNode {
  return {
    id,
    entity_type: entityType,
    label,
    risk_score: riskScore,
  } as UnifiedNode;
}

function edge(id: string, source: string, target: string, traversable = true): UnifiedEdge {
  return {
    id,
    source,
    target,
    relationship: RelationshipType.USES,
    direction: "directed",
    traversable,
  } as UnifiedEdge;
}

describe("graph reachability", () => {
  it("summarizes reachable nodes, edge keys, type counts, and bounded path previews", () => {
    const summary = summarizeReachability({
      rootId: "agent-1",
      rootLabel: "Build agent",
      nodes: [
        node("agent-1", EntityType.AGENT, "Build agent", 4),
        node("tool-1", EntityType.TOOL, "Deploy tool", 8),
        node("cred-1", EntityType.CREDENTIAL, "Cloud token", 7),
        node("pkg-1", EntityType.PACKAGE, "Unused package", 1),
      ],
      edges: [
        edge("edge-1", "agent-1", "tool-1"),
        edge("edge-2", "tool-1", "cred-1"),
        edge("edge-3", "pkg-1", "cred-1"),
      ],
      depthByNode: {
        "agent-1": 0,
        "tool-1": 1,
        "cred-1": 2,
      },
    });

    expect(summary.nodeIds).toEqual(new Set(["agent-1", "tool-1", "cred-1"]));
    expect(summary.edgeKeys.has("agent-1=>tool-1")).toBe(true);
    expect(summary.edgeKeys.has("pkg-1=>cred-1")).toBe(false);
    expect(summary.countsByType).toEqual({ tool: 1, credential: 1 });
    expect(summary.pathPreviews[0]).toMatchObject({
      targetId: "tool-1",
      depth: 1,
      labels: ["Build agent", "Deploy tool"],
    });
  });

  it("ignores non-traversable edges when building path previews", () => {
    const summary = summarizeReachability({
      rootId: "agent-1",
      nodes: [
        node("agent-1", EntityType.AGENT, "Build agent"),
        node("tool-1", EntityType.TOOL, "Deploy tool"),
      ],
      edges: [edge("edge-1", "agent-1", "tool-1", false)],
    });

    expect(summary.nodeIds).toEqual(new Set(["agent-1"]));
    expect(summary.pathPreviews).toEqual([]);
  });
});
