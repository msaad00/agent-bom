import { describe, expect, it } from "vitest";
import type { ContextGraphData, ContextGraphNode } from "@/lib/context-graph";
import { contextExpansionKey, projectContextNeighborhood } from "@/lib/context-neighborhood";

const node = (id: string, kind: ContextGraphNode["kind"] = "server"): ContextGraphNode => ({ id, kind, label: "same label", metadata: {} });
function graph(nodes: ContextGraphNode[], pairs: string[][]): ContextGraphData {
  return { nodes, edges: pairs.map(([source, target]) => ({ source: source!, target: target!, kind: "uses", weight: 1, metadata: {} })),
    lateral_paths: [], interaction_risks: [], stats: { total_nodes: nodes.length, total_edges: pairs.length, agent_count: 1,
      shared_server_count: 0, shared_credential_count: 0, lateral_path_count: 0, max_lateral_depth: 0, highest_path_risk: 0, interaction_risk_count: 0 } };
}
const chain = graph([node("a", "agent"), node("b"), node("c", "tool"), node("d", "credential"), node("other")], [["a", "b"], ["b", "c"], ["c", "d"]]);

describe("projectContextNeighborhood", () => {
  it("starts with two recorded hops and groups the next hidden neighbors", () => {
    const result = projectContextNeighborhood(chain, "a", [], "both", 2);
    expect(result.nodes.map(n => n.id)).toEqual(["a", "b", "c"]);
    expect(result.depthById).toEqual({ a: 0, b: 1, c: 2 });
    expect(result.hiddenGroups.c).toEqual([{ kind: "credential", count: 1, nodeIds: ["d"], nodeIdsTruncated: false }]);
    expect(result.hiddenNodeCount).toBe(2);
    expect(result.hiddenEdgeCount).toBe(1);
    expect(result.truncated).toBe(false);
  });
  it("expands selected visible nodes one hop without joining names or disconnected IDs", () => {
    const result = projectContextNeighborhood(chain, "a", ["c", "other"], "both", 2);
    expect(result.nodes.map(n => n.id)).toEqual(["a", "b", "c", "d"]);
    expect(result.depthById).toEqual({ a: 0, b: 1, c: 2, d: 3 });
    expect(result.hiddenNodeCount).toBe(1);
    expect(projectContextNeighborhood(chain, "same label").seedFound).toBe(false);
  });
  it("respects incoming/outgoing direction while retaining recorded arrow endpoints", () => {
    const incoming = projectContextNeighborhood(chain, "c", [], "in", 1);
    expect(incoming.nodes.map(n => n.id)).toEqual(["c", "b"]);
    expect(incoming.edges[0]).toEqual(chain.edges[1]);
    expect(projectContextNeighborhood(chain, "c", [], "out", 1).nodes.map(n => n.id)).toEqual(["c", "d"]);
  });
  it("batches fanout at four neighbors, counts distinct hidden IDs and drops dangling edges", () => {
    const nodes = [node("a", "agent"), ...Array.from({ length: 100 }, (_, i) => node(`n${String(i).padStart(3, "0")}`, "tool"))];
    const data = graph(nodes, [...nodes.slice(1).map(n => ["a", n.id]), ["a", "missing"]]);
    const result = projectContextNeighborhood(data, "a");
    expect(result.nodes).toHaveLength(5);
    expect(result.edges).toHaveLength(4);
    expect(result.hiddenNodeCount).toBe(96);
    expect(result.hiddenEdgeCount).toBe(96);
    expect(result.hiddenGroups.a?.[0]?.count).toBe(96);
    expect(result.hiddenGroups.a?.[0]?.nodeIds).toHaveLength(24);
    expect(result.hiddenGroups.a?.[0]?.nodeIdsTruncated).toBe(true);
    expect(result.truncated).toBe(false);
    expect(projectContextNeighborhood({ ...data, nodes: [...nodes].reverse(), edges: [...data.edges].reverse() }, "a").nodes).toEqual(result.nodes);
  });
  it("caps cross-links at36 while keeping every included node connected", () => {
    const nodes = Array.from({ length: 20 }, (_, i) => node(String(i)));
    const data = graph(nodes, nodes.flatMap(a => nodes.filter(b => a !== b).map(b => [a.id, b.id])));
    const result = projectContextNeighborhood(data, "0", [], "both", 3);
    expect(result.edges).toHaveLength(36);
    expect(result.hiddenEdgeCount).toBe(344);
    expect(result.truncated).toBe(true);
    for (const item of result.nodes.slice(1)) expect(result.edges.some(e => e.source === item.id || e.target === item.id)).toBe(true);
  });
  it("keeps a thousand-agent shared hub bounded, expands exact batches, and collapses", () => {
    const nodes = [node("hub"), ...Array.from({ length: 5000 }, (_, i) => node(`agent:${String(i).padStart(5, "0")}`, "agent"))];
    const data = graph(nodes, nodes.slice(1).map(n => [n.id, "hub"]));
    const start = performance.now();
    const initial = projectContextNeighborhood(data, "hub", [], "in");
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1000);
    expect(initial.nodes).toHaveLength(5);
    expect(initial.hiddenGroups.hub?.[0]?.count).toBe(4996);
    const expanded = projectContextNeighborhood(data, "hub", [], "in", 1, { [contextExpansionKey("hub", "agent")]: 1 });
    expect(expanded.nodes).toHaveLength(9);
    expect(expanded.hiddenGroups.hub?.[0]?.count).toBe(4992);
    expect(expanded.edges.every(edge => edge.target === "hub")).toBe(true);
    const capped = projectContextNeighborhood(data, "hub", [], "in", 1, { [contextExpansionKey("hub", "agent")]: 100 });
    expect(capped.nodes).toHaveLength(24);
    expect(capped.truncated).toBe(true);
    expect(capped.edges).toHaveLength(23);
    expect(projectContextNeighborhood(data, "hub", [], "in").nodes).toEqual(initial.nodes);
    expect(projectContextNeighborhood(data, "agent:04999").nodes.map(n => n.id)).toEqual(["agent:04999", "hub"]);
  });
  it("uses canonical types for hidden groups and deduplicates parallel neighbors", () => {
    const data = graph([node("a"), { ...node("role", "tool"), entity_type: "iam_role" }], [["a", "role"], ["a", "role"]]);
    const result = projectContextNeighborhood(data, "a");
    expect(result.nodes).toHaveLength(2);
    expect(result.edges).toHaveLength(2);
  });
  it("keeps unknown source completeness distinct from a local projection cap", () => {
    const result = projectContextNeighborhood({ ...chain, completeness: { status: "truncated", complete: false, sampled: false, truncated: true, returned: 5 } }, "a");
    expect(result.sourceIncomplete).toBe(true);
    expect(result.truncated).toBe(false);
    expect(chain.nodes).toHaveLength(5);
  });
});
