import { describe, expect, it } from "vitest";
import { completeDirectedHopCount } from "@/lib/security-graph-focus";
import type { AttackPath } from "@/lib/graph-schema";

function validPath(): AttackPath {
  return {
    source: "a", target: "c", hops: ["a", "b", "c"], edges: ["uses", "contains"],
    composite_risk: 8, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: [],
    reachability: "confirmed", analysis: { status: "complete" },
    hop_evidence: ["uses", "contains"].map((relationship, i) => ({
      source_node_id: ["a", "b"][i]!, target_node_id: ["b", "c"][i]!, relationship,
      source_snapshot_ids: ["scan"], relationship_provenance: "recorded", correlation_identity_status: "current",
      evidence_tier: "static_evidence", confidence: 1, freshness: "fresh", runtime_observed_state: "not_observed",
      direction: "directed", traversable: true, complete: true, truncated: false,
    })),
  } as AttackPath;
}

describe("ordered hop proof", () => {
  it("accepts an evidenced ordered positive path", () => expect(completeDirectedHopCount(validPath())).toBe(2));
  const cases: Array<[string, (path: AttackPath) => void]> = [
    ["missing analysis", p => { delete p.analysis; }],
    ["limited analysis", p => { p.analysis = {status: "limited"}; }],
    ["wrong path source", p => { p.source = "other"; }],
    ["wrong path target", p => { p.target = "other"; }],
    ["reversed", p => { p.hop_evidence!.reverse(); }],
    ["duplicate", p => { p.hop_evidence![1] = p.hop_evidence![0]!; }],
    ["unrelated relationship", p => { p.hop_evidence![0]!.relationship = "other"; }],
    ["stale", p => { p.hop_evidence![0]!.freshness = "stale_allowed"; }],
    ["unknown freshness", p => { p.hop_evidence![0]!.freshness = "unknown"; }],
    ["missing provenance", p => { delete (p.hop_evidence![0] as unknown as Record<string, unknown>).relationship_provenance; }],
    ["old identity", p => { Object.assign(p.hop_evidence![0]!, {correlation_identity_status: "recomputation_required"}); }],
    ["empty source", p => { p.hop_evidence![0]!.source_snapshot_ids = [""]; }],
    ["malformed sources", p => { Object.assign(p.hop_evidence![0]!, {source_snapshot_ids: null}); }],
    ["missing receipt", p => { p.hop_evidence!.pop(); }],
    ["truncated", p => { p.hop_evidence![0]!.truncated = true; }],
    ["non-traversable", p => { p.hop_evidence![0]!.traversable = false; }],
    ["no hops", p => { p.hops = []; p.edges = []; p.hop_evidence = []; }],
  ];
  it.each(cases)("rejects %s", (_, mutate) => {
    const path = validPath(); mutate(path);
    expect(completeDirectedHopCount(path)).toBeNull();
  });
});
