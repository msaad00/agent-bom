import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import { evaluateGraphUx, gradeGraphUxScore } from "@/lib/graph-ux-evaluation";
import type { UnifiedGraphResponse } from "@/lib/api";

function graphFixture(): UnifiedGraphResponse {
  return {
    nodes: [
      { id: "agent:a", entity_type: "agent", data_sources: ["scan"] },
      { id: "server:a/fs", entity_type: "server", data_sources: ["scan"] },
      { id: "pkg:npm/next@16.2.6", entity_type: "package", data_sources: ["lockfile"] },
      { id: "cve:CVE-2026-21441", entity_type: "vulnerability", data_sources: ["osv"] },
      { id: "cred:GITHUB_TOKEN", entity_type: "credential", data_sources: ["config"] },
      { id: "tool:create_pull_request", entity_type: "tool", data_sources: ["introspection"] },
      { id: "env:prod", entity_type: "environment", data_sources: ["scan"] },
    ],
    edges: [
      { source: "agent:a", target: "server:a/fs", relationship: "uses", evidence: { source: "config" } },
      { source: "server:a/fs", target: "pkg:npm/next@16.2.6", relationship: "depends_on", evidence: { source: "lockfile" } },
      { source: "pkg:npm/next@16.2.6", target: "cve:CVE-2026-21441", relationship: "affects", evidence: { source: "osv" } },
      { source: "server:a/fs", target: "cred:GITHUB_TOKEN", relationship: "exposes_cred", evidence: { source: "env" } },
      { source: "cred:GITHUB_TOKEN", target: "tool:create_pull_request", relationship: "reaches_tool", evidence: { confidence: "medium" } },
      { source: "env:prod", target: "agent:a", relationship: "hosts", evidence: { source: "scan" } },
    ],
    attack_paths: [
      {
        source: "agent:a",
        target: "cve:CVE-2026-21441",
        hops: ["agent:a", "server:a/fs", "pkg:npm/next@16.2.6", "cve:CVE-2026-21441"],
        edges: [],
        composite_risk: 9.1,
        summary: "test",
        credential_exposure: [],
        tool_exposure: [],
        vuln_ids: ["CVE-2026-21441"],
      },
    ],
  } as unknown as UnifiedGraphResponse;
}

describe("evaluateGraphUx", () => {
  it("scores a relationship-rich graph as strong or better", () => {
    const graph = graphFixture();
    const evaluation = evaluateGraphUx(
      graph,
      graph.nodes.map((node) => ({ id: node.id })) as unknown as Node[],
      graph.edges.map((edge, index) => ({ id: `e${index}`, source: edge.source, target: edge.target })) as unknown as Edge[],
    );

    expect(evaluation.score).toBeGreaterThanOrEqual(82);
    expect(["strong", "excellent"]).toContain(evaluation.grade);
    expect(evaluation.stats.entityTypes).toBe(7);
    expect(evaluation.stats.relationshipTypes).toBe(6);
    expect(evaluation.warnings).not.toContain("No ranked attack paths are available for this view.");
  });

  it("warns when relationships and path signal are missing", () => {
    const evaluation = evaluateGraphUx({
      ...graphFixture(),
      edges: [],
      attack_paths: [],
    });

    expect(evaluation.grade).toBe("failing");
    expect(evaluation.warnings).toContain("Entities are present but relationships are missing.");
    expect(evaluation.warnings).toContain("No ranked attack paths are available for this view.");
  });

  it("keeps grade boundaries stable", () => {
    expect(gradeGraphUxScore(93)).toBe("excellent");
    expect(gradeGraphUxScore(83)).toBe("strong");
    expect(gradeGraphUxScore(69)).toBe("usable");
    expect(gradeGraphUxScore(51)).toBe("weak");
    expect(gradeGraphUxScore(49)).toBe("failing");
  });
});
