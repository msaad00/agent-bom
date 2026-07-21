import { describe, expect, it } from "vitest";

import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";
import {
  collectPathEnvironments,
  filterAttackPathsForInvestigation,
} from "@/lib/investigation-path-filters";

function path(overrides: Partial<AttackPath> & Pick<AttackPath, "hops">): AttackPath {
  return {
    source: overrides.hops[0] ?? "a",
    target: overrides.hops[overrides.hops.length - 1] ?? "z",
    edges: [],
    composite_risk: overrides.composite_risk ?? 8,
    summary: "test",
    credential_exposure: [],
    tool_exposure: [],
    vuln_ids: [],
    ...overrides,
  };
}

function node(
  id: string,
  entity_type: string,
  attributes: Record<string, unknown> = {},
): UnifiedNode {
  return {
    id,
    entity_type,
    label: id,
    status: "active",
    severity: "high",
    risk_score: 5,
    attributes,
  } as UnifiedNode;
}

describe("investigation-path-filters", () => {
  const nodes = new Map<string, UnifiedNode>([
    ["agent-1", node("agent-1", "agent", { environment: "prod" })],
    ["pkg-1", node("pkg-1", "package", { evidence_tier: "static_scan" })],
    ["vuln-1", node("vuln-1", "vulnerability", { evidence_tier: "runtime_observed" })],
  ]);

  const paths = [
    path({ hops: ["vuln-1", "pkg-1", "agent-1"], composite_risk: 9.2 }),
    path({ hops: ["pkg-1", "agent-1"], composite_risk: 3.1 }),
  ];

  it("filters by severity band derived from composite risk", () => {
    const critical = filterAttackPathsForInvestigation(paths, nodes, {
      severity: "critical",
      layer: null,
      evidenceTier: null,
      environment: null,
    });
    expect(critical).toHaveLength(1);
    expect(critical[0]!.composite_risk).toBe(9.2);
  });

  it("filters by semantic layer and evidence tier", () => {
    const filtered = filterAttackPathsForInvestigation(paths, nodes, {
      severity: null,
      layer: "finding",
      evidenceTier: "runtime_observed",
      environment: null,
    });
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.hops).toContain("vuln-1");
  });

  it("collects distinct environments from path hops", () => {
    expect(collectPathEnvironments(paths, nodes)).toEqual(["prod"]);
  });
});
