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

  it("filters by finding severity rather than composite risk", () => {
    const critical = filterAttackPathsForInvestigation(paths, nodes, {
      severity: "high",
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

  it("reads environment from dimensions when attributes omit it", () => {
    const dimsOnly = new Map<string, UnifiedNode>([
      [
        "agent-dims",
        {
          ...node("agent-dims", "agent"),
          dimensions: { environment: "staging" },
        } as UnifiedNode,
      ],
    ]);
    expect(collectPathEnvironments([path({ hops: ["agent-dims"] })], dimsOnly)).toEqual(["staging"]);
  });
});


it("never promotes high priority into critical finding severity", () => {
  const nodes = new Map([["asset", node("asset", "cloud_resource")], ["finding", { ...node("finding", "vulnerability"), severity: "low" }]]);
  const filters = { severity: "critical", layer: null, evidenceTier: null, environment: null };
  expect(filterAttackPathsForInvestigation([path({ hops: ["asset", "finding"], composite_risk: 95 })], nodes, filters)).toEqual([]);
});

it("retains a critical finding even when its path priority is low", () => {
  const nodes = new Map([["finding", { ...node("finding", "misconfiguration"), severity: "critical" }]]);
  const candidate = path({ hops: ["finding"], composite_risk: 2 });
  expect(filterAttackPathsForInvestigation([candidate], nodes, { severity: "critical", layer: null, evidenceTier: null, environment: null })).toEqual([candidate]);
});


it("preserves explicit unknown severity and never substitutes an asset risk", () => {
  const nodes = new Map([["asset", { ...node("asset", "cloud_resource"), severity: "critical" }], ["finding", { ...node("finding", "vulnerability"), severity: "critical" }]]);
  const filters = { severity: "critical", layer: null, evidenceTier: null, environment: null };
  expect(filterAttackPathsForInvestigation([path({ hops: ["asset"], composite_risk: 100 })], nodes, filters)).toEqual([]);
  expect(filterAttackPathsForInvestigation([path({ hops: ["finding"], severity: "unknown", composite_risk: 100 })], nodes, filters)).toEqual([]);
});

it("question presets preserve server order and never infer credentials or criticality from priority", async () => {
  const { filterInvestigationQuestion } = await import("@/lib/investigation-path-filters");
  const nodes = new Map([["pkg", node("pkg", "package")], ["v", node("v", "vulnerability")]]);
  const low = path({ hops: ["pkg", "v"], severity: "low", composite_risk: 99 });
  const critical = path({ hops: ["pkg", "v"], severity: "critical", composite_risk: 10 });
  const credential = path({ hops: ["pkg", "v"], credential_exposure: ["redacted credential"] });
  expect(filterInvestigationQuestion([low, critical, credential], nodes, "critical")).toEqual([critical]);
  expect(filterInvestigationQuestion([low, credential, critical], nodes, "credentials")).toEqual([credential]);
  expect(filterInvestigationQuestion([low, critical], nodes, null)).toEqual([low, critical]);
});
