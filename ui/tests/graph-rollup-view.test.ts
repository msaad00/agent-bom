import { describe, expect, it } from "vitest";

import type { GraphRollupContainer } from "@/lib/api-types";
import {
  buildRollupFlowGraph,
  rollupContainerSubtitle,
  rollupEntityToNodeType,
} from "@/lib/graph-rollup-view";

function sampleContainer(
  overrides: Partial<GraphRollupContainer> = {},
): GraphRollupContainer {
  return {
    id: "account:prod",
    label: "prod",
    entity_type: "account",
    severity: "",
    is_container: true,
    has_children: true,
    direct_child_count: 2,
    aggregate: {
      descendant_count: 42,
      by_type: { server: 2, package: 40 },
      severity_counts: { critical: 1, low: 39 },
      worst_severity: "critical",
      worst_severity_rank: 5,
      internet_exposed: true,
      toxic_combo: false,
      exposed_count: 1,
      toxic_count: 0,
    },
    ...overrides,
  };
}

describe("rollupEntityToNodeType", () => {
  it("maps estate entity types to lineage node types", () => {
    expect(rollupEntityToNodeType("account")).toBe("account");
    expect(rollupEntityToNodeType("application")).toBe("container");
    expect(rollupEntityToNodeType("unknown_type")).toBe("cloudResource");
  });
});

describe("rollupContainerSubtitle", () => {
  it("summarizes descendants, severity, exposure, and drill hint", () => {
    const subtitle = rollupContainerSubtitle(sampleContainer());
    expect(subtitle).toContain("42 descendants");
    expect(subtitle).toContain("worst critical");
    expect(subtitle).toContain("internet exposed");
    expect(subtitle).toContain("click to drill down");
  });

  it("tolerates missing aggregate without throwing", () => {
    const subtitle = rollupContainerSubtitle(
      sampleContainer({
        aggregate: undefined as unknown as GraphRollupContainer["aggregate"],
        direct_child_count: 2,
      }),
    );
    expect(subtitle).toContain("2 direct children");
    expect(subtitle).toContain("click to drill down");
  });
});

describe("buildRollupFlowGraph", () => {
  it("lays out containers on a grid with rollup metadata", () => {
    const { nodes, edges } = buildRollupFlowGraph([
      sampleContainer(),
      sampleContainer({
        id: "account:dev",
        label: "dev",
        has_children: false,
        aggregate: {
          ...sampleContainer().aggregate,
          descendant_count: 3,
          worst_severity: "low",
          worst_severity_rank: 1,
          internet_exposed: false,
        },
      }),
    ]);

    expect(edges).toHaveLength(0);
    expect(nodes).toHaveLength(2);
    expect(nodes[0]?.id).toBe("account:prod");
    expect(nodes[0]?.position).toEqual({ x: 0, y: 0 });
    expect(nodes[1]?.position).toEqual({ x: 268, y: 0 });
    expect(nodes[0]?.data.attributes?.rollup_has_children).toBe(true);
    expect(nodes[0]?.data.description).toContain("click to drill down");
  });
});
