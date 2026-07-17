import { describe, expect, it } from "vitest";

import {
  graphRollupEligible,
  parseGraphRollupUrlPreference,
  parseRollupNodeParam,
  rollupViewHasContainers,
} from "@/lib/graph-rollup-default";

describe("parseGraphRollupUrlPreference", () => {
  it("defaults to roll-up unless explicitly opted out", () => {
    expect(parseGraphRollupUrlPreference(new URLSearchParams())).toBe("default");
    expect(parseGraphRollupUrlPreference(new URLSearchParams("rollup=1"))).toBe(
      "force",
    );
    expect(parseGraphRollupUrlPreference(new URLSearchParams("rollup=0"))).toBe(
      "off",
    );
  });

  it("parses rollup_node drill param", () => {
    expect(
      parseRollupNodeParam(new URLSearchParams("rollup_node=account%3Aprod")),
    ).toBe("account:prod");
  });
});

describe("graphRollupEligible", () => {
  const base = {
    hasSelectedScan: true,
    rollupPreference: "default" as const,
    rollupDismissed: false,
    investigationMode: false,
    selectedAttackPath: false,
    reachabilityActive: false,
    blastRadiusActive: false,
  };

  it("enables roll-up for any snapshot size when not in investigation overlays", () => {
    expect(graphRollupEligible(base)).toBe(true);
  });

  it("skips roll-up when ranked attack paths are available", () => {
    expect(graphRollupEligible({ ...base, attackPathCount: 3 })).toBe(false);
  });

  it("honors an explicit rollup=1 preference even when attack paths exist", () => {
    expect(
      graphRollupEligible({
        hasSelectedScan: true,
        rollupPreference: "force",
        rollupDismissed: false,
        investigationMode: false,
        selectedAttackPath: false,
        reachabilityActive: false,
        blastRadiusActive: false,
        attackPathCount: 12,
      }),
    ).toBe(true);
  });

  it.each([
    ["investigation", { investigationMode: true }],
    ["selected path", { selectedAttackPath: true }],
    ["reachability", { reachabilityActive: true }],
    ["blast radius", { blastRadiusActive: true }],
  ])("keeps %s detail overlays ahead of explicit rollup", (_label, overlay) => {
    expect(
      graphRollupEligible({
        hasSelectedScan: true,
        rollupPreference: "force",
        rollupDismissed: false,
        investigationMode: false,
        selectedAttackPath: false,
        reachabilityActive: false,
        blastRadiusActive: false,
        attackPathCount: 12,
        ...overlay,
      }),
    ).toBe(false);
  });

  it("respects explicit opt-out and competing overlays", () => {
    expect(
      graphRollupEligible({ ...base, rollupPreference: "off" }),
    ).toBe(false);
    expect(graphRollupEligible({ ...base, rollupDismissed: true })).toBe(false);
    expect(graphRollupEligible({ ...base, investigationMode: true })).toBe(
      false,
    );
    expect(graphRollupEligible({ ...base, selectedAttackPath: true })).toBe(
      false,
    );
    expect(graphRollupEligible({ ...base, reachabilityActive: true })).toBe(
      false,
    );
    expect(graphRollupEligible({ ...base, blastRadiusActive: true })).toBe(
      false,
    );
  });
});

describe("rollupViewHasContainers", () => {
  it("detects empty roll-up payloads", () => {
    expect(rollupViewHasContainers("rollup", [], undefined)).toBe(false);
    expect(
      rollupViewHasContainers("rollup", [{ id: "account:prod" }], undefined),
    ).toBe(true);
    expect(
      rollupViewHasContainers("drilldown", undefined, [{ id: "fleet:a" }]),
    ).toBe(true);
  });
});
