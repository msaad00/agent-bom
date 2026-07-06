import { describe, expect, it } from "vitest";

import {
  graphRollupEligible,
  parseGraphRollupUrlPreference,
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
