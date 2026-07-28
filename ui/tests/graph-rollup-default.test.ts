import { describe, expect, it } from "vitest";

import {
  graphRollupCanvasMode,
  graphRollupEligible,
  parseGraphRollupUrlPreference,
  parseRollupNodeParam,
  rollupDismissedForPreference,
  rollupViewHasContainers,
} from "@/lib/graph-rollup-default";

describe("parseGraphRollupUrlPreference", () => {
  it("parses default, forced, and explicitly disabled preferences", () => {
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
    estateNodeCount: 36,
    investigationMode: false,
    selectedAttackPath: false,
    reachabilityActive: false,
    blastRadiusActive: false,
  };

  it("defaults to real topology below 200 nodes and roll-up at 200 or more", () => {
    expect(graphRollupEligible(base)).toBe(false);
    expect(graphRollupEligible({ ...base, estateNodeCount: 199 })).toBe(false);
    expect(graphRollupEligible({ ...base, estateNodeCount: 200 })).toBe(true);
  });

  it("does not let ranked-path availability override the estate threshold", () => {
    expect(
      graphRollupEligible({
        ...base,
        estateNodeCount: 200,
        attackPathCount: 3,
      }),
    ).toBe(true);
  });

  it("honors an explicit rollup=1 preference even when attack paths exist", () => {
    expect(
      graphRollupEligible({
        hasSelectedScan: true,
        rollupPreference: "force",
        rollupDismissed: false,
        estateNodeCount: 36,
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
        estateNodeCount: 36,
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

describe("roll-up presentation state", () => {
  it("derives dismissal only from an explicit operator opt-out", () => {
    expect(rollupDismissedForPreference("off")).toBe(true);
    expect(rollupDismissedForPreference("force")).toBe(false);
    expect(rollupDismissedForPreference("default")).toBe(false);
  });

  it("withholds raw topology while an eligible roll-up is loading", () => {
    expect(
      graphRollupCanvasMode({
        eligible: true,
        dismissed: false,
        hasView: false,
        unavailable: false,
        failed: false,
      }),
    ).toBe("loading");
    expect(
      graphRollupCanvasMode({
        eligible: true,
        dismissed: false,
        hasView: true,
        unavailable: false,
        failed: false,
      }),
    ).toBe("active");
    expect(
      graphRollupCanvasMode({
        eligible: true,
        dismissed: false,
        hasView: false,
        unavailable: true,
        failed: false,
      }),
    ).toBe("raw");
    expect(
      graphRollupCanvasMode({
        eligible: true,
        dismissed: false,
        hasView: false,
        unavailable: false,
        failed: false,
      }),
    ).toBe("loading");
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
