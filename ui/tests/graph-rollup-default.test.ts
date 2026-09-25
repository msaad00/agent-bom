import { describe, expect, it } from "vitest";

import {
  graphRollupCanvasMode,
  graphRollupEligible,
  MAX_ROLLUP_AUTO_DESCEND_DEPTH,
  parseGraphRollupUrlPreference,
  rollupAutoDescendTarget,
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

describe("failed roll-up on an eligible estate", () => {
  it("does not fall back to the raw topology without an explicit request", () => {
    expect(
      graphRollupCanvasMode({
        eligible: true,
        dismissed: false,
        hasView: false,
        unavailable: false,
        failed: true,
      }),
    ).toBe("failed");
    expect(
      graphRollupCanvasMode({
        eligible: true,
        dismissed: true,
        hasView: false,
        unavailable: false,
        failed: true,
      }),
    ).toBe("raw");
  });
});

describe("rollupAutoDescendTarget", () => {
  const org = { id: "org:northstar", label: "Northstar", is_container: true, has_children: true };
  const account = { id: "account:prod", label: "prod", is_container: true, has_children: true };

  it("descends through a lone top-level container so the first view is a ranked summary", () => {
    expect(
      rollupAutoDescendTarget({ mode: "rollup", top_level: [org] }, { stack: [], allowed: true }),
    ).toEqual({ id: "org:northstar", label: "Northstar" });
    expect(
      rollupAutoDescendTarget({ mode: "drilldown", children: [account] }, { stack: [{ id: "org:northstar" }], allowed: true }),
    ).toEqual({ id: "account:prod", label: "prod" });
  });

  it("stops at a level that already offers a choice", () => {
    expect(
      rollupAutoDescendTarget({ mode: "rollup", top_level: [org, account] }, { stack: [], allowed: true }),
    ).toBeNull();
    expect(rollupAutoDescendTarget({ mode: "rollup", top_level: [] }, { stack: [], allowed: true })).toBeNull();
  });

  it("never descends into a leaf, past the depth bound, or after an operator navigates", () => {
    const leaf = { id: "asset:db", label: "db", is_container: false, has_children: false };
    expect(rollupAutoDescendTarget({ mode: "rollup", top_level: [leaf] }, { stack: [], allowed: true })).toBeNull();
    expect(
      rollupAutoDescendTarget(
        { mode: "drilldown", children: [account] },
        { stack: Array.from({ length: MAX_ROLLUP_AUTO_DESCEND_DEPTH }, (_, i) => ({ id: `scope:${i}` })), allowed: true },
      ),
    ).toBeNull();
    expect(rollupAutoDescendTarget({ mode: "rollup", top_level: [org] }, { stack: [], allowed: false })).toBeNull();
  });

  it("does not reopen a scope that is already on the stack", () => {
    expect(
      rollupAutoDescendTarget({ mode: "drilldown", children: [org] }, { stack: [{ id: "org:northstar" }], allowed: true }),
    ).toBeNull();
  });

  it("ignores the attack-path view", () => {
    expect(
      rollupAutoDescendTarget({ mode: "attack_path", top_level: [org] }, { stack: [], allowed: true }),
    ).toBeNull();
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
