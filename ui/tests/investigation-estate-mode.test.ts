import { describe, expect, it } from "vitest";

import { investigationEstateMode } from "@/lib/investigation-estate-mode";
import { graphRollupPreferenceForCanvas } from "@/lib/graph-rollup-default";

describe("investigationEstateMode", () => {
  it("defaults a 1,241-node estate to clustered investigation with raw topology as drill-down", () => {
    expect(investigationEstateMode(1_241, "scan-large")).toEqual({
      large: true,
      summary: "1,241 nodes",
      clusteredHref: "/security-graph?scan=scan-large&lens=lineage&rollup=1",
      rawHref: "/security-graph?scan=scan-large&lens=lineage&rollup=0",
    });
  });

  it("does not warn for a small graph", () => {
    expect(investigationEstateMode(120, "scan-small").large).toBe(false);
  });
});

describe("graphRollupPreferenceForCanvas", () => {
  it("starts the estate canvas as a roll-up while preserving explicit raw mode", () => {
    expect(graphRollupPreferenceForCanvas(new URLSearchParams(), true)).toBe("force");
    expect(graphRollupPreferenceForCanvas(new URLSearchParams("rollup=0"), true)).toBe("off");
    expect(graphRollupPreferenceForCanvas(new URLSearchParams(), false)).toBe("default");
  });
});
