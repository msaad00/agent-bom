import { describe, expect, it } from "vitest";

import { investigationEstateMode } from "@/lib/investigation-estate-mode";

describe("investigationEstateMode", () => {
  it("defaults a 1,241-node estate to clustered investigation with raw topology as drill-down", () => {
    expect(investigationEstateMode(1_241, "scan-large")).toEqual({
      large: true,
      summary: "1,241 nodes",
      clusteredHref: "/graph?scan=scan-large&rollup=1",
      rawHref: "/graph?scan=scan-large&rollup=0",
    });
  });

  it("does not warn for a small graph", () => {
    expect(investigationEstateMode(120, "scan-small").large).toBe(false);
  });
});
