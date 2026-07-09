import { describe, expect, it } from "vitest";

import { laneForPath, PAGE_LANE_META } from "@/lib/page-lanes";

describe("page lanes", () => {
  it("maps primary routes to product lanes", () => {
    expect(laneForPath("/manifest")).toBe("ai-estate");
    expect(laneForPath("/registry")).toBe("reference");
    expect(laneForPath("/cost")).toBe("operations");
    expect(laneForPath("/connections")).toBe("cloud-data");
    expect(laneForPath("/security-graph")).toBe("command");
  });

  it("resolves nested paths by longest prefix", () => {
    expect(laneForPath("/findings/abc")).toBe("command");
    expect(laneForPath("/registry?id=foo")).toBe("reference");
  });

  it("exposes scope chips for every lane", () => {
    for (const lane of Object.keys(PAGE_LANE_META)) {
      expect(PAGE_LANE_META[lane as keyof typeof PAGE_LANE_META].scope.length).toBeGreaterThan(3);
    }
  });
});
