import { describe, expect, it } from "vitest";

import {
  graphEdgeChangeHeadingClass,
  graphEdgeChangeMetaClass,
  graphEdgeChangeRowClass,
} from "@/lib/graph-edge-change-tones";

describe("graphEdgeChange tones", () => {
  it("includes light and dark pairs for each lifecycle tone", () => {
    for (const tone of ["added", "removed", "changed"] as const) {
      const row = graphEdgeChangeRowClass(tone);
      expect(row).toContain("dark:");
      expect(row).toMatch(/text-(emerald|rose|amber)-800/);
      expect(graphEdgeChangeHeadingClass(tone)).toContain("dark:");
      expect(graphEdgeChangeMetaClass(tone)).toContain("dark:");
    }
  });
});
