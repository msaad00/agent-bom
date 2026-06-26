import { describe, it, expect } from "vitest";

import { fmtCount } from "@/app/gateway/GatewayFeedPanel";

describe("fmtCount — partial KPI payload guard", () => {
  it("formats present numbers with grouping", () => {
    expect(fmtCount(4485)).toBe((4485).toLocaleString());
    expect(fmtCount(0)).toBe("0");
  });

  it("degrades to an em dash for missing fields instead of throwing", () => {
    // A partial KPI payload (object present, field undefined) must not crash
    // the panel via `undefined.toLocaleString()`.
    expect(fmtCount(undefined)).toBe("—");
    expect(fmtCount(null)).toBe("—");
  });
});
