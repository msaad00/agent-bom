import { describe, expect, it } from "vitest";

import { runtimeEvidenceTierAttr } from "@/lib/unified-graph-flow";

describe("runtimeEvidenceTierAttr", () => {
  it("maps graph overlay evidence tiers", () => {
    expect(
      runtimeEvidenceTierAttr({ evidence_tier: "runtime_blocked" }),
    ).toBe("runtime_blocked");
    expect(
      runtimeEvidenceTierAttr({ evidence_tier: "runtime_observed" }),
    ).toBe("runtime_observed");
    expect(runtimeEvidenceTierAttr({ evidence_tier: "static_scan" })).toBe(
      "static_scan",
    );
  });

  it("ignores redaction-only tiers", () => {
    expect(runtimeEvidenceTierAttr({ evidence_tier: "replay_only" })).toBe(
      undefined,
    );
    expect(runtimeEvidenceTierAttr({ evidence_tier: "safe_to_store" })).toBe(
      undefined,
    );
  });
});
