import { describe, expect, it } from "vitest";

import { resolveSnapshotAttackPathCount } from "@/lib/graph-snapshot-metrics";

describe("resolveSnapshotAttackPathCount", () => {
  it("prefers the persisted snapshot total over the bounded path page", () => {
    expect(
      resolveSnapshotAttackPathCount({
        pageTotal: 2_155,
        statsTotal: 2_155,
        returnedPaths: 75,
      }),
    ).toBe(2_155);
  });

  it("falls back through graph stats to returned rows", () => {
    expect(
      resolveSnapshotAttackPathCount({
        pageTotal: null,
        statsTotal: 820,
        returnedPaths: 75,
      }),
    ).toBe(820);
    expect(
      resolveSnapshotAttackPathCount({
        pageTotal: null,
        statsTotal: null,
        returnedPaths: 18,
      }),
    ).toBe(18);
  });
});
