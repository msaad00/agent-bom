import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const source = readFileSync(
  resolve(__dirname, "../components/lineage-nodes.tsx"),
  "utf8",
);

describe("lineage node labels", () => {
  it("wraps long asset names instead of clipping them to one line", () => {
    // Estate names are long by nature -- GCS_SERVICE_ACCOUNT_JSON,
    // data: customer-pii-prod. Clipped to a single 180px line they render as
    // "GCS_SERVICE_ACC..." and the node stops identifying anything. The grid
    // has vertical slack and no horizontal slack, so the label takes a second
    // line rather than a wider node.
    // Neither the detailed node nor the rolled-up summary node may clip.
    expect(source).not.toMatch(/flex-1 truncate/);
    expect(source.match(/line-clamp-2/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
  });
});
