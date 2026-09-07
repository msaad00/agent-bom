import { describe, expect, it } from "vitest";
import { assertCaptureSnapshotScope } from "../scripts/product-proof-scope.mjs";

const gallery = "scan-proof-ai-platform";
const reference = "reference-evidence-correlation-v1";

describe("capture fixture snapshot scope", () => {
  it("accepts one selected gallery snapshot without comparing differently scoped counts", () => {
    expect(() => assertCaptureSnapshotScope(`http://fixture/v1/graph/rollup?scan_id=${gallery}`, gallery, [gallery])).not.toThrow();
    expect(() => assertCaptureSnapshotScope(`http://fixture/comparison?scan_id=${gallery}`, gallery, [gallery, gallery])).not.toThrow();
  });

  it.each([
    [`http://fixture/rollup?scan_id=${reference}`, [gallery]],
    ["http://fixture/rollup", [gallery]],
    [`http://fixture/rollup?scan_id=${gallery}`, [reference]],
    [`http://fixture/comparison?scan_id=${gallery}`, [gallery, reference]],
    [`http://fixture/rollup?scan_id=${gallery}`, []],
  ])("rejects unsupported requests or mismatched response/base identity: %s", (url, responseIds) => {
    expect(() => assertCaptureSnapshotScope(url, gallery, responseIds)).toThrow("Capture fixture snapshot scope mismatch");
  });
});
