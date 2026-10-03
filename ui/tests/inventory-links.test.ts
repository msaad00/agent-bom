import { describe, expect, it } from "vitest";

import type { AssetRow } from "@/lib/inventory";
import { complianceHref, findingsHref, securityGraphHref } from "@/lib/inventory-links";

describe("inventory security graph links", () => {
  it("distinguishes equal component labels by canonical ID and pins the snapshot", () => {
    const first = { id: "aws:package:one", label: "shared-library" } as AssetRow;
    const second = { id: "gcp:package:one", label: "shared-library" } as AssetRow;
    expect(findingsHref(first, "scan/one")).toBe("/findings?asset=aws%3Apackage%3Aone&scan=scan%2Fone");
    expect(findingsHref(first, "scan/one")).not.toBe(findingsHref(second, "scan/one"));
  });
  it("keeps exact compliance scope even without tags", () => {
    const row = { id: "cloud:one", complianceTags: [] } as unknown as AssetRow;
    expect(complianceHref(row, "old-scan")).toBe("/compliance?asset=cloud%3Aone&scan=old-scan");
  });
  it("keeps an inventory asset on the current-state estate lens", () => {
    const row = {
      id: "cloud:aws:account:123456789012",
      label: "Production account",
    } as AssetRow;

    expect(securityGraphHref(row, "scan-123")).toBe(
      "/security-graph?lens=estate&node=cloud%3Aaws%3Aaccount%3A123456789012&scan=scan-123",
    );
  });
});
