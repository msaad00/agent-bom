import { describe, expect, it } from "vitest";

import type { AssetRow } from "@/lib/inventory";
import { securityGraphHref } from "@/lib/inventory-links";

describe("inventory security graph links", () => {
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
