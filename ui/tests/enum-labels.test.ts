import { describe, expect, it } from "vitest";

import { humanizeEnum } from "@/lib/enum-labels";

describe("humanizeEnum", () => {
  it.each([
    ["CIS_FAIL", "CIS fail"],
    ["SENSITIVE_DATA", "Sensitive data"],
    ["CLOUD_SECURITY", "Cloud security"],
    ["CLOUD_CIS", "Cloud CIS"],
    ["MCP_SCAN", "MCP scan"],
    ["SBOM", "SBOM"],
    ["CVE", "CVE"],
    ["CIEM_OVER_PRIVILEGE", "CIEM over privilege"],
  ])("renders %s as %s", (raw, label) => {
    expect(humanizeEnum(raw)).toBe(label);
  });

  it("leaves already-readable values alone", () => {
    expect(humanizeEnum("Package vulnerability")).toBe("Package vulnerability");
    expect(humanizeEnum("")).toBe("");
  });
});
