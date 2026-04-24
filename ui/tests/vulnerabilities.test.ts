import { describe, expect, it } from "vitest";

import { getOsvVulnerabilityUrl } from "@/lib/vulnerabilities";

describe("getOsvVulnerabilityUrl", () => {
  it("builds OSV URLs for strict CVE identifiers", () => {
    expect(getOsvVulnerabilityUrl("CVE-2026-12345")).toBe("https://osv.dev/vulnerability/CVE-2026-12345");
  });

  it("rejects labels that are not vulnerability identifiers", () => {
    expect(getOsvVulnerabilityUrl("CVE-2026-12345/../../session")).toBeNull();
    expect(getOsvVulnerabilityUrl("javascript:alert(1)")).toBeNull();
    expect(getOsvVulnerabilityUrl("")).toBeNull();
  });
});
