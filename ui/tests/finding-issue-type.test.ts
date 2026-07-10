import { describe, expect, it } from "vitest";

import { classifyFindingIssueType, matchesIssueTypeFilter } from "@/lib/finding-issue-type";
import type { EnrichedVuln } from "@/lib/findings-view";

function sample(partial: Partial<EnrichedVuln>): EnrichedVuln {
  return {
    id: "CVE-2024-0001",
    severity: "high",
    packages: [],
    agents: [],
    sources: [],
    affected_servers: [],
    exposed_credentials: [],
    reachable_tools: [],
    references: [],
    advisory_sources: [],
    remediation_items: [],
    ...partial,
  };
}

describe("finding-issue-type", () => {
  it("classifies CVE findings as vulnerabilities", () => {
    expect(classifyFindingIssueType(sample({ id: "CVE-2024-0001" }))).toBe("vulnerability");
  });

  it("classifies secret scan sources as secrets", () => {
    expect(
      classifyFindingIssueType(
        sample({ id: "SECRET-1", sources: ["SECRET_SCAN"], finding_type: "CREDENTIAL_EXPOSURE" }),
      ),
    ).toBe("secret");
  });

  it("classifies CIS failures as misconfigurations", () => {
    expect(
      classifyFindingIssueType(sample({ id: "CIS-1.2", sources: ["CLOUD_CIS"], finding_type: "CIS_FAIL" })),
    ).toBe("misconfiguration");
  });

  it("filters by issue type", () => {
    const vuln = sample({ id: "CVE-2024-0001" });
    expect(matchesIssueTypeFilter(vuln, "all")).toBe(true);
    expect(matchesIssueTypeFilter(vuln, "vulnerability")).toBe(true);
    expect(matchesIssueTypeFilter(vuln, "secret")).toBe(false);
  });
});
