import { describe, expect, it } from "vitest";

import {
  buildIssueSeverityMatrix,
  classifyFindingIssueType,
  classifyIssueTypeFromSignals,
  findingsHref,
  matchesIssueTypeFilter,
} from "@/lib/finding-issue-type";
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

  it("classifies blast-style signals the same way", () => {
    expect(
      classifyIssueTypeFromSignals({
        id: "CIS-4.1",
        finding_type: "CIS_FAIL",
        sources: ["CLOUD_CIS"],
      }),
    ).toBe("misconfiguration");
  });

  it("filters by issue type", () => {
    const vuln = sample({ id: "CVE-2024-0001" });
    expect(matchesIssueTypeFilter(vuln, "all")).toBe(true);
    expect(matchesIssueTypeFilter(vuln, "vulnerability")).toBe(true);
    expect(matchesIssueTypeFilter(vuln, "secret")).toBe(false);
  });

  it("builds a severity × issue-type matrix", () => {
    const matrix = buildIssueSeverityMatrix([
      { id: "CVE-1", severity: "critical" },
      { id: "CVE-2", severity: "high" },
      { id: "CIS-1", severity: "high", finding_type: "CIS_FAIL", sources: ["CLOUD_CIS"] },
      { id: "SECRET-1", severity: "critical", sources: ["SECRET_SCAN"], exposed_credentials: ["AWS_KEY"] },
      { id: "skip-me", severity: "info" },
    ]);

    expect(matrix.totals.critical).toBe(2);
    expect(matrix.totals.high).toBe(2);
    expect(matrix.vulnerability.critical).toBe(1);
    expect(matrix.vulnerability.high).toBe(1);
    expect(matrix.misconfiguration.high).toBe(1);
    expect(matrix.secret.critical).toBe(1);
    expect(matrix.byType.vulnerability).toBe(2);
    expect(matrix.openTotal).toBe(4);
  });

  it("builds findings deep links for severity and issue type", () => {
    expect(findingsHref({ severity: "critical", issue: "misconfiguration" })).toBe(
      "/findings?severity=critical&issue=misconfiguration",
    );
    expect(findingsHref({ kev: true })).toBe("/findings?kev=1");
  });
});
