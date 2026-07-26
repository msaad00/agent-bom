import { describe, expect, it } from "vitest";

import type { FindingTriageItem } from "@/lib/api";
import type { FindingFacets } from "@/lib/api-types";
import type { EnrichedVuln } from "@/lib/findings-view";
import {
  buildComplianceMetrics,
  buildEngineeringMetrics,
  controlLabels,
  findingTriageKey,
} from "@/lib/findings-workspace";

function finding(overrides: Partial<EnrichedVuln> = {}): EnrichedVuln {
  return {
    id: "CVE-2026-0001",
    severity: "high",
    packages: ["pkg-a"],
    agents: ["agent-a"],
    sources: ["osv"],
    affected_servers: [],
    exposed_credentials: [],
    reachable_tools: [],
    references: [],
    advisory_sources: [],
    remediation_items: [],
    ...overrides,
  };
}

const facets: FindingFacets = {
  finding_class: { vulnerability: 9, misconfiguration: 2, secret: 1, identity: 0, unclassified: 1 },
  severity: { critical: 2, high: 7, medium: 3, low: 1, info: 0, unknown: 0 },
  status: { open: 12, resolved: 1 },
  domain: { cspm: 2, vuln: 9, aspm: 1, dspm: 0, aispm: 1 },
  freshness: { last_24_hours: 2, last_7_days: 3, last_30_days: 4, older: 1, unavailable: 3 },
};

function triage(overrides: Partial<FindingTriageItem> = {}): FindingTriageItem {
  return {
    id: "triage-1",
    vulnerability_id: "CVE-2026-0001",
    package: "pkg-a",
    server_name: "",
    queue_state: "decided",
    decision: "not_affected",
    decision_reason: "Not in the execution path",
    assignee: "appsec",
    created_by: "operator",
    created_at: "2026-07-20T00:00:00Z",
    reviewed_at: "2026-07-21T00:00:00Z",
    expires_at: "2026-08-20T00:00:00Z",
    tenant_id: "tenant-test",
    vex_eligible: true,
    ...overrides,
  };
}

describe("findings persona summaries", () => {
  it("keeps server facet facts query-scoped and page-derived facts explicit", () => {
    const row = finding({ graph_reachable: true, epss_score: 0.42, fixed_version: "2.0.0" });
    const triageByKey = new Map([[findingTriageKey(row.id, "pkg-a"), triage()]]);

    const metrics = buildEngineeringMetrics([row], triageByKey, facets);
    expect(metrics[0]).toMatchObject({
      label: "Evidence freshness",
      value: "5 observed ≤7d",
      scope: "query",
    });
    expect(metrics.slice(1).every((metric) => metric.scope === "page")).toBe(true);
  });

  it("does not turn absent compliance or freshness evidence into factual zero", () => {
    const metrics = buildComplianceMetrics([finding()], new Map(), null);
    expect(metrics[0]).toMatchObject({ value: "Unavailable", unavailable: true, scope: "query" });
    expect(metrics.find((metric) => metric.label === "Control mapping")).toMatchObject({
      value: "Unavailable",
      unavailable: true,
      scope: "page",
    });
    expect(metrics.find((metric) => metric.label === "Disposition")).toMatchObject({
      value: "Unavailable",
      unavailable: true,
    });
  });

  it("reads typed controls as well as framework tags", () => {
    expect(
      controlLabels(
        finding({
          framework_tags: ["SOC2-CC7.1"],
          controls: [{ control_id: "NIST-RA-5" }, { name: "OWASP-A06" }, { ignored: true }],
        }),
      ),
    ).toEqual(["SOC2-CC7.1", "NIST-RA-5", "OWASP-A06"]);
  });
});
