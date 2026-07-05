import { describe, expect, it } from "vitest";

import {
  findingStatusClass,
  findingStatusLabel,
  formatFindingTimestamp,
  hasLifecycleMetadata,
  type EnrichedVuln,
} from "@/lib/findings-view";

function sampleVuln(overrides: Partial<EnrichedVuln> = {}): EnrichedVuln {
  return {
    id: "CVE-2026-0001",
    severity: "high",
    packages: ["requests"],
    agents: [],
    sources: [],
    affected_servers: [],
    exposed_credentials: [],
    reachable_tools: [],
    references: [],
    advisory_sources: [],
    remediation_items: [],
    ...overrides,
  };
}

describe("findings lifecycle helpers", () => {
  it("formats ISO timestamps for table display", () => {
    const formatted = formatFindingTimestamp("2026-07-01T12:00:00Z");
    expect(formatted).not.toBe("—");
    expect(formatted).toContain("2026");
  });

  it("labels lifecycle status values", () => {
    expect(findingStatusLabel("open")).toBe("open");
    expect(findingStatusLabel("resolved")).toBe("resolved");
    expect(findingStatusClass("reopened")).toContain("orange");
  });

  it("detects lifecycle metadata on enriched rows", () => {
    expect(hasLifecycleMetadata([sampleVuln()])).toBe(false);
    expect(hasLifecycleMetadata([sampleVuln({ lifecycle_status: "open", last_seen: "2026-07-01T00:00:00Z" })])).toBe(true);
  });
});
