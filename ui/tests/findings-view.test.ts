import { describe, expect, it } from "vitest";

import {
  findingStatusClass,
  findingStatusLabel,
  formatFindingTimestamp,
  hasLifecycleMetadata,
  vulnRowKey,
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

describe("vulnRowKey", () => {
  it("prefers the unique per-finding id so the same CVE keeps distinct keys", () => {
    // Same CVE label affecting two assets must yield two distinct row keys,
    // otherwise React collapses/drops rows (regression: duplicate keys).
    const a = sampleVuln({ id: "CVE-2020-14343", finding_id: "uuid-a" });
    const b = sampleVuln({ id: "CVE-2020-14343", finding_id: "uuid-b" });
    expect(vulnRowKey(a)).toBe("uuid-a");
    expect(vulnRowKey(b)).toBe("uuid-b");
    expect(vulnRowKey(a)).not.toBe(vulnRowKey(b));
  });

  it("falls back to the vulnerability id when no finding id is present", () => {
    expect(vulnRowKey(sampleVuln({ id: "CVE-2026-0001" }))).toBe("CVE-2026-0001");
  });
});
