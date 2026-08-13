import { describe, expect, it } from "vitest";

import {
  findingStatusClass,
  findingStatusLabel,
  cvssVersion,
  formatFindingTimestamp,
  formatSlaDue,
  hasLifecycleMetadata,
  officialAdvisoryLinks,
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

describe("formatSlaDue", () => {
  const now = Date.parse("2026-08-10T00:00:00Z");

  it("returns null when no deadline is known", () => {
    expect(formatSlaDue(undefined, now)).toBeNull();
    expect(formatSlaDue("", now)).toBeNull();
    expect(formatSlaDue("not-a-date", now)).toBeNull();
  });

  it("renders a future deadline as a relative, non-overdue label", () => {
    const sla = formatSlaDue("2026-08-15T00:00:00Z", now);
    expect(sla).not.toBeNull();
    expect(sla?.overdue).toBe(false);
    expect(sla?.label).toBe("SLA in 5d");
  });

  it("flags a past deadline as overdue", () => {
    const sla = formatSlaDue("2026-08-07T00:00:00Z", now);
    expect(sla?.overdue).toBe(true);
    expect(sla?.label).toBe("SLA overdue 3d");
  });

  it("labels a same-day deadline as due today", () => {
    const sla = formatSlaDue("2026-08-10T00:00:00Z", now);
    expect(sla?.overdue).toBe(false);
    expect(sla?.label).toBe("SLA due today");
  });
});

describe("finding intelligence helpers", () => {
  it("reads the CVSS version only from a canonical vector prefix", () => {
    expect(cvssVersion("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")).toBe("3.1");
    expect(cvssVersion("AV:N/AC:L")).toBeNull();
    expect(cvssVersion(undefined)).toBeNull();
  });

  it("allows official HTTPS advisory links and drops untrusted references", () => {
    expect(
      officialAdvisoryLinks([
        "https://osv.dev/vulnerability/CVE-2026-0001",
        "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        "http://osv.dev/vulnerability/CVE-2026-0001",
        "https://evil.example/phishing",
      ]),
    ).toEqual([
      { label: "OSV", href: "https://osv.dev/vulnerability/CVE-2026-0001" },
      { label: "GitHub Advisory", href: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" },
      { label: "NVD", href: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" },
    ]);
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
