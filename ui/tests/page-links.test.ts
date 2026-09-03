import { describe, expect, it } from "vitest";

import {
  complianceHref,
  findingsHref,
  graphLayerHref,
  remediationHref,
  securityGraphHref,
} from "@/lib/page-links";

describe("typed page links", () => {
  it("uses only query keys consumed by each destination", () => {
    expect(findingsHref({ q: "finding 1", scan: "scan/1" })).toBe(
      "/findings?q=finding+1&scan=scan%2F1",
    );
    expect(securityGraphHref({ cve: "CVE-2026-1", finding: "finding/1" })).toBe(
      "/security-graph?lens=attack-path&cve=CVE-2026-1&finding=finding%2F1",
    );
    expect(complianceHref({ scan: "scan/1" })).toBe("/compliance?scan=scan%2F1");
    expect(remediationHref({ q: "AC-2", scan: "corr-output" })).toBe(
      "/remediation?q=AC-2&scan=corr-output",
    );
    expect(
      remediationHref({
        correlation: "corr/1",
        scan: "corr/1",
        finding: "finding/1",
        cve: "CVE-2023-4863",
        packageName: "pillow",
        path: "source::target::source->target",
      }),
    ).toBe(
      "/remediation?correlation=corr%2F1&scan=corr%2F1&finding=finding%2F1&cve=CVE-2023-4863&package=pillow&path=source%3A%3Atarget%3A%3Asource-%3Etarget",
    );
    expect(
      securityGraphHref({
        scan: "corr/1",
        cve: "CVE-2023-4863",
        path: "source::target::source->target",
      }),
    ).toBe(
      "/security-graph?lens=attack-path&scan=corr%2F1&cve=CVE-2023-4863&path=source%3A%3Atarget%3A%3Asource-%3Etarget",
    );
  });

  it("maps observed lineage entity kinds to supported graph layers", () => {
    expect(graphLayerHref("server")).toBe("/graph?layers=server");
    expect(graphLayerHref("service_account")).toBe("/graph?layers=serviceAccount");
    expect(graphLayerHref("unknown-kind")).toBe("/graph");
  });

  it("drops blank values instead of creating misleading empty filters", () => {
    expect(findingsHref({ q: "  ", scan: "" })).toBe("/findings");
    expect(securityGraphHref({ packageName: "requests", agent: undefined })).toBe(
      "/security-graph?lens=attack-path&package=requests",
    );
  });
});
