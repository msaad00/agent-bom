import { describe, expect, it } from "vitest";

import { buildFindingInvestigationHref } from "@/lib/finding-investigation-href";
import { defaultOperatorLanding, SECOPS_DEFAULT_LANDING } from "@/lib/operator-landing";

describe("buildFindingInvestigationHref", () => {
  it("prefers stamped graph FKs over free-floating CVE-only links", () => {
    expect(
      buildFindingInvestigationHref({
        id: "CVE-2026-0001",
        finding_id: "fid-1",
        node_id: "pkg:pypi/flask@3.0.0",
        finding_node_id: "vuln:CVE-2026-0001",
        entity_type: "package",
        packages: ["flask"],
        agents: ["Claude Desktop"],
      }),
    ).toBe(
      "/security-graph?node=pkg%3Apypi%2Fflask%403.0.0&cve=CVE-2026-0001&package=flask&agent=Claude+Desktop&finding=fid-1",
    );
  });
});

describe("defaultOperatorLanding", () => {
  it("routes bare home to SecOps investigation", () => {
    expect(defaultOperatorLanding(null)).toBe(SECOPS_DEFAULT_LANDING);
    expect(defaultOperatorLanding("/")).toBe(SECOPS_DEFAULT_LANDING);
    expect(defaultOperatorLanding("/findings")).toBe("/findings");
  });
});
