import { describe, expect, it } from "vitest";

import { buildFindingInvestigationHref } from "@/lib/finding-investigation-href";
import { defaultOperatorLanding, OVERVIEW_LANDING } from "@/lib/operator-landing";

describe("buildFindingInvestigationHref", () => {
  it("pins investigation to the scan that supplied the finding", () => {
    const finding = { id: "CVE-2026-0001", packages: ["pillow@9.0.0"], agents: [], scan_id: "scan-evidence-1" };
    const params = new URL(buildFindingInvestigationHref(finding), "http://localhost").searchParams;
    expect(params.get("scan")).toBe("scan-evidence-1");
    expect(params.get("package")).toBe("pillow@9.0.0");
  });

  it("preserves an explicitly selected snapshot override", () => {
    const finding = { id: "CVE-2026-0001", packages: [], agents: [], scan_id: "scan-evidence-1" };
    const params = new URL(buildFindingInvestigationHref(finding, { scanId: "scan-selected" }), "http://localhost").searchParams;
    expect(params.get("scan")).toBe("scan-selected");
  });

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
      "/security-graph?lens=attack-path&node=pkg%3Apypi%2Fflask%403.0.0&cve=CVE-2026-0001&package=flask&agent=Claude+Desktop&finding=fid-1",
    );
  });
});

describe("defaultOperatorLanding", () => {
  it("uses Overview for bare and root landings while preserving explicit destinations", () => {
    expect(defaultOperatorLanding(null)).toBe(OVERVIEW_LANDING);
    expect(defaultOperatorLanding("/")).toBe(OVERVIEW_LANDING);
    expect(defaultOperatorLanding("/findings")).toBe("/findings");
    expect(defaultOperatorLanding("/security-graph?node=asset-1")).toBe(
      "/security-graph?node=asset-1",
    );
  });
});
