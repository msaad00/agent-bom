import { describe, expect, it } from "vitest";

import { buildFindingAssetHref, buildFindingInvestigationHref } from "@/lib/finding-investigation-href";
import { defaultOperatorLanding, OVERVIEW_LANDING } from "@/lib/operator-landing";

describe("buildFindingInvestigationHref", () => {
  it("pins investigation to the scan that supplied the finding", () => {
    const finding = { id: "CVE-2026-0001", packages: ["pillow@9.0.0"], agents: [], scan_id: "scan-evidence-1" };
    const params = new URL(buildFindingInvestigationHref(finding), "http://localhost").searchParams;
    expect(params.get("scan")).toBe("scan-evidence-1");
    expect(params.get("package")).toBe("pillow@9.0.0");
  });

  it("preserves occurrence provenance when a page supplies a different snapshot", () => {
    const finding = { id: "CVE-2026-0001", packages: [], agents: [], scan_id: "scan-evidence-1" };
    const params = new URL(buildFindingInvestigationHref(finding, { scanId: "scan-selected" }), "http://localhost").searchParams;
    expect(params.get("scan")).toBe("scan-evidence-1");
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

it("keeps an occurrence node identifier out of the advisory filter", () => {
  const params = new URL(buildFindingInvestigationHref({ id: "CVE-2020-14343", finding_id: "occurrence-1", finding_node_id: "vuln:demo-estate:occurrence-1", node_id: "package:exact", packages: [], agents: [] }), "http://localhost").searchParams;
  expect(params.get("cve")).toBe("CVE-2020-14343");
  expect(params.get("finding")).toBe("occurrence-1");
  expect(params.get("lens")).toBe("attack-path");
});

it("opens the exact asset neighborhood with occurrence and snapshot provenance", () => {
  const params = new URL(buildFindingAssetHref({ nodeId: "package:exact", findingId: "occurrence-1", scanId: "scan-1" }), "http://localhost").searchParams;
  expect(params.get("lens")).toBe("lineage");
  expect(params.get("investigate")).toBe("1");
  expect(params.get("root")).toBe("package:exact");
  expect(params.get("node")).toBe("package:exact");
  expect(params.get("finding")).toBe("occurrence-1");
  expect(params.get("scan")).toBe("scan-1");
});
