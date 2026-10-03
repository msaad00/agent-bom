import { test, expect } from "@playwright/test";

for (const theme of ["light", "dark"] as const) {
  test(`component relationships preserve evidence and scope in ${theme}`, async ({ page }, testInfo) => {
    const broadFindingRequests: string[] = [];
    await page.setViewportSize({ width: 1440, height: 1100 });
    await page.emulateMedia({ colorScheme: theme });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const scan = "component-context-fixture";
    const asset = { id: "package:shared", type: "package", name: "shared-library", severity: "high", risk_score: 0,
      status: "active", source: "lockfile", sources: ["lockfile"], attributes: { owner: "platform" },
      compliance_tags: [], ecosystem: "pypi", version: "1.0.0", first_seen: "2026-09-01T00:00:00Z", last_seen: "2026-10-01T00:00:00Z",
      finding_summary: { total: 1, ids: ["finding:one"], by_severity: { high: 1 }, top_severity: "high" }, relationship_count: 2 };
    const completeness = { status: "complete", complete: true, sampled: false, truncated: false, returned: 1, total: 1 };
    const facets = Object.fromEntries(["type", "source", "provider", "environment", "severity"].map(key => [key, { buckets: [] }]));
    const metadata = { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: scan };
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/version", route => route.fulfill({ json: { version: "0.107.2" } }));
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/findings" || url.pathname.startsWith("/v1/compliance")) broadFindingRequests.push(url.href);
      if (url.pathname === "/v1/graph/incident-edges") {
        expect(url.searchParams.get("scan_id")).toBe(scan);
        expect(url.searchParams.get("node_id")).toBe(asset.id);
        return route.fulfill({ json: { scan_id: scan, snapshot_generation: "a".repeat(32), node_id: asset.id, found: true,
          direction: "both", limit: 24, node: { id: asset.id, label: asset.name, entity_type: "package", attributes: {} },
          nodes: [{ id: "finding:one", label: "Dependency vulnerability", entity_type: "vulnerability", severity: "high", attributes: {}, compliance_tags: ["NIST-RA-5"] }],
          edges: [{ source: asset.id, target: "finding:one", relationship: "vulnerable_to", direction: "directed" }], next_cursor: null, completeness,
        } });
      }
      if (url.pathname.startsWith("/v1/auth/")) return route.fulfill({ json: { authenticated: true, auth_required: true, role: "analyst", tenant_id: "fixture", permissions: ["read"] } });
      if (url.pathname.endsWith("/inventory/summary")) return route.fulfill({ json: {
        schema_version: "inventory.summary.v1", tenant_id: "fixture", scan_id: scan, total_assets: 1, by_type: { package: 1 }, by_group: { code: 1 },
        finding_count: 1, filters: { type: ["package"] }, facets, facet_metadata: metadata, completeness,
      } });
      if (url.pathname.endsWith("/inventory/assets")) return route.fulfill({ json: {
        schema_version: "inventory.assets.v1", tenant_id: "fixture", scan_id: scan, assets: [asset], filters: {},
        pagination: { total: 1, offset: 0, limit: 100, next_cursor: "", has_more: false, facet_filtered: false }, facets, facet_metadata: metadata, completeness,
      } });
      if (url.pathname.includes("/inventory/assets/")) {
        expect(url.searchParams.get("scan_id")).toBe(scan);
        return route.fulfill({ json: { schema_version: "inventory.asset.v1", tenant_id: "fixture", scan_id: scan,
          snapshot_generation: "a".repeat(32), next_cursor: null, asset, node: { id: asset.id },
          nodes: [{ id: "container:app", label: "Application container" }, { id: "finding:one", label: "Dependency vulnerability" }],
          edges_in: [{ source: "container:app", target: asset.id, relationship: "contains", direction: "directed", source_scan_id: scan }],
          edges_out: [{ source: asset.id, target: "finding:one", relationship: "vulnerable_to", direction: "directed" }],
          sources: ["container:app"], neighbors: ["finding:one"], evidence_sources: ["lockfile"], impact: {}, impact_status: "not_evaluated", completeness,
        } });
      }
      return route.fulfill({ status: 503, json: { detail: "Outside component fixture" } });
    });
    await page.goto(`/inventory/packages?scan=${scan}`);
    await page.getByText("shared-library", { exact: true }).click();
    const relationships = page.getByRole("list", { name: "Recorded component relationships" });
    await expect(relationships.getByText("Parent · contains")).toBeVisible();
    await expect(relationships.getByRole("link", { name: "Application container" })).toHaveAttribute("href", `/security-graph?lens=estate&node=container%3Aapp&scan=${scan}`);
    await expect(page.getByText(/Collection coverage and blast radius are not assessed/)).toBeVisible();
    await expect(page.getByText("Impact fields")).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath(`component-context-${theme}.png`), fullPage: true, animations: "disabled" });
    await page.getByRole("link", { name: "Findings Recorded component evidence" }).click();
    await expect(page).toHaveURL(url => url.searchParams.get("asset") === asset.id && url.searchParams.get("scan") === scan);
    await expect(page.getByRole("list", { name: "Component finding records" }).getByText("Dependency vulnerability")).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`component-findings-${theme}.png`), animations: "disabled" });
    await page.getByRole("link", { name: "Inspect control evidence" }).click();
    await expect(page).toHaveURL(url => url.pathname === "/compliance" && url.searchParams.get("asset") === asset.id && url.searchParams.get("scan") === scan);
    await expect(page.getByRole("list", { name: "Component control records" }).getByText("NIST-RA-5")).toBeVisible();
    await expect(page.getByText("Mapped · Not evaluated", { exact: true })).toBeVisible();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`component-compliance-${theme}.png`), animations: "disabled" });
    expect(broadFindingRequests).toEqual([]);
  });
}
