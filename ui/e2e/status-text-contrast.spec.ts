import { expect, test, type Locator, type Page } from "@playwright/test";

// Browser-computed colors include each translucent ancestor surface.
async function readable(target: Locator) {
  await expect(target).toBeVisible();
  await target.scrollIntoViewIfNeeded();
  const result = await target.evaluate(node => {
    const ctx = document.createElement("canvas").getContext("2d")!;
    const rgba = (color: string) => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = color; ctx.fillRect(0, 0, 1, 1); return [...ctx.getImageData(0, 0, 1, 1).data]; };
    const over = (front: number[], back: number[]) => back.map((v, i) => front[i]! * front[3]! / 255 + v * (1 - front[3]! / 255));
    const lum = (rgb: number[]) => rgb.map(v => { const c = v / 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; }).reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i]!, 0);
    const ancestors: Element[] = [];
    for (let el: Element | null = node; el; el = el.parentElement) ancestors.unshift(el);
    let background = [255, 255, 255];
    for (const el of ancestors) background = over(rgba(getComputedStyle(el).backgroundColor), background);
    const foreground = over(rgba(getComputedStyle(node).color), background);
    const a = lum(foreground), b = lum(background);
    return { text: node.textContent, foreground, background, ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) };
  });
  expect.soft(result.ratio, JSON.stringify(result)).toBeGreaterThanOrEqual(4.5);
}

async function fixture(page: Page) {
  await page.route("**/v1/**", route => route.fulfill({ status: 503, json: { detail: "Not configured in the contrast fixture" } }));
  await page.route("**/v1/auth/me", route => route.fulfill({ json: { authenticated: true, role: "analyst", tenant_id: "contrast-fixture", permissions: ["read"] } }));
  const bands = { critical: 4, high: 13, medium: 5, low: 1, unrated: 0, total: 23 };
  await page.route("**/v1/posture/counts", route => route.fulfill({ json: { ...bands, scan_count: 1, services: {} } }));
  await page.route("**/v1/overview", route => route.fulfill({ json: { schema_version: "overview.v1", tenant_id: "contrast-fixture", posture: { grade: "F", score: 37, summary: "Prioritize current findings." }, headline: { ...bands, scans: 1, critical_high: 17, kev: 0 }, coverage: [], domains: Object.fromEntries(["cloud", "vuln", "code", "runtime", "cost", "identity", "ops"].map(key => [key, { label: key, metric: 1, metric_label: "fixture", href: "/", status: "ok", detail: {} }])), top_risks: [] } }));
  await page.route("**/v1/jobs", route => route.fulfill({ json: { jobs: [] } }));
  const facets = Object.fromEntries(["type", "source", "provider", "environment", "severity"].map(key => [key, { buckets: [{ value: key === "type" ? "package" : key === "severity" ? "critical" : "fixture", count: key === "severity" ? 1 : 4 }] }]));
  const completeness = { status: "complete", complete: true, sampled: false, truncated: false, returned: 4, total: 4 };
  const metadata = { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: "fixture" };
  await page.route("**/v1/inventory/summary**", route => route.fulfill({ json: { schema_version: "inventory.summary.v1", tenant_id: "contrast-fixture", scan_id: "fixture", total_assets: 4, finding_count: 4, by_type: { package: 4 }, by_group: { code: 4 }, facets, facet_metadata: metadata, completeness } }));
  await page.route("**/v1/inventory/assets**", route => route.fulfill({ json: {
    schema_version: "inventory.assets.v1", tenant_id: "contrast-fixture", scan_id: "fixture", filters: {}, facets, facet_metadata: metadata, completeness,
    pagination: { total: 4, offset: 0, limit: 100, next_cursor: null, has_more: false, facet_filtered: false },
    assets: ["critical", "high", "medium", "low"].map(severity => ({ id: `pkg:${severity}`, type: "package", name: `fixture-${severity}`, severity, sources: ["fixture"], source: "fixture", attributes: {}, compliance_tags: [], relationship_count: 0, finding_summary: { total: 1, top_severity: severity, by_severity: { [severity]: 1 }, ids: [] } })),
  } }));
  await page.route("**/v1/inventory/assets/*", route => {
    const id = decodeURIComponent(new URL(route.request().url()).pathname.split("/").at(-1)!);
    const severity = id.replace("pkg:", "");
    return route.fulfill({ json: {
      schema_version: "inventory.asset.v1", tenant_id: "contrast-fixture",
      asset: { id, type: "package", name: `fixture-${severity}`, severity, attributes: {} },
      node: { id, entity_type: "package", label: `fixture-${severity}`, attributes: {} },
      edges_in: [], edges_out: [], neighbors: [], sources: [], impact: {}, completeness,
    } });
  });
  const keys = ["owasp_llm_top10", "owasp_mcp_top10", "mitre_atlas", "nist_ai_rmf", "owasp_agentic_top10", "eu_ai_act", "nist_csf", "iso_27001", "soc2", "cis_controls", "cmmc", "nist_800_53", "fedramp", "pci_dss"];
  await page.route("**/v1/compliance", route => route.fulfill({ json: { overall_score: 25, overall_status: "fail", evaluated_controls: 4, total_controls: 4, coverage_pct: 100, scan_count: 1, framework_kinds: {}, summary: {}, ...Object.fromEntries(keys.map(key => [key, []])), aisvs_benchmark: { checks: [], summary: {} } } }));
  await page.route("**/v1/compliance/nist-800-53**", route => route.fulfill({ json: { framework: "nist-800-53", framework_key: "nist_800_53_catalog", framework_label: "NIST SP 800-53 Rev 5", representation: "catalog", source: "fixture", vendor_asserted: true, status: "fail", score: 25, summary: { pass: 1, fail: 1, warning: 1, error: 1, evaluated: 4, not_evaluated: 0, catalog_size: 4, coverage_pct: 100, score: 25 }, families: [], controls: [], iso_27001_derived: { source: "fixture", note: "Synthetic contrast fixture", controls: [] } } }));
}

for (const theme of ["light", "dark"] as const) test.describe(theme, () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(t => localStorage.setItem("agent-bom-theme", t), theme);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await fixture(page);
  });
  test("overview severity and enabled primary action contrast", async ({ page }) => {
    await page.goto("/");
    for (const [label, value] of [["Critical", "4"], ["High", "13"], ["Medium", "5"], ["Low", "1"]]) {
      const link = page.getByRole("link", { name: new RegExp(`^${label} ${value}`) });
      await readable(link.getByText(value!, { exact: true }));
      await link.focus();
      await expect(link).toBeFocused();
      await readable(link.getByText(value!, { exact: true }));
    }
    const action = page.locator('main a[href="/compliance"]').filter({ hasText: /^Compliance/ }).first();
    await readable(action);
    await action.hover();
    await readable(action);
    await action.focus();
    await expect(action).toBeFocused();
    await readable(action);
  });
  test("inventory asset context and selected severity text contrast", async ({ page }) => {
    await page.goto("/inventory");
    for (const severity of ["critical", "high", "medium", "low"]) {
      const row = page.getByRole("button", { name: new RegExp(`^fixture-${severity}`) });
      await readable(row.getByText(`fixture-${severity}`, { exact: true }));
      await readable(row.getByText("fixture", { exact: true }));
      await row.hover();
      await readable(row.getByText(`fixture-${severity}`, { exact: true }));
      await row.click();
      const details = page.getByRole("region", { name: "Selected asset details" });
      await expect(details.getByRole("heading", { name: `fixture-${severity}`, exact: true })).toBeVisible();
      await readable(details.getByText(severity, { exact: true }));
      await details.getByRole("button", { name: "Close asset details" }).click();
    }
  });
  test("compliance evaluated count contrast", async ({ page }) => {
    await page.goto("/compliance");
    const buckets = page.getByTestId("nist-catalog-buckets");
    for (const label of ["Pass", "Fail", "Warn", "Error"]) {
      const tile = buckets.locator(":scope > div").filter({ has: page.getByText(label, { exact: true }) });
      await readable(tile.getByText("1", { exact: true }));
    }
  });
  test("runtime selected tab contrast and focus", async ({ page }) => {
    await page.goto("/runtime");
    for (const label of ["Proxy", "Gateway"]) {
      const tab = page.getByRole("tab", { name: label, exact: true });
      await tab.focus();
      await page.keyboard.press("Enter");
      await expect(tab).toHaveAttribute("aria-selected", "true");
      await expect(tab).toBeFocused();
      await readable(tab);
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await readable(page.getByRole("tab", { name: "Gateway", exact: true }));
  });
});
