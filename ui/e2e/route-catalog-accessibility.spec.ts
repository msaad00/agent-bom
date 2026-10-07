import { expect, test } from "@playwright/test";
import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";
import { PRODUCT_ROUTES, routeBaseline } from "./fixtures/route-catalog";

const require = createRequire(import.meta.url);

// Allow test-only axe instrumentation without weakening the shipped CSP.
test.use({ bypassCSP: true });

for (const theme of ["light", "dark"] as const) {
  test(`all catalog routes have no serious or critical axe violations in ${theme}`, async ({ page }, testInfo) => {
    test.setTimeout(300_000);
    await routeBaseline(page);
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("console", message => {
      if (message.type() !== "error") return;
      const expectedFixtureFailure = message.location().url.includes("/v1/") && message.text().includes("503");
      if (!expectedFixtureFailure) errors.push(message.text());
    });
    const receipts = [];
    for (const route of PRODUCT_ROUTES) {
      const response = await page.goto(route, { waitUntil: "networkidle" });
      expect(response?.status(), `${route} must render its application route`).toBeLessThan(400);
      await expect(page.locator("#main-content")).toBeVisible();
      await expect(page.getByText("Application error", { exact: false })).toHaveCount(0);
      await page.addScriptTag({ path: require.resolve("axe-core/axe.min.js") });
      const result = await page.evaluate(async () => {
        const axe = (window as unknown as { axe: typeof import("axe-core") }).axe;
        const result = await axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } });
        return result.violations.filter(item => item.impact === "critical" || item.impact === "serious");
      });
      receipts.push({ route, violations: result.map(item => ({ id: item.id, impact: item.impact, description: item.description, nodes: item.nodes.map(node => ({ target: node.target, summary: node.failureSummary })) })) });
    }
    await writeFile(testInfo.outputPath(`axe-${theme}.json`), JSON.stringify({ theme, scope: "catalog routes with unavailable data fixture", errors, receipts }, null, 2));
    await page.screenshot({ path: testInfo.outputPath(`catalog-${theme}.png`), fullPage: true });
    expect(errors).toEqual([]);
    expect(receipts.filter(item => item.violations.length)).toEqual([]);
  });
}
