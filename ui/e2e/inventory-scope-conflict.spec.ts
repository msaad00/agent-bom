import { test, expect } from "@playwright/test";

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`incompatible inventory type stays empty in ${theme} at ${width}`, async ({ page }, testInfo) => {
    const inventoryRequests: URL[] = [];
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.emulateMedia({ colorScheme: theme });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/version", route => route.fulfill({ json: { version: "0.105.0" } }));
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname.startsWith("/v1/auth/")) return route.fulfill({ json: { authenticated: true, auth_required: true, role: "analyst", tenant_id: "fixture", permissions: ["read"] } });
      if (url.pathname.startsWith("/v1/inventory/")) inventoryRequests.push(url);
      return route.fulfill({ status: 503, json: { detail: "Outside inventory scope fixture" } });
    });
    await page.goto("/inventory/packages?scan=scope-fixture&type=agent&provider=aws&environment=production");
    await expect(page.getByText("No assets match these filters", { exact: true })).toBeVisible();
    await expect(page.getByText(/No packages discovered yet/i)).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Clear type filter" })).toBeVisible();
    expect(inventoryRequests).toHaveLength(0);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`inventory-scope-${theme}-${width}.png`) });
    await page.getByRole("button", { name: "Clear type filter" }).click();
    await expect.poll(() => inventoryRequests.some(url => url.pathname.endsWith("/summary"))).toBe(true);
    const summary = inventoryRequests.find(url => url.pathname.endsWith("/summary"));
    expect(summary?.searchParams.get("scan_id")).toBe("scope-fixture");
    expect(summary?.searchParams.get("type")).toBe("package");
    expect(summary?.searchParams.get("provider")).toBe("aws");
    expect(summary?.searchParams.get("environment")).toBe("production");
    await expect(page).toHaveURL(url => url.searchParams.get("scan") === "scope-fixture"
      && url.searchParams.get("provider") === "aws"
      && url.searchParams.get("environment") === "production"
      && !url.searchParams.has("type"));
  });
}
