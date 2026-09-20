import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1024, 1440]) {
    test(`proxy reason labels stay inside their panel ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      await page.routeWebSocket("**/ws/proxy/metrics", socket => socket.close());
      await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
      await page.route("**/v1/**", route => {
        const path = new URL(route.request().url()).pathname;
        let body: unknown = {};
        if (path === "/v1/auth/me") body = { authenticated: true, auth_required: false, configured_modes: [], tenant_id: "default" };
        else if (path === "/v1/posture/counts") body = { has_proxy: true, deployment_mode: "local", scan_count: 1 };
        else if (path === "/v1/proxy/status") body = {
          status: "active", total_tool_calls: 123, total_blocked: 78, uptime_seconds: 500,
          calls_by_tool: { read_document: 82, search_catalog: 41 },
          blocked_by_reason: Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`long_policy_condition_and_external_destination_reason_${i}`, i + 1])),
        };
        else if (path === "/v1/proxy/alerts") body = { alerts: [], count: 0 };
        return route.fulfill({ json: body });
      });
      await page.goto("/runtime?tab=proxy");
      const panel = page.getByRole("heading", { name: "Block Reasons", exact: true }).locator("..");
      await expect(panel.getByText("long_policy_condition_and_external_destination_reason_11: 12", { exact: true })).toBeAttached();
      const chart = panel.locator(".recharts-responsive-container");
      await expect(chart.locator("svg")).toBeVisible();
      await expect(chart.locator("path.recharts-sector")).toHaveCount(12);
      await expect(chart.locator("path.recharts-sector").last()).toBeVisible();
      await panel.getByText("long_policy_condition_and_external_destination_reason_11: 12", { exact: true }).scrollIntoViewIfNeeded();
      const parent = await panel.boundingBox();
      const lastReason = await panel.getByText("long_policy_condition_and_external_destination_reason_11: 12", { exact: true }).boundingBox();
      expect(parent).not.toBeNull();
      expect(lastReason).not.toBeNull();
      expect(lastReason!.y + lastReason!.height).toBeLessThanOrEqual(parent!.y + parent!.height);
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`proxy-${theme}-${width}.png`), fullPage: true });
    });
  }
}
