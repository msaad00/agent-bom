import { test, expect } from "@playwright/test";

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`unknown collection context stays qualified in ${theme} at ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.emulateMedia({ colorScheme: theme });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/agents") return route.fulfill({ json: { agents: [{
        name: "Imported agent", agent_type: "custom", status: "configured", config_path: "fixture",
        mcp_servers: [{ name: "fixture-server", transport: "stdio", command: "fixture", packages: [], tools: [], credential_env_vars: [] }],
        discovery_envelope: { envelope_version: 1, scan_mode: "future_mode", redaction_status: "unknown",
          captured_at: "invalid-capture-time", discovery_scope: ["fixture:account/example"], permissions_used: ["iam:GetRole"] },
      }], count: 1 } });
      if (path.startsWith("/v1/auth/")) return route.fulfill({ json: { authenticated: true, role: "analyst", tenant_id: "fixture", permissions: ["read"] } });
      return route.fulfill({ status: 503, json: { detail: "Outside collection context fixture" } });
    });
    await page.goto("/agents");
    await page.getByTestId("agents-configured-table").getByText("Imported agent", { exact: true }).click();
    const detail = page.getByRole("dialog");
    await expect(detail.getByText("Collection context", { exact: true })).toBeVisible();
    await expect(detail.getByText("redaction: unknown", { exact: true })).toBeVisible();
    await expect(detail.getByText(/Capture time unknown/)).toBeVisible();
    await expect(detail.getByText(/Scan ran from|Invalid Date/)).toHaveCount(0);
    await detail.getByText("Reported permissions (1)", { exact: true }).click();
    await expect(detail.getByText("iam:GetRole", { exact: true })).toBeVisible();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`collection-${theme}-${width}.png`) });
  });
}
