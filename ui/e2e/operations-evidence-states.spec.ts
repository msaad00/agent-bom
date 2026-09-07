import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) {
  test(`partial Operations evidence remains honest and retryable in ${theme}`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.addInitScript((mode) => localStorage.setItem("agent-bom-theme", mode), theme);
    await page.route("**/v1/**", (route) => route.fulfill({ json: {} }));
    await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/version", (route) => route.fulfill({ json: { version: "0.103.2" } }));
    await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
      authenticated: true, auth_required: false, configured_modes: [], recommended_ui_mode: "no_auth",
      role: "admin", subject: null, auth_method: null, memberships: [], tenant_id: "fixture",
      role_summary: { role: "admin", ui_role: "admin", display_name: "Admin", capabilities: ["policy.manage"] },
    } }));
    await page.route("**/v1/observability/costs", (route) => route.fulfill({ json: {
      total_cost_usd: 12.5, total_calls: 2, total_input_tokens: 100, total_output_tokens: 50,
      unpriced_calls: 0, by_agent: [], by_model: [], by_provider: [], budget: { configured: false },
    } }));
    let failed = true;
    await page.route("**/v1/observability/anomalies", (route) => failed
      ? route.fulfill({ status: 503, json: { detail: "Unavailable" } })
      : route.fulfill({ json: { anomaly_count: 0, cost_anomalies: [], behavior_anomalies: [] } }));
    await page.route("**/v1/observability/costs/forecast", (route) => route.fulfill({ status: 503, json: { detail: "Unavailable" } }));
    await page.goto("/cost");
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await expect(page.getByText("Anomaly analysis unavailable", { exact: true })).toBeVisible();
    await expect(page.getByText("Forecast unavailable. Refresh to retry.")).toBeVisible();
    await expect(page.getByTestId("cost-kpi-strip")).toContainText("$12.5");
    failed = false;
    await page.getByRole("button", { name: "Refresh cost data" }).click();
    await expect(page.getByText("Anomaly analysis unavailable", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: /Cost & behavior anomalies/ }).click();
    await expect(page.getByText(/No statistical anomalies detected/)).toBeVisible();
    await page.screenshot({ path: `/private/tmp/operations-evidence-${theme}-cost.png`, fullPage: true });

    await page.route("**/v1/webhooks?**", (route) => route.fulfill({ json: { subscriptions: [], event_catalog: [], count: 0 } }));
    await page.route("**/v1/posture/webhooks/outbox?**", (route) => route.fulfill({ status: 503, json: { detail: "Unavailable" } }));
    await page.goto("/integrations");
    await expect(page.getByText("Delivery telemetry unavailable", { exact: true })).toBeVisible();
    await expect(page.getByText("Unavailable", { exact: true })).toHaveCount(3);
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.locator("#main-content")).toHaveCSS("padding-left", "0px");
    await expect(page.getByText("Delivery telemetry unavailable", { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: `/private/tmp/operations-evidence-${theme}-webhooks-mobile.png`, fullPage: true });
  });
}
