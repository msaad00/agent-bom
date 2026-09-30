import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) for (const width of [390, 1440]) {
  test(`trace intake preserves input and evidence scope ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 980 });
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/v1/**", (route) => route.fulfill({ json: {} }));
    await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/version", (route) => route.fulfill({ json: { version: "0.106.1" } }));
    await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
      authenticated: true, auth_required: false, configured_modes: [], recommended_ui_mode: "no_auth",
      role: "analyst", subject: "trace-fixture", auth_method: "api_key", memberships: [], tenant_id: "fixture",
      role_summary: { role: "analyst", ui_role: "analyst", display_name: "Analyst", capabilities: [] },
    } }));
    await page.route("**/v1/posture/counts", (route) => route.fulfill({ json: { has_traces: true, services: {} } }));
    let writes = 0;
    await page.route("**/v1/traces", (route) => {
      if (route.request().method() !== "POST") return route.fulfill({ json: {} });
      writes += 1;
      return route.fulfill({ json: { traces: 0, flagged: [], message: "No tool call traces found" } });
    });
    await page.goto("/traces");
    await page.getByRole("button", { name: "OTLP ingest" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Input:" })).toContainText("Bundled sample");
    expect(writes).toBe(0);
    await page.getByRole("button", { name: "Run correlation" }).click();
    await expect(page.getByText(/No tool-call evidence was parsed/)).toBeVisible();
    expect(writes).toBe(1);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath(`trace-zero-${theme}-${width}.png`), fullPage: true });
    await page.getByRole("textbox", { name: "Trace JSON payload" }).fill('{"private-secret": broken}');
    await expect(page.getByText(/No tool-call evidence was parsed/)).toHaveCount(0);
    await page.getByRole("button", { name: "Run correlation" }).click();
    const alert = page.getByRole("alert").filter({ hasText: "Trace input" });
    await expect(alert).toContainText("valid JSON");
    await expect(alert).not.toContainText("private-secret");
    expect(writes).toBe(1);
    await page.locator('input[type="file"]').setInputFiles({ name: "trace.json", mimeType: "application/json", buffer: Buffer.from('{"spans": []}') });
    await expect(page.getByRole("textbox")).toHaveValue('{"spans": []}');
    await expect(page.getByRole("status").filter({ hasText: "Input:" })).toContainText("Local file");
    expect(writes).toBe(1);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath(`trace-ready-${theme}-${width}.png`), fullPage: true });
  });
}
