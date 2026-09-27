import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1440]) {
    test(`agent BOM evidence is readable and selectable: ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      const agents = ["provider:a", "provider:b"].map((id) => ({
        name: "customer-agent", canonical_id: id, stable_id: id, agent_type: "custom", mcp_servers: [],
      }));
      const result = { agents, blast_radius: [], generated_at: "2026-09-26T12:00:00Z", scan_sources: ["approved-inventory-view"],
        scan_run: { outcome: "partial", requested_scope_count: 3, complete_scope_count: 2, incomplete_scope_count: 1 } };
      const job = { job_id: "bom-fixture", status: "done", created_at: result.generated_at, progress: [], request: {}, result };
      await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
      await page.route("**/v1/**", async (route) => {
        const url = new URL(route.request().url());
        if (url.pathname === "/v1/auth/me") return route.fulfill({ json: {
          authenticated: true, auth_required: false, configured_modes: [], recommended_ui_mode: "no_auth",
          auth_method: "anonymous", role: "viewer", tenant_id: "default", memberships: [],
        } });
        if (url.pathname.endsWith("/agent-bom")) {
          expect(url.searchParams.get("agent_id")).toBe("provider:b");
          return route.fulfill({ json: { fixture: true, subject: "provider:b" } });
        }
        if (url.pathname.endsWith("/stream")) return route.fulfill({ contentType: "text/event-stream", body: 'data: {"type":"done","status":"done"}\n\n' });
        if (url.pathname.startsWith("/v1/scan/bom-fixture")) return route.fulfill({ json: job });
        return route.fulfill({ json: {} });
      });
      await page.goto("/scan?id=bom-fixture");
      const panel = page.locator('details[aria-label="Scan evidence and agent BOM"]');
      await panel.locator("summary").click();
      await expect(panel.getByText("2 of 3 requested scopes complete · 1 incomplete")).toBeVisible();
      await expect(panel.getByRole("button", { name: "Download agent BOM" })).toBeDisabled();
      await panel.getByRole("combobox").selectOption("provider:b");
      await expect(panel.getByText("provider:b", { exact: true })).toBeVisible();
      const download = page.waitForEvent("download");
      await panel.getByRole("button", { name: "Download agent BOM" }).click();
      expect((await download).suggestedFilename()).toBe("agent.bom.json");
      await panel.scrollIntoViewIfNeeded();
      expect(await panel.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
      await panel.screenshot({ path: testInfo.outputPath(`scan-evidence-${theme}-${width}.png`) });
    });
  }
}
