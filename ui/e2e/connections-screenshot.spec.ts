import { expect, test, type Page } from "@playwright/test";

// Screenshot-only spec for the cloud connections plane. Mocks the connections
// API so the page renders with real-looking data without a live backend.

const CONNECTION = {
  id: "conn-1",
  tenant_id: "default",
  provider: "aws",
  display_name: "Production account",
  role_ref: "arn:aws:iam::123456789012:role/agent-bom-readonly",
  has_external_id: true,
  regions: ["us-east-1", "us-west-2"],
  status: "active",
  status_detail: "",
  created_at: "2026-06-27T00:00:00Z",
  updated_at: "2026-06-27T01:00:00Z",
  last_scan_at: "2026-06-27T01:00:00Z",
  scan_interval_minutes: 60,
};

const PENDING = {
  ...CONNECTION,
  id: "conn-2",
  display_name: "Staging account",
  status: "pending",
  last_scan_at: null,
  regions: ["eu-west-1"],
  scan_interval_minutes: null,
};

async function routeConnections(page: Page) {
  await page.route("**/health", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ status: "ok", version: "0.98.1" }) }),
  );
  await page.route("**/version", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ version: "0.98.1" }) }),
  );
  await page.route("**/v1/auth/me", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        authenticated: true,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: "anonymous",
        subject: null,
        role: "analyst",
        role_summary: {
          role: "analyst",
          ui_role: "contributor",
          display_name: "Contributor",
          description: "Synthetic browser-test role",
          capabilities: ["inventory.read", "scan.run", "sources.manage"],
          capability_matrix: [],
          can_see: [],
          can_do: [],
          cannot_do: [],
        },
        tenant_id: "default",
        memberships: [],
        request_id: "req-conn-e2e",
        trace_id: "trace-conn-e2e",
        span_id: "span-conn-e2e",
      }),
    }),
  );
  await page.route("**/v1/posture/counts", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ critical: 0, high: 0, medium: 0, low: 0, total: 0, kev: 0, compound_issues: 0 }),
    }),
  );
  await page.route("**/v1/cloud/connections", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema_version: "cloud.connections.v1",
        tenant_id: "default",
        connections: [CONNECTION, PENDING],
        count: 2,
      }),
    }),
  );
  await page.route("**/v1/sources", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema_version: "sources.v1",
        tenant_id: "default",
        sources: [],
        count: 0,
      }),
    }),
  );
  // The Sources segment also loads connector / schedule / provider state.
  await page.route("**/v1/connectors", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ connectors: [] }) }),
  );
  await page.route("**/v1/schedules", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify([]) }),
  );
  await page.route("**/v1/discovery/providers", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        contract_version: "1",
        entrypoints_enabled: false,
        provider_count: 0,
        warnings: [],
        providers: [],
      }),
    }),
  );
}

test("captures connections page and wizard", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await routeConnections(page);

  await page.goto("/connections");
  await page.waitForLoadState("networkidle");
  // Established estates open their recorded sources first.
  await expect(page.getByRole("heading", { name: "Connections" })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Sources/ })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: /Add source/ }).click();
  await expect(page.getByRole("button", { name: "Connect Amazon Web Services" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("connections-page.png"), fullPage: true });
  // Also write a stable copy under the worktree for reporting.
  await page.screenshot({ path: ".screenshots/connections-page.png", fullPage: true });

  // Sources segment shows the unified table merging cloud connections + sources.
  await page.getByRole("tab", { name: /Sources/ }).click();
  await expect(page.getByText("Production account")).toBeVisible();
  await expect(page.getByText("Staging account")).toBeVisible();
  await page.screenshot({ path: ".screenshots/connections-sources.png", fullPage: true });

  // Open the wizard and walk to the details step.
  await page.getByRole("button", { name: "Add cloud account" }).click();
  const dialog = page.getByRole("dialog", { name: "Add cloud account" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Next", exact: true }).click();
  const setupExternalId = (await dialog.getByTestId("wizard-external-id").textContent())?.trim();
  expect(setupExternalId).toMatch(/^[a-f0-9]{32}$/);
  await dialog.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByText("Read-only connection · step 3 of 4")).toBeVisible();
  await dialog.getByPlaceholder("Production account").fill("Production account");
  await dialog.getByPlaceholder(/arn:aws:iam/).fill("arn:aws:iam::123456789012:role/agent-bom-readonly");
  await expect(dialog.getByTestId("wizard-external-id-details")).toHaveText(setupExternalId!);
  await dialog.getByPlaceholder("us-east-1, us-west-2").fill("us-east-1, us-west-2");
  await expect(dialog.getByText("A display name is required.")).toHaveCount(0);
  await page.screenshot({ path: ".screenshots/connections-wizard.png" });
});

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    test(`source-first workspace and readable catalog ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await routeConnections(page);
      await page.goto("/connections");
      const sourcesTab = page.getByRole("tab", { name: /Sources/ });
      await expect(sourcesTab).toHaveAttribute("aria-selected", "true");
      await expect(page.getByRole("table")).toBeVisible();
      await expect(page.getByText("Production account", { exact: true })).toBeVisible();
      const table = await page.getByRole("table").boundingBox();
      expect(table!.y).toBeLessThan(width === 390 ? 760 : 620);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      const connectionButton = page.getByRole("button", { name: "Production account", exact: true });
      await connectionButton.click();
      const drawer = page.getByRole("dialog", { name: "Production account" });
      await expect(drawer.getByRole("region", { name: "Recorded connection configuration" })).toBeVisible();
      await expect(drawer.getByText("AWS AssumeRole", { exact: true })).toBeVisible();
      await expect(drawer.getByText("Every 60 minutes", { exact: true })).toBeVisible();
      await drawer.getByText("Capability evidence", { exact: true }).click();
      await expect(drawer.getByText("Not reported by this connection record", { exact: true })).toBeVisible();
      await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
      // The slide-over can still be entering when the font-size reflow runs.
      // Keep the overflow check, but let the transform settle before measuring.
      await expect.poll(() => drawer.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
      const titleBounds = await drawer.getByRole("heading", { name: "Production account", exact: true }).boundingBox();
      const drawerBounds = await drawer.locator("aside").boundingBox();
      expect(titleBounds!.width).toBeGreaterThan(drawerBounds!.width * 0.6);
      expect(titleBounds!.height).toBeLessThan(120);
      await page.screenshot({ path: testInfo.outputPath(`connection-evidence-${theme}-${width}.png`), fullPage: true });
      await page.keyboard.press("Escape");
      await expect(drawer).toHaveCount(0);
      await expect(connectionButton).toBeFocused();
      await page.evaluate(() => { document.documentElement.style.fontSize = ""; });
      await sourcesTab.focus();
      await page.keyboard.press("Home");
      const addTab = page.getByRole("tab", { name: /Add source/ });
      await expect(addTab).toHaveAttribute("aria-selected", "true");
      await expect(addTab).toBeFocused();
      await expect(page.getByRole("button", { name: "Connect Amazon Web Services" })).toBeVisible();
      const label = page.getByText("Amazon Web Services", { exact: true });
      expect(await label.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`source-catalog-${theme}-${width}.png`), fullPage: true });
      await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });
  }
}

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    for (const provider of ["gcp", "snowflake"] as const) test(`advertised ${provider} workload binding wizard ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await routeConnections(page);
      await page.route("**/v1/cloud/connections", route => route.fulfill({ json: {
        connections: [], count: 0, workload_auth_modes: { [provider]: ["workload_identity"] },
      } }));
      await page.goto("/connections");
      await page.getByRole("button", { name: "Add cloud account" }).click();
      const wizard = page.getByRole("dialog", { name: "Add cloud account" });
      await wizard.getByRole("button", { name: provider === "gcp" ? /Google Cloud/ : /Snowflake/ }).click();
      await expect(wizard.getByRole("combobox", { name: "Authentication method" })).toHaveValue("workload_identity");
      await wizard.getByRole("button", { name: "Next", exact: true }).click();
      await expect(wizard.getByText("Operator-managed workload binding")).toBeVisible();
      await wizard.getByRole("button", { name: "Next", exact: true }).click();
      await wizard.getByPlaceholder("Production account").fill("Bound GCP account");
      if (provider === "gcp") {
        await wizard.getByLabel("Service account email").fill("agent-bom@project.iam.gserviceaccount.com");
        await wizard.getByLabel("Project ID").fill("project");
      } else {
        await wizard.getByLabel("Account", { exact: true }).fill("account-a");
        for (const label of ["User", "Role", "Warehouse"]) await expect(wizard.getByLabel(label, { exact: true })).toHaveCount(0);
      }
      await wizard.getByLabel("Operator binding ID", { exact: true }).fill("readonly-prod");
      await expect(wizard.locator('input[type="password"], textarea')).toHaveCount(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`workload-binding-${provider}-${theme}-${width}.png`), fullPage: true });
      await page.keyboard.press("Escape");
      await expect(wizard).toHaveCount(0);
      await expect(page.getByRole("button", { name: "Add cloud account" })).toBeFocused();
    });
  }
}
