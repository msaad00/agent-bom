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
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ status: "ok", version: "0.90.0" }) }),
  );
  await page.route("**/version", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ version: "0.90.0" }) }),
  );
  await page.route("**/v1/auth/me", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        authenticated: true,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: null,
        role_summary: null,
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
}

test("captures connections page and wizard", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await routeConnections(page);

  await page.goto("/connections");
  await page.waitForLoadState("networkidle");
  await expect(page.getByRole("heading", { name: "Connections" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connected accounts" })).toBeVisible();
  await expect(page.getByText("Production account")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("connections-page.png"), fullPage: true });
  // Also write a stable copy under the worktree for reporting.
  await page.screenshot({ path: ".screenshots/connections-page.png", fullPage: true });

  // Open the wizard and walk to the details step.
  await page.getByRole("button", { name: "Add cloud account" }).click();
  const dialog = page.getByRole("dialog", { name: "Add cloud account" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Next", exact: true }).click();
  await dialog.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByText("Read-only connection · step 3 of 3")).toBeVisible();
  await dialog.getByPlaceholder("Production account").fill("Production account");
  await dialog.getByPlaceholder(/arn:aws:iam/).fill("arn:aws:iam::123456789012:role/agent-bom-readonly");
  await dialog.getByPlaceholder("••••••••••••").fill("example-external-id");
  await dialog.getByPlaceholder("us-east-1, us-west-2").fill("us-east-1, us-west-2");
  await expect(dialog.getByText("A display name is required.")).toHaveCount(0);
  await page.screenshot({ path: ".screenshots/connections-wizard.png" });
});
