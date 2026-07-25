import { expect, test, type Page } from "@playwright/test";

// Every addressable page emitted by the packaged Next.js build. Dynamic
// templates use a deterministic, non-customer example segment.
const PRODUCT_ROUTES = [
  "/",
  "/accounts/_",
  "/activity",
  "/agents",
  "/agents/topology",
  "/audit",
  "/blueprints",
  "/compliance",
  "/connections",
  "/context",
  "/cost",
  "/drift",
  "/findings",
  "/fleet",
  "/gateway",
  "/governance",
  "/graph",
  "/help",
  "/identity",
  "/insights",
  "/integrations",
  "/inventory",
  "/inventory/agents",
  "/inventory/cloud",
  "/inventory/code",
  "/inventory/containers",
  "/inventory/identities",
  "/inventory/packages",
  "/inventory/servers",
  "/jobs",
  "/login",
  "/manifest",
  "/mesh",
  "/overview",
  "/proxy",
  "/registry",
  "/remediation",
  "/reports",
  "/runtime",
  "/scan",
  "/security-graph",
  "/self-posture",
  "/sources",
  "/threat-intel",
  "/traces",
  "/vulns",
] as const;

async function routeBaseline(page: Page) {
  await page.route("**/v1/**", (route) =>
    route.fulfill({ status: 503, json: { detail: "Unavailable in route smoke" } }),
  );
  await page.route("**/health", (route) =>
    route.fulfill({ json: { status: "ok", version: "0.99.0" } }),
  );
  await page.route("**/version", (route) =>
    route.fulfill({ json: { version: "0.99.0" } }),
  );
  await page.route("**/v1/auth/me", (route) =>
    route.fulfill({
      json: {
        authenticated: true,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: null,
        role_summary: null,
        tenant_id: "route-smoke",
        memberships: [],
      },
    }),
  );
  await page.route("**/v1/posture/counts", (route) =>
    route.fulfill({
      json: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
        kev: 0,
        compound_issues: 0,
        deployment_mode: "local",
        scan_count: 0,
        scan_sources: [],
        services: {},
      },
    }),
  );
}

test("every packaged product route renders and enabled controls are named", async ({ page }) => {
  test.setTimeout(180_000);
  expect(PRODUCT_ROUTES.length).toBeGreaterThanOrEqual(40);
  await routeBaseline(page);

  for (const path of PRODUCT_ROUTES) {
    const response = await page.goto(path, { waitUntil: "domcontentloaded" });
    expect(response?.status(), `${path} returned an HTTP error`).toBeLessThan(400);
    await expect(page.getByRole("heading", { name: "404", exact: true }), `${path} rendered the not-found page`).toHaveCount(0);
    await expect(page.getByText("Application error", { exact: false }), `${path} rendered a framework error`).toHaveCount(0);

    const unnamed = await page.locator("button:enabled:visible").evaluateAll((buttons) =>
      buttons
        .filter((button) => {
          const text = button.textContent?.trim() ?? "";
          return !text && !button.getAttribute("aria-label") && !button.getAttribute("title");
        })
        .map((button) => button.outerHTML.slice(0, 180)),
    );
    expect(unnamed, `${path} has enabled buttons without an accessible label`).toEqual([]);
  }
});
