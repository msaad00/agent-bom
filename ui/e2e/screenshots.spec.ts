import { test, expect } from "@playwright/test";
import * as path from "node:path";

// Repo-relative path so the captured PNGs replace the canonical ones
// referenced from README.md / docs/.
const OUT_DIR = path.resolve(__dirname, "..", "..", "docs", "images");

// Each entry maps a docs/images PNG name to the dashboard route the
// product README and docs/SECURITY_ARCHITECTURE.md reference. The
// `readySelector` waits for a route-specific surface to mount with real
// data — a generic `networkidle` is not enough because React Flow
// graphs, table virtualisation, and chart libraries hydrate AFTER
// fetch responses settle. Keep keys in sync with
// `docs/images/*-live.png` callsites.
const SHOTS: {
  name: string;
  route: string;
  readySelector: string;
}[] = [
  // Risk overview — wait for the main panel to mount.
  { name: "dashboard-live.png", route: "/", readySelector: "main" },
  // Attack-paths surface — wait for React Flow viewport with edges.
  {
    name: "dashboard-paths-live.png",
    route: "/security-graph",
    readySelector: ".react-flow__viewport, [data-testid='security-graph-canvas']",
  },
  // Agent mesh — wait for at least one mesh node to render.
  {
    name: "mesh-live.png",
    route: "/mesh",
    readySelector: ".react-flow__node, [data-testid='agent-mesh-node']",
  },
  // Findings table — wait for at least one finding row.
  {
    name: "remediation-live.png",
    route: "/findings",
    readySelector: "table tbody tr, [data-testid='findings-table-row']",
  },
];

test.describe("docs screenshot capture", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  for (const { name, route, readySelector } of SHOTS) {
    test(`capture ${name}`, async ({ page }) => {
      const resp = await page.goto(route, { waitUntil: "networkidle" });
      expect(resp?.ok(), `${route} did not return 2xx`).toBeTruthy();

      // Wait for the route-specific surface so we capture the real
      // visualisation, not the loading skeleton. Soft-fail so empty-data
      // states still capture (with the timeout giving slow charts time
      // to render before falling back).
      await page
        .waitForSelector(readySelector, { state: "visible", timeout: 8000 })
        .catch(() => {
          /* selector not found in time — capture whatever is there */
        });

      // Final settle for chart animations / React Flow auto-layout.
      await page.waitForTimeout(1500);

      await page.screenshot({
        path: path.join(OUT_DIR, name),
        fullPage: false,
      });
    });
  }
});
