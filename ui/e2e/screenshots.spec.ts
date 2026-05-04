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
  // Supply-chain graph (the product moat) — full /v1/graph blast-radius
  // visualization. Wait for at least one React Flow node to render.
  {
    name: "dashboard-paths-live.png",
    route: "/graph",
    readySelector: ".react-flow__node, [data-testid='graph-node']",
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
  for (const { name, route, readySelector } of SHOTS) {
    test(`capture ${name}`, async ({ page }) => {
      // Graph + mesh need a tall viewport to fit the canvas below the
      // header and stats row; / and /findings stay at hero crop size.
      const isGraphRoute = route === "/graph" || route === "/mesh";
      // Graph routes routinely exceed the 30s default — 244-node dagre
      // layout + interaction + settle adds up. Bump per-test cap.
      if (isGraphRoute) {
        test.setTimeout(90_000);
      }
      await page.setViewportSize({
        width: 1600,
        height: isGraphRoute ? 1400 : 900,
      });

      const resp = await page.goto(route, { waitUntil: "networkidle" });
      expect(resp?.ok(), `${route} did not return 2xx`).toBeTruthy();

      // Wait for the route-specific surface so we capture the real
      // visualisation, not the loading skeleton.
      await page
        .waitForSelector(readySelector, { state: "visible", timeout: 20000 })
        .catch(() => {
          /* selector not found in time — capture whatever is there */
        });

      // For graph routes the canvas only renders after the user picks a
      // layout — the default `/graph` view shows "How to read this graph"
      // help prose and "filter resolves to findings only" until the
      // operator clicks a Layouts button. Click "Layered" so the
      // capture shows the actual blast-radius topology, not the help.
      if (isGraphRoute) {
        for (const label of ["Layered", "Compounds", "Sources"]) {
          const btn = page.getByRole("button", { name: label }).first();
          if (await btn.isVisible({ timeout: 1000 }).catch(() => false)) {
            await btn.click().catch(() => {});
            break;
          }
        }
        await page
          .locator(".react-flow")
          .first()
          .scrollIntoViewIfNeeded()
          .catch(() => {});
      }

      // Final settle for chart animations / React Flow auto-layout.
      const settleMs = isGraphRoute ? 4000 : 1500;
      await page.waitForTimeout(settleMs);

      await page.screenshot({
        path: path.join(OUT_DIR, name),
        fullPage: false,
      });
    });
  }
});
