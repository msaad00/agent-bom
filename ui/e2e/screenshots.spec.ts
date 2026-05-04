import { test, expect } from "@playwright/test";
import * as path from "node:path";

// Repo-relative path so the captured PNGs replace the canonical ones
// referenced from README.md / docs/.
const OUT_DIR = path.resolve(__dirname, "..", "..", "docs", "images");

// Each entry maps a docs/images PNG name to the dashboard route the
// product README and docs/SECURITY_ARCHITECTURE.md reference. Keep the
// keys in sync with `docs/images/*-live.png` callsites — adding or
// renaming a screenshot here is a docs-facing surface change.
const SHOTS: { name: string; route: string; selector?: string }[] = [
  { name: "dashboard-live.png", route: "/" },
  { name: "dashboard-paths-live.png", route: "/security-graph" },
  { name: "mesh-live.png", route: "/mesh" },
  { name: "remediation-live.png", route: "/findings" },
];

test.describe("docs screenshot capture", () => {
  test.beforeEach(async ({ page }) => {
    // Wide viewport so the captured shot matches the README hero crop.
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  for (const { name, route } of SHOTS) {
    test(`capture ${name}`, async ({ page }) => {
      const resp = await page.goto(route, { waitUntil: "networkidle" });
      expect(resp?.ok(), `${route} did not return 2xx`).toBeTruthy();
      // Give React Flow / charts a moment to settle after networkidle.
      await page.waitForTimeout(800);
      await page.screenshot({
        path: path.join(OUT_DIR, name),
        fullPage: false,
      });
    });
  }
});
