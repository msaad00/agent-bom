import { expect, test } from "@playwright/test";

import { PRODUCT_ROUTES, routeBaseline } from "./fixtures/route-catalog";

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

test("representative global actions change state, focus content, and navigate", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await routeBaseline(page);
  await page.addInitScript(() => window.localStorage.setItem("agent-bom-theme", "dark"));
  await page.goto("/help", { waitUntil: "domcontentloaded" });

  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect.poll(() => page.evaluate(() => window.localStorage.getItem("agent-bom-theme"))).toBe("light");

  const collapseSidebar = page.getByRole("button", { name: "Collapse sidebar" });
  const expandSidebar = page.getByRole("button", { name: "Expand sidebar" });
  if (await expandSidebar.isVisible()) {
    await expandSidebar.click();
    await expect(collapseSidebar).toBeVisible();
  }
  await collapseSidebar.click();
  await expect(expandSidebar).toBeVisible();
  await expandSidebar.click();
  await expect(collapseSidebar).toBeVisible();

  await page.getByText("Search pages...", { exact: true }).click();
  await page.getByRole("button", { name: "Focus main content" }).click();
  await expect(page.locator("#main-content")).toBeFocused();

  await page.getByText("Search pages...", { exact: true }).click();
  await page.getByPlaceholder("Search pages and commands...").fill("Jobs");
  await page.getByRole("link", { name: /Scan Jobs/ }).click();
  await page.waitForURL((url) => url.pathname === "/jobs");
});
