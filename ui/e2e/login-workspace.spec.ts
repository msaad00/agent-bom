import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"] as const) {
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    test(`sign-in stays readable and contains safe errors: ${theme} ${viewport.width}`, async ({ page }, testInfo) => {
      await page.setViewportSize(viewport);
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
        authenticated: false, auth_required: true, configured_modes: ["api_key"],
        recommended_ui_mode: "session_api_key", auth_method: null, subject: null,
        role: null, tenant_id: "default", memberships: [],
      } }));
      await page.route("**/v1/auth/session", (route) => route.fulfill({
        status: 401, json: { detail: "private-auth-receipt must never be shown" },
      }));
      await page.goto("/login");
      await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      const input = page.getByLabel("API key", { exact: true });
      await expect(input).toBeVisible();
      await expect(page.getByText("Need access? Contact your administrator.")).toBeVisible();
      await expect(page.getByText(/AGENT_BOM_API_KEYS|That key is not active/)).toHaveCount(0);
      await page.screenshot({ path: testInfo.outputPath(`login-${theme}-${viewport.width}.png`), fullPage: true });
      await input.fill("synthetic-invalid-key");
      await input.press("Tab");
      await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeFocused();
      await page.keyboard.press("Enter");
      await expect(page.getByText("Sign-in failed. Check your API key or contact your administrator.")).toBeVisible();
      await expect(input).toHaveValue("");
      await expect(page.getByText("private-auth-receipt", { exact: false })).toHaveCount(0);
      await page.screenshot({ path: testInfo.outputPath(`login-rejected-${theme}-${viewport.width}.png`), fullPage: true });
      await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
      await expect(input).toBeVisible();
      const bounds = await input.boundingBox();
      expect(bounds).not.toBeNull();
      expect(bounds!.x).toBeGreaterThanOrEqual(0);
      expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
      await page.getByRole("button", { name: "Sign in", exact: true }).scrollIntoViewIfNeeded();
      await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeInViewport();
    });
  }
}
