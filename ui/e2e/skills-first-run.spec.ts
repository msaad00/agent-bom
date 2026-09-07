import { writeFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

const EMPTY = {
  scan_type: "skills", report_type: "skills_scan", status: "no_data", run_id: null, created_at: null,
  summary: { files_scanned: 0, bundles: 0, bundled_files: 0, packages_found: 0, servers_found: 0, credential_env_vars: 0, findings: 0, verified_files: 0, suspicious_files: 0, malicious_files: 0, blocked_files: 0, high_risk_files: 0, clean_files: 0, suspicious_status_files: 0, malicious_status_files: 0, pending_status_files: 0, unavailable_status_files: 0 },
  files: [],
};
const FILE = {
  path: "skills/review/SKILL.md", status: "pending", credential_env_vars: [], packages: [], servers: [],
  audit: { passed: true, findings: [] },
  trust: { verdict: "benign", content_verdict: "benign", provenance_verdict: "unverified", review_verdict: "review", confidence: "medium", recommendations: [], review_reasons: [] },
  provenance: { status: "unsigned", sha256: "a".repeat(64), signer: null },
};

for (const theme of ["light", "dark"] as const) {
  test(`Skills first-run feedback and keyboard evidence in ${theme}`, async ({ page }, testInfo) => {
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.route("**/v1/**", (route) => route.fulfill({ json: {} }));
    await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
      authenticated: true, auth_method: "api_key", role: "admin", tenant_id: "fixture-tenant", permissions: ["read", "scan"],
    } }));
    let attempt = 0;
    await page.route("**/v1/skills/scan", (route) => {
      if (route.request().method() === "GET") return route.fulfill({ json: EMPTY });
      attempt += 1;
      expect(route.request().postDataJSON()).toEqual({ directories: [], files: ["skills/review/SKILL.md"] });
      if (attempt === 1) return route.fulfill({ status: 400, json: { detail: "Invalid scan path" } });
      if (attempt === 2) return route.fulfill({ json: { ...EMPTY, status: "completed", run_id: "empty-run", created_at: "2026-09-07T00:00:00Z" } });
      return route.fulfill({ json: { ...EMPTY, status: "completed", run_id: "skill-run", created_at: "2026-09-07T00:01:00Z", summary: { ...EMPTY.summary, files_scanned: 1, pending_status_files: 1 }, files: [FILE] } });
    });
    await page.goto("/skills");
    await expect(page.getByText("No skills scanned yet")).toBeVisible();
    await page.getByLabel("Scan targets").fill("skills/review/SKILL.md");
    const scan = page.getByTestId("skills-scan-button");
    await scan.click();
    await expect(page.getByText("Invalid scan path", { exact: true })).toBeVisible();
    await expect(page.getByTestId("skills-scan-disabled")).toHaveCount(0);
    await scan.click();
    await expect(page.getByText("No skill files found")).toBeVisible();
    await expect(page.getByText("No skills scanned yet")).toHaveCount(0);
    await scan.click();
    const inspect = page.getByRole("button", { name: "Inspect skills/review/SKILL.md" });
    await inspect.focus();
    await page.keyboard.press("Enter");
    const drawer = page.getByRole("dialog", { name: "Skill scan detail for skills/review/SKILL.md" });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByText("unsigned", { exact: false })).toBeVisible();
    await page.waitForTimeout(500);
    await page.screenshot({ path: testInfo.outputPath(`skills-evidence-${theme}.png`) });
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    await expect(inspect).toBeFocused();
    await page.setViewportSize({ width: 390, height: 844 });
    await inspect.press("Space");
    await expect(drawer).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`skills-evidence-${theme}-mobile.png`) });
    await page.keyboard.press("Escape");
    await expect(inspect).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`Skills status and provenance chip contrast in ${theme}`, async ({ page }, testInfo) => {
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.route("**/v1/**", (route) => route.fulfill({ json: {} }));
    const statuses = ["malicious", "suspicious", "pending", "unavailable", "clean"];
    const provenance = ["bundle_found_but_invalid", "unsigned", "unsigned", "missing", "verified"];
    await page.route("**/v1/skills/scan", (route) => route.fulfill({ json: {
      ...EMPTY, status: "completed", run_id: "contrast-fixture", created_at: "2026-09-07T00:00:00Z",
      summary: { ...EMPTY.summary, files_scanned: 5 },
      files: statuses.map((status, index) => ({ ...FILE, path: `skills/${status}/SKILL.md`, status, provenance: { ...FILE.provenance, status: provenance[index] } })),
    } }));
    await page.goto("/skills");
    const chips = page.getByTestId("skills-row").locator("span.rounded-full");
    await expect(chips).toHaveCount(10);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await page.waitForTimeout(500);
    const contrast = await chips.evaluateAll((nodes) => {
      const context = document.createElement("canvas").getContext("2d")!;
      function rgba(color: string): number[] {
        context.clearRect(0, 0, 1, 1);
        context.fillStyle = color;
        context.fillRect(0, 0, 1, 1);
        return [...context.getImageData(0, 0, 1, 1).data];
      }
      function luminance(rgb: number[]): number {
        return rgb.slice(0, 3).map((c) => {
          const s = c / 255;
          return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
        }).reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i]!, 0);
      }
      return nodes.map((node) => {
        const ancestors: Element[] = [];
        for (let current: Element | null = node; current; current = current.parentElement) ancestors.unshift(current);
        let background = [255, 255, 255];
        for (const ancestor of ancestors) {
          const color = rgba(getComputedStyle(ancestor).backgroundColor);
          const alpha = color[3]! / 255;
          background = background.map((value, i) => color[i]! * alpha + value * (1 - alpha));
        }
        const foreground = rgba(getComputedStyle(node).color);
        const a = luminance(foreground);
        const b = luminance(background);
        return { text: node.textContent, foreground, background, ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) };
      });
    });
    const evidencePath = testInfo.outputPath(`skills-chip-contrast-${theme}.json`);
    await writeFile(evidencePath, JSON.stringify(contrast, null, 2));
    await testInfo.attach(`skills-chip-contrast-${theme}`, { path: evidencePath, contentType: "application/json" });
    await page.screenshot({ path: testInfo.outputPath(`skills-chip-contrast-${theme}.png`) });
    for (const metric of contrast) expect(metric.ratio, `${theme} chip ${metric.text}`).toBeGreaterThanOrEqual(4.5);
  });
}
