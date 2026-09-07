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
