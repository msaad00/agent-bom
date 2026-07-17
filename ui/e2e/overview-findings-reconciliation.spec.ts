import { mkdir } from "node:fs/promises";

import { expect, test, type Page, type TestInfo } from "@playwright/test";

const COUNTS = {
  critical: 7,
  high: 26,
  medium: 13,
  low: 17,
  unrated: 19,
  total: 82,
  kev: 5,
  compound_issues: 3,
  deployment_mode: "fleet",
  scan_count: 14,
  scan_sources: ["aws-organizations", "github-actions", "local-agents"],
  services: {
    cloud_accounts: { state: "connected", count: 4 },
    local_agents: { state: "live", count: 18 },
    compliance: { state: "live", count: 82 },
  },
};

function domain(label: string, metric: number, metricLabel: string, href: string) {
  return { label, metric, metric_label: metricLabel, href, status: "ok", detail: {} };
}

const OVERVIEW = {
  schema_version: "overview.v1",
  tenant_id: "tenant-production",
  posture: {
    grade: "D",
    score: 48,
    display_format: "percent",
    summary: "Current estate needs prioritized remediation.",
    breakdown: [
      { driver: "critical", label: "Critical findings", count: 7, weight: 12, contribution: 84 },
      { driver: "high", label: "High findings", count: 26, weight: 6, contribution: 156 },
    ],
  },
  headline: {
    critical: 7,
    high: 26,
    critical_high: 33,
    kev: 5,
    credential_exposed: 4,
    scans: 14,
    latest_scan_at: "2026-07-17T16:30:00Z",
    hub_findings: 82,
  },
  coverage: [
    { domain: "cspm", label: "CSPM", href: "/findings?scope=all&domain=cspm", count: 22, severity: { critical: 2, high: 9, medium: 7, low: 3, unrated: 1 } },
    { domain: "vuln", label: "Vuln mgmt", href: "/findings?scope=all&domain=vuln", count: 33, severity: { critical: 5, high: 15, medium: 7, low: 4, unrated: 2 } },
    { domain: "aspm", label: "ASPM", href: "/findings?scope=all&domain=aspm", count: 12, severity: { critical: 0, high: 2, medium: 5, low: 3, unrated: 2 } },
    { domain: "dspm", label: "DSPM", href: "/findings?scope=all&domain=dspm", count: 9, severity: { critical: 1, high: 2, medium: 2, low: 1, unrated: 3 } },
    { domain: "aispm", label: "AISPM", href: "/findings?scope=all&domain=aispm", count: 6, severity: { critical: 0, high: 1, medium: 2, low: 1, unrated: 2 } },
  ],
  domains: {
    cloud: domain("Cloud posture", 4, "accounts connected", "/connections"),
    vuln: domain("Vuln / SCA", 33, "open CVEs", "/findings?scope=all&issue=vulnerability"),
    code: domain("Code / repo", 12, "repo scans", "/scan"),
    runtime: domain("Runtime", 3, "active surfaces", "/runtime"),
    cost: domain("LLM Cost", 1824, "USD tracked", "/cost"),
    identity: domain("NHI / Identity", 41, "identities + agents", "/identity"),
    ops: domain("Ops", 14, "completed scans", "/jobs"),
  },
  top_risks: [
    { vulnerability_id: "CVE-2026-7001", package: "gateway-runtime", severity: "critical", risk_score: 9.8, is_kev: true, affected_agents: ["payments-agent"] },
    { vulnerability_id: "CVE-2026-7002", package: "identity-broker", severity: "high", risk_score: 8.4, is_kev: false, affected_agents: ["release-agent"] },
  ],
};

function staleScan(index: number) {
  return {
    job_id: `scan-${index}`,
    status: "done",
    created_at: `2026-07-17T${String(23 - index).padStart(2, "0")}:00:00Z`,
    request: { inventory: true },
    progress: [],
    result: {
      agents: [],
      blast_radius: [{
        vulnerability_id: `CVE-STALE-${index}`,
        package: "old-scan-only",
        severity: "critical",
        risk_score: 7.1,
        affected_agents: [],
        exposed_credentials: [],
        reachable_tools: [],
      }],
      remediation_plan: [],
    },
  };
}

function finding(index: number) {
  return {
    id: `finding-${index}`,
    cve_id: `CVE-2026-${String(8000 + index)}`,
    title: `Production exposure ${index}`,
    severity: "high",
    status: "open",
    asset: { name: `prod-workload-${index}`, type: "workload" },
    package: { name: `runtime-lib-${index}`, version: "1.0.0" },
    effective_reach_score: 8.2,
    last_seen: "2026-07-17T16:00:00Z",
  };
}

async function routeProductFixture(page: Page) {
  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok", version: "0.96.3" } }));
  await page.route("**/version", (route) => route.fulfill({ json: { version: "0.96.3" } }));
  await page.route("**/v1/auth/me", (route) => route.fulfill({
    json: {
      authenticated: true,
      auth_required: false,
      configured_modes: [],
      recommended_ui_mode: "no_auth",
      auth_method: null,
      subject: "operator@example.com",
      role: "admin",
      tenant_id: "tenant-production",
      memberships: [],
    },
  }));
  await page.route("**/v1/posture/counts", (route) => route.fulfill({ json: COUNTS }));
  await page.route("**/v1/posture", (route) => route.fulfill({ json: { grade: "D", score: 48, summary: OVERVIEW.posture.summary } }));
  await page.route("**/v1/overview", (route) => route.fulfill({ json: OVERVIEW }));
  await page.route("**/v1/compliance", (route) => route.fulfill({ status: 503, json: { detail: "not configured" } }));
  await page.route("**/v1/agents", (route) => route.fulfill({ json: { count: 18, agents: [] } }));
  await page.route("**/v1/jobs", (route) => route.fulfill({
    json: {
      jobs: Array.from({ length: 14 }, (_, index) => ({
        job_id: `scan-${index}`,
        status: "done",
        created_at: `2026-07-17T${String(23 - index).padStart(2, "0")}:00:00Z`,
        request: { inventory: true },
        summary: { total_vulnerabilities: 1, critical_findings: 1 },
      })),
    },
  }));
  await page.route(/\/v1\/scan\/scan-(\d+)$/, (route) => {
    const match = route.request().url().match(/scan-(\d+)$/);
    return route.fulfill({ json: staleScan(Number(match?.[1] ?? 0)) });
  });
  await page.route("**/v1/findings**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/v1/findings/triage") {
      return route.fulfill({ json: { triage: [], count: 0 } });
    }
    if (url.searchParams.get("severity") !== "high") {
      return route.fulfill({
        json: { schema_version: "v1", findings: [], count: 0, total: 0, limit: 25, offset: 0, sort: "severity", cursor: "", next_cursor: "", has_more: false, warnings: [], window: { days: 90, since: "2026-04-18T00:00:00Z", applied: true, label: "Last 90 days" } },
      });
    }
    const cursor = url.searchParams.get("cursor");
    const rows = cursor ? [finding(25)] : Array.from({ length: 25 }, (_, index) => finding(index));
    return route.fulfill({
      json: {
        schema_version: "v1",
        findings: rows,
        count: rows.length,
        total: cursor ? null : 26,
        limit: 25,
        offset: 0,
        sort: "severity",
        cursor: cursor ?? "",
        next_cursor: cursor ? "" : "opaque-high-page-2",
        has_more: !cursor,
        warnings: [],
        window: { days: 90, since: "2026-04-18T00:00:00Z", applied: true, label: "Last 90 days" },
      },
    });
  });
}

async function capture(page: Page, testInfo: TestInfo, name: string) {
  await mkdir(".screenshots", { recursive: true });
  await page.screenshot({ path: testInfo.outputPath(name), fullPage: true });
  await page.screenshot({ path: `.screenshots/${name}`, fullPage: true });
}

for (const theme of ["light", "dark"] as const) {
  test(`overview and findings reconcile in ${theme} theme`, async ({ page }, testInfo) => {
    await page.addInitScript((selectedTheme) => localStorage.setItem("agent-bom-theme", selectedTheme), theme);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await routeProductFixture(page);

    await page.goto("/");
    await expect(page.getByText("Current findings · Last 90 days")).toBeVisible();
    const critical = page.getByRole("link", { name: /^Critical 7/i });
    const high = page.getByRole("link", { name: /^High 26/i });
    await expect(critical).toHaveAttribute("href", "/findings?scope=all&severity=critical");
    await expect(high).toHaveAttribute("href", "/findings?scope=all&severity=high");
    await expect(page.getByRole("link", { name: /^Critical 10/i })).toHaveCount(0);
    await capture(page, testInfo, `overview-reconciled-${theme}.png`);

    await high.click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/findings");
    await expect.poll(() => new URL(page.url()).searchParams.get("scope")).toBe("all");
    await expect.poll(() => new URL(page.url()).searchParams.get("severity")).toBe("high");
    await expect(page.getByText("Current state · Last 90 days")).toBeVisible();
    await expect(page.getByText(/26 findings/).first()).toBeVisible();
    await expect(page.getByText("Page 1 of 2 (26 findings)")).toBeVisible();
    await page.getByRole("button", { name: /Next/i }).click();
    await expect(page.getByText("Page 2 · total unavailable")).toBeVisible();
    await expect(page.getByRole("button", { name: /Next/i })).toBeDisabled();
    await capture(page, testInfo, `findings-continuation-${theme}.png`);
  });
}

test("overview and current-state findings remain readable without mobile overflow", async ({ page }, testInfo) => {
  await page.addInitScript(() => localStorage.setItem("agent-bom-theme", "dark"));
  await page.setViewportSize({ width: 390, height: 844 });
  await routeProductFixture(page);

  await page.goto("/");
  await expect(page.getByRole("link", { name: /^Critical 7/i })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await capture(page, testInfo, "overview-reconciled-mobile.png");

  await page.getByRole("link", { name: /^High 26/i }).click();
  await expect(page.getByText("Current state · Last 90 days")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await capture(page, testInfo, "findings-current-state-mobile.png");
});
