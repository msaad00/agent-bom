import { mkdir, writeFile } from "node:fs/promises";

import { expect, test, type Page, type TestInfo } from "@playwright/test";
import type { UnifiedFinding } from "../lib/api-types";

const COUNTS = {
  critical: 7,
  high: 28,
  medium: 13,
  low: 17,
  unrated: 19,
  total: 84,
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
      { driver: "high", label: "High findings", count: 28, weight: 6, contribution: 168 },
    ],
  },
  headline: {
    critical: 7,
    high: 28,
    critical_high: 35,
    kev: 5,
    credential_exposed: 4,
    scans: 14,
    latest_scan_at: "2026-07-17T16:30:00Z",
    hub_findings: 84,
  },
  coverage: [
    { domain: "cspm", label: "CSPM", href: "/findings?scope=all&domain=cspm", count: 22, severity: { critical: 2, high: 9, medium: 7, low: 3, unrated: 1 } },
    { domain: "vuln", label: "Vuln mgmt", href: "/findings?scope=all&domain=vuln", count: 35, severity: { critical: 5, high: 17, medium: 7, low: 4, unrated: 2 } },
    { domain: "aspm", label: "ASPM", href: "/findings?scope=all&domain=aspm", count: 12, severity: { critical: 0, high: 2, medium: 5, low: 3, unrated: 2 } },
    { domain: "dspm", label: "DSPM", href: "/findings?scope=all&domain=dspm", count: 9, severity: { critical: 1, high: 2, medium: 2, low: 1, unrated: 3 } },
    { domain: "aispm", label: "AISPM", href: "/findings?scope=all&domain=aispm", count: 6, severity: { critical: 0, high: 1, medium: 2, low: 1, unrated: 2 } },
  ],
  domains: {
    cloud: domain("Cloud posture", 4, "accounts connected", "/connections"),
    vuln: domain("Vuln / SCA", 35, "open CVEs", "/findings?scope=all&issue=vulnerability"),
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

function finding(index: number): UnifiedFinding & { effective_reach_score: number } {
  const occurrenceCount = index === 0 ? 3 : 1;
  return {
    id: `finding-${index}`,
    finding_class: "vulnerability",
    cve_id: `CVE-2026-${String(8000 + index)}`,
    title: `Production exposure ${index}`,
    severity: "high",
    status: "open",
    asset: { name: `prod-workload-${index}`, asset_type: "workload" },
    package: `runtime-lib-${index}`,
    package_version: "1.0.0",
    effective_reach_score: 8.2,
    last_seen: "2026-07-17T16:00:00Z",
    occurrence_count: occurrenceCount,
    occurrences: Array.from({ length: occurrenceCount }, (_, occurrenceIndex) => ({
      finding_id: `finding-${index}-occurrence-${occurrenceIndex}`,
      asset: {
        name: `prod-workload-${index}-${occurrenceIndex}`,
        stable_id: `workload:prod-workload-${index}-${occurrenceIndex}`,
        asset_type: "workload",
      },
      package_version: "1.0.0",
    })),
  };
}

async function routeProductFixture(page: Page) {
  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok", version: "9.8.7" } }));
  await page.route("**/version", (route) => route.fulfill({ json: { version: "9.8.7" } }));
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
    await expect(page.getByText("Current findings · configured window")).toBeVisible();
    const critical = page.getByRole("link", { name: /^Critical 7/i });
    const high = page.getByRole("link", { name: /^High 28/i });
    await expect(critical).toHaveAttribute("href", "/findings?scope=all&severity=critical");
    await expect(high).toHaveAttribute("href", "/findings?scope=all&severity=high");
    await expect(page.getByRole("link", { name: /^Critical 10/i })).toHaveCount(0);
    await capture(page, testInfo, `overview-reconciled-${theme}.png`);

    await high.click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/findings");
    await expect.poll(() => new URL(page.url()).searchParams.get("scope")).toBe("all");
    await expect.poll(() => new URL(page.url()).searchParams.get("severity")).toBe("high");
    await expect(page.getByText("Current state · Last 90 days")).toBeVisible();
    await expect(page.getByText(/26 issues/).first()).toBeVisible();
    await expect(page.getByText("Page 1 of 2 (26 issues)")).toBeVisible();
    const occurrences = page.getByRole("button", { name: "Show 3 affected asset occurrences" });
    await expect(occurrences).toBeVisible();
    await occurrences.click();
    await expect(page.getByText("Asset-scoped occurrences")).toBeVisible();
    // Exact name: the dev server also renders an "Open Next.js Dev Tools"
    // button, which a loose /Next/i match resolves to as well.
    const nextPage = page.getByRole("button", { name: "Next", exact: true });
    await nextPage.click();
    await expect(page.getByText("Page 2 · total unavailable")).toBeVisible();
    await expect(nextPage).toBeDisabled();
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

  await page.getByRole("link", { name: /^High 28/i }).click();
  await expect(page.getByText("Current state · Last 90 days")).toBeVisible();
  const overflow = await page.evaluate(() => {
    const viewportWidth = document.documentElement.clientWidth;
    return Array.from(document.querySelectorAll<HTMLElement>("body *"))
      .map((element) => ({
        tag: element.tagName.toLowerCase(),
        className: element.className,
        left: Math.round(element.getBoundingClientRect().left),
        right: Math.round(element.getBoundingClientRect().right),
      }))
      .filter(({ left, right }) => left < -1 || right > viewportWidth + 1)
      .slice(0, 10);
  });
  expect(overflow, "findings mobile layout contains elements outside the viewport").toEqual([]);
  await capture(page, testInfo, "findings-current-state-mobile.png");
});

for (const theme of ["light", "dark"] as const) {
  test(`operational metrics meet text contrast in ${theme} theme`, async ({ page }, testInfo) => {
    await page.addInitScript((selectedTheme) => localStorage.setItem("agent-bom-theme", selectedTheme), theme);
    await page.setViewportSize({ width: 1440, height: 900 });
    await routeProductFixture(page);
    await page.route("**/v1/overview", (route) => route.fulfill({ json: {
      ...OVERVIEW,
      domains: {
        ...OVERVIEW.domains,
        runtime: { ...OVERVIEW.domains.runtime, status: "critical" },
        cost: { ...OVERVIEW.domains.cost, status: "warn" },
        identity: { ...OVERVIEW.domains.identity, status: "ok" },
      },
    } }));
    await page.goto("/");
    const metrics = page.getByTestId("overview-estate-ops").locator("span.font-mono");
    await expect(metrics).toHaveCount(4);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    // Measure settled theme colors rather than the deliberate transition frame.
    await page.waitForTimeout(500);
    const contrast = await metrics.evaluateAll((nodes) => {
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
    const evidencePath = testInfo.outputPath(`operational-contrast-${theme}.json`);
    await writeFile(evidencePath, JSON.stringify(contrast, null, 2));
    await testInfo.attach(`operational-contrast-${theme}`, { path: evidencePath, contentType: "application/json" });
    await page.screenshot({ path: testInfo.outputPath(`operational-contrast-${theme}.png`) });
    for (const metric of contrast) expect(metric.ratio, `${theme} metric ${metric.text}`).toBeGreaterThanOrEqual(4.5);
  });
}

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    test(`framework names retain readable columns in ${theme} at ${width}px`, async ({ page }, testInfo) => {
      await page.addInitScript((selectedTheme) => localStorage.setItem("agent-bom-theme", selectedTheme), theme);
      await page.setViewportSize({ width, height: 900 });
      await routeProductFixture(page);
      const scoredKeys = ["nist_ai_rmf", "eu_ai_act", "nist_csf", "iso_27001", "soc2", "cis_controls", "cmmc", "nist_800_53", "fedramp", "pci_dss"];
      const mappingKeys = ["owasp_llm_top10", "owasp_mcp_top10", "mitre_atlas", "owasp_agentic_top10"];
      await page.route("**/v1/compliance", (route) => route.fulfill({ json: {
        overall_score: 100, overall_status: "pass", evaluated_controls: 6, total_controls: 6,
        scan_count: 14, has_mcp_context: true, has_agent_context: true,
        framework_kinds: Object.fromEntries([...scoredKeys.map((key) => [key, "scored"]), ...mappingKeys.map((key) => [key, "applicability"])]),
        ...Object.fromEntries([...scoredKeys, ...mappingKeys].map((key) => [key, ["cis_controls", "nist_800_53", "fedramp", "pci_dss"].includes(key) ? [{ id: `${key}-1`, status: "pass" }] : []])),
        summary: { cis_pass: 1, nist_800_53_pass: 1, pci_dss_pass: 1, fedramp_pass: 1, cis_foundations_pass: 1, cis_foundations_evaluated: 1, aisvs_pass: 1 },
      } }));
      await page.goto("/");
      await page.getByRole("button", { name: /Findings by discipline/i }).click();
      const unavailableLane = page.getByTestId("coverage-lane-cspm");
      await expect(unavailableLane.getByText("Count unavailable")).toBeVisible();
      expect((await unavailableLane.boundingBox())!.height).toBeLessThanOrEqual(56);
      await expect(unavailableLane.getByText("0", { exact: true })).toHaveCount(0);
      const disclosure = page.getByRole("button", { name: /Evaluated frameworks/i });
      await disclosure.focus();
      await page.keyboard.press("Enter");
      const frameworks = page.getByTestId("overview-evaluated-frameworks");
      for (const label of ["CIS Controls v8", "NIST SP 800-53", "PCI DSS 4.0", "FedRAMP Moderate", "CIS Foundations Benchmark", "OWASP AISVS"]) {
        const title = frameworks.getByText(label, { exact: true });
        const card = frameworks.getByRole("link", { name: new RegExp(label) });
        await expect(title).toBeVisible();
        await expect(card).toHaveAttribute("href", "/compliance");
        const titleBox = await title.boundingBox();
        const cardBox = await card.boundingBox();
        expect(titleBox!.width).toBeGreaterThan(80);
        expect(cardBox!.height).toBeLessThan(100);
        await card.focus();
        await expect(card).toBeFocused();
      }
      await expect(page.getByText("6/6 evaluated controls pass")).toBeVisible();
      await expect(page.getByText("Not evaluated · 0/0 controls").first()).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.waitForTimeout(350);
      await page.getByRole("region", { name: "Coverage & controls" }).screenshot({ path: testInfo.outputPath(`frameworks-${theme}-${width}.png`) });
    });
  }
}
