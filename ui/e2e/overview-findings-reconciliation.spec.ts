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
  await page.route("**/v1/inventory/summary**", (route) => route.fulfill({ status: 503, json: {detail: "No inventory snapshot in this fixture"} }));
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
    expect(url.searchParams.get("window_days")).toBe("90");
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
    await page.getByRole("tab", { name: "Posture", exact: true }).click();
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
    await page.getByTestId("findings-filters-toggle").click();
    await expect(page.getByTestId("findings-window-select")).toHaveValue("90");
    await page.getByTestId("findings-filters-toggle").click();
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
  await page.getByRole("tab", { name: "Posture", exact: true }).click();
  await expect(page.getByRole("link", { name: /^Critical 7/i })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await capture(page, testInfo, "overview-reconciled-mobile.png");

  await page.getByRole("link", { name: /^High 28/i }).click();
  await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
  await expect(page.getByText("Page 1 of 2 (26 issues)")).toBeVisible();
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
  test(`risk rows meet text contrast in ${theme} theme`, async ({ page }, testInfo) => {
    await page.addInitScript((selectedTheme) => localStorage.setItem("agent-bom-theme", selectedTheme), theme);
    await page.setViewportSize({ width: 1440, height: 900 });
    await routeProductFixture(page);
    await page.route("**/v1/overview", (route) => route.fulfill({ json: {
      ...OVERVIEW,
      domains: {
        ...OVERVIEW.domains,
        runtime: { ...OVERVIEW.domains.runtime, status: "critical" },
        cost: { ...OVERVIEW.domains.cost, status: "warn" },
        identity: { ...OVERVIEW.domains.identity, status: "warn" },
      },
    } }));
    await page.goto("/");
    const metrics = page.getByRole("group", { name: "Select a risk" }).locator("button > span:first-child");
    await expect(metrics).toHaveCount(2);
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
    const evidencePath = testInfo.outputPath(`risk-row-contrast-${theme}.json`);
    await writeFile(evidencePath, JSON.stringify(contrast, null, 2));
    await testInfo.attach(`risk-row-contrast-${theme}`, { path: evidencePath, contentType: "application/json" });
    await page.screenshot({ path: testInfo.outputPath(`risk-row-contrast-${theme}.png`) });
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
        ...Object.fromEntries([...scoredKeys, ...mappingKeys].map((key) => [key, ["cis_controls", "nist_800_53", "fedramp", "pci_dss"].includes(key) ? [{ code: `${key}-1`, name: "Recorded control evidence", status: "pass", findings: 0, severity_breakdown: {}, affected_packages: [], affected_agents: [] }] : []])),
        summary: { cis_pass: 1, nist_800_53_pass: 1, pci_dss_pass: 1, fedramp_pass: 1, cis_foundations_pass: 1, cis_foundations_evaluated: 1, aisvs_pass: 1 },
      } }));
      await page.goto("/");
      await expect(page.getByText("6/6 evaluated controls pass")).toBeVisible();
      await expect(page.getByLabel("Evaluated control results").locator("dt")).toHaveText(["Controls passed", "Controls failed", "Controls need review"]);
      await expect(page.getByText("100% pass rate", { exact: true })).toBeVisible();
      await expect(page.getByText("Assessment: 6/6 framework control entries evaluated (100%)", { exact: true })).toBeVisible();
      expect(await page.getByRole("button", {name: /^Compliance & frameworks/}).getByText("Compliance & frameworks", {exact: true}).evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
      await page.waitForTimeout(350);
      await page.getByRole("tab", { name: "Posture", exact: true }).click();
      const panels = await Promise.all(["Risk overview", "Compliance & frameworks", "Findings by discipline"].map((name) => page.getByRole("region", { name, exact: true }).boundingBox()));
      const [risks, compliance, coverage] = panels;
      const score = (await page.getByTestId("overview-posture-score").boundingBox())!;
      const issues = (await page.getByTestId("overview-severity-issue-strip").boundingBox())!;
      if (width === 1440) {
        expect(issues.x).toBeGreaterThan(score.x + score.width);
        expect(issues.y).toBeLessThan(score.y + score.height);
        expect(risks!.height).toBeLessThan(500);
        expect(risks!.width).toBeGreaterThan(compliance!.width + coverage!.width);
        expect(Math.abs(compliance!.y - coverage!.y)).toBeLessThan(2);
        expect(compliance!.y).toBeGreaterThan(risks!.y + risks!.height);
        expect(coverage!.x).toBeGreaterThan(compliance!.x + compliance!.width);
      } else {
        expect(issues.y).toBeGreaterThan(score.y + score.height);
        for (let index = 1; index < panels.length; index++) {
          expect(panels[index]!.y).toBeGreaterThanOrEqual(panels[index - 1]!.y + panels[index - 1]!.height);
        }
      }
      await page.screenshot({ path: testInfo.outputPath(`overview-two-row-${theme}-${width}.png`) });
      await expect(page.getByRole("button", { name: /Operational signals/ })).toHaveCount(0);
      await page.getByRole("tab", { name: "Top risks", exact: true }).click();
      if (width === 1440) {
        expect((await page.getByRole("region", { name: "Prioritized findings" }).boundingBox())!.y).toBeLessThan(850);
      }
      const unavailableLane = page.getByTestId("coverage-lane-cspm");
      await expect(unavailableLane.getByText("Count unavailable")).toBeVisible();
      expect((await unavailableLane.boundingBox())!.height).toBeLessThanOrEqual(112);
      const cloudBox = (await unavailableLane.boundingBox())!;
      const appBox = (await page.getByTestId("coverage-lane-aspm").boundingBox())!;
      if (width === 1440) {
        expect(appBox.x).toBeGreaterThan(cloudBox.x + cloudBox.width);
        expect(Math.abs(cloudBox.y - appBox.y)).toBeLessThan(2);
      } else {
        expect(Math.abs(cloudBox.x - appBox.x)).toBeLessThan(2);
        expect(appBox.y).toBeGreaterThanOrEqual(cloudBox.y + cloudBox.height);
      }
      await expect(unavailableLane.getByText("0", { exact: true })).toHaveCount(0);
      await page.getByRole("tab", { name: "Posture", exact: true }).click();
      const scoreToggle = page.getByRole("button", { name: /What influences this score/ });
      await scoreToggle.focus();
      await page.keyboard.press("Enter");
      const highPressure = (await page.getByTestId("score-pressure-high").boundingBox())!;
      const criticalPressure = (await page.getByTestId("score-pressure-critical").boundingBox())!;
      expect(highPressure.width / criticalPressure.width).toBeCloseTo(2, 1);
      await expect(page.getByTestId("score-driver-critical").getByText("Critical findings", { exact: true })).toBeVisible();
      await expect(page.getByText(/not points deducted from 100/)).toBeVisible();
      await page.getByTestId("overview-score-explainer").screenshot({ path: testInfo.outputPath(`score-pressure-${theme}-${width}.png`) });
      await scoreToggle.focus();
      await page.keyboard.press("Enter");
      const coverageToggle = page.getByRole("button", { name: /^Findings by discipline/ });
      await coverageToggle.focus();
      await page.keyboard.press("Enter");
      await expect(unavailableLane).not.toBeVisible();
      await expect(coverageToggle).toBeFocused();
      await page.keyboard.press("Space");
      await expect(unavailableLane).toBeVisible();
      const complianceToggle = page.getByRole("button", { name: /^Compliance & frameworks/ });
      await complianceToggle.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByText("6/6 evaluated controls pass")).not.toBeVisible();
      await expect(complianceToggle).toBeFocused();
      await expect(coverageToggle).toHaveAttribute("aria-expanded", "true");
      await expect(page.getByRole("tab", { name: "Posture", exact: true })).toHaveAttribute("aria-selected", "true");
      await page.keyboard.press("Space");
      await expect(page.getByText("6/6 evaluated controls pass")).toBeVisible();
      const disclosure = page.getByRole("button", { name: /^Control frameworks/i });
      await expect(disclosure).toHaveAttribute("aria-expanded", "true");
      await disclosure.focus();
      await page.keyboard.press("Enter");
      await expect(disclosure).toHaveAttribute("aria-expanded", "false");
      await page.keyboard.press("Space");
      await page.getByRole("button", { name: /Show all \d+ control frameworks/ }).click();
      const frameworks = page.getByTestId("overview-evaluated-frameworks");
      const frameworkList = frameworks.getByRole("region", { name: "Control framework list" });
      await frameworkList.focus();
      await expect(frameworkList).toBeFocused();
      expect((await frameworkList.boundingBox())!.height).toBeLessThanOrEqual(353);
      for (const label of ["CIS Controls v8", "NIST SP 800-53", "PCI DSS 4.0", "FedRAMP Moderate", "CIS Foundations Benchmark", "OWASP AISVS"]) {
        const title = frameworks.getByText(label, { exact: true });
        const card = frameworks.getByRole("link", { name: new RegExp(label) });
        await expect(title).toBeVisible();
        expect(await title.evaluate((element) => Number.parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(14);
        await expect(card).toHaveAttribute("href", /^\/compliance\?framework=/);
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
      await page.getByRole("region", { name: "Compliance & frameworks" }).screenshot({ path: testInfo.outputPath(`frameworks-${theme}-${width}.png`) });
      await page.route("**/v1/frameworks/catalogs", route => route.fulfill({ json: { frameworks: {} } }));
      await page.route("**/v1/compliance/hub/posture", route => route.fulfill({ json: { totals: { combined: 0, native: 0, hub: 0 } } }));
      await page.route("**/v1/compliance/nist-800-53**", route => route.fulfill({ status: 503, json: { detail: "not configured" } }));
      await frameworks.getByRole("link", { name: /^CIS Controls v8/ }).click();
      await expect(page).toHaveURL(/\/compliance\?framework=cis$/);
      await expect(page.getByRole("heading", { name: "CIS Controls v8" })).toBeVisible();
      const control = page.getByText("cis_controls-1", { exact: true });
      await control.scrollIntoViewIfNeeded();
      await expect(control).toBeInViewport();
      if (width === 390) expect((await page.getByTestId("compliance-split").boundingBox())!.height).toBeLessThan(400);
      await control.click();
      const drawer = page.getByRole("dialog", { name: /Control details for cis_controls-1/ });
      await expect(drawer).toHaveCSS("opacity", "1");
      await drawer.getByRole("tab", { name: "Evidence", exact: true }).click();
      await expect(drawer.locator("aside")).toBeInViewport();
      expect(await drawer.getByRole("heading").evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`control-drill-${theme}-${width}.png`), animations: "disabled" });
      await page.keyboard.press("Escape");
      await expect(drawer).toHaveCount(0);
      if (width === 390) {
        await page.getByRole("button", { name: "Browse frameworks", exact: true }).click();
        await page.getByTestId("compliance-frameworks-table").getByText("800-53", { exact: true }).click();
        await expect(page.getByRole("heading", { name: "NIST SP 800-53 Rev 5", exact: true })).toBeVisible();
        await expect(page.getByText("nist_800_53-1", { exact: true })).toBeInViewport();
      }
    });
  }
}

for (const theme of ["light", "dark"] as const) {
  for (const viewport of [{ width: 1568, height: 900 }, { width: 390, height: 844 }]) {
    test(`posture-first scope workspace ${theme} ${viewport.width}`, async ({ page }, testInfo) => {
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await page.setViewportSize(viewport);
      await routeProductFixture(page);
      const version = "9.8.7-preview.20260921.abcdef";
      await page.route("**/health", route => route.fulfill({ json: { status: "ok", version } }));
      await page.route("**/v1/overview", (route) => route.fulfill({ json: { ...OVERVIEW, finding_counts: COUNTS,
        top_risks: Array.from({length: 7}, (_, i) => ({...OVERVIEW.top_risks[0], vulnerability_id: `CVE-2026-${7100+i}`, risk_score: 10-i, affected_agents: [`scope-agent-${i}`]})),
      } }));
      await page.route("**/v1/inventory/summary**", (route) => route.fulfill({json: {
        schema_version: "inventory.summary.v1", scan_id: "scope-snapshot", total_assets: 127,
        by_type: {agent: 2, server: 3, tool: 10, tool_call: 50, model: 40, framework: 20, user: 2},
      }}));
      await page.goto("/");
      await expect(page.getByRole("tab", {name: "Posture"})).toHaveAttribute("aria-selected", "true");
      await expect(page.getByRole("tablist", {name: "Risk overview views"}).getByRole("tab")).toHaveText(["Posture", "Top risks", "Assets & coverage"]);
      await page.getByRole("tab", {name: "Top risks"}).click();
      const risks = page.getByRole("group", {name: "Select a risk"});
      await expect(risks.getByRole("button")).toHaveCount(5);
      await risks.getByRole("button", {name: /scope-agent-4/}).click();
      const detail = viewport.width >= 960 ? page.getByRole("region", {name: "Selected risk"}) : page.getByRole("dialog", {name: "Selected risk"});
      await expect(detail.getByText("Affected workload: scope-agent-4")).toBeVisible();
      await expect(detail.getByRole("link", {name: /Affected workload/})).toHaveAttribute("href", /CVE-2026-7104/);
      if (viewport.width >= 960) {
        const listBox = await risks.boundingBox(); const detailBox = await detail.boundingBox();
        expect(listBox).not.toBeNull(); expect(detailBox).not.toBeNull();
        expect(detailBox!.x).toBeGreaterThan(listBox!.x + listBox!.width);
        expect(Math.abs(detailBox!.y - listBox!.y)).toBeLessThan(5);
      } else {
        await page.keyboard.press("Escape");
        await expect(detail).toBeHidden();
        await expect(risks.getByRole("button", {name: /scope-agent-4/})).toBeFocused();
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      const firstScreen = await risks.boundingBox();
      expect(firstScreen!.y + firstScreen!.height).toBeLessThanOrEqual(viewport.height);
      await page.screenshot({path: testInfo.outputPath(`overview-${theme}-${viewport.width}.png`)});
      await page.getByRole("tab", {name: "Assets & coverage"}).click();
      await expect(page.getByRole("tab", {name: "Assets & coverage"})).toHaveAttribute("aria-selected", "true");
      const agents = page.getByRole("link", {name: "At least 2 Agents", exact: true});
      await expect(agents).toBeVisible();
      await expect(agents).toHaveAttribute("href", "/inventory?scan=scope-snapshot&type=agent");
      await expect(page.getByRole("link", {name: "At least 3 Servers", exact: true})).toBeVisible();
      await expect(page.getByText(/Coverage not established by asset counts/)).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.screenshot({path: testInfo.outputPath(`overview-assets-${theme}-${viewport.width}.png`), animations: "disabled"});
      await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      const navigation = page.getByRole("button", {name: "Open navigation menu"});
      if (viewport.width === 390) {
        const bounds = await navigation.boundingBox();
        expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width);
      }
      const status = page.locator("header summary", {hasText: "Control plane"});
      await status.focus(); await page.keyboard.press("Enter");
      const statusDetails = page.locator("header details[open] p");
      await expect(statusDetails).toHaveText(`Control plane · v${version}`);
      const statusBounds = await statusDetails.boundingBox();
      expect(statusBounds!.x).toBeGreaterThanOrEqual(0);
      expect(statusBounds!.x + statusBounds!.width).toBeLessThanOrEqual(viewport.width);
      await page.keyboard.press("Enter");
      for (const tile of await page.getByRole("region", {name: "Recorded assets"}).getByRole("link").all()) {
        expect(await tile.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
      }
      await page.getByRole("region", {name: "Recorded assets"}).screenshot({path: testInfo.outputPath(`overview-assets-zoom-${theme}-${viewport.width}.png`), animations: "disabled"});
    });
  }
}

test("failed asset summary keeps its requested snapshot and filters", async ({ page }) => {
  await routeProductFixture(page);
  await page.route("**/v1/inventory/summary**", route => route.fulfill({status: 503, json: {detail: "Unavailable"}}));
  await page.goto("/?scan=locked-snapshot&provider=aws&environment=production&type=agent&min_severity=high");
  await page.getByRole("tab", {name: "Assets & coverage"}).click();
  await expect(page.getByRole("status").filter({hasText: "Recorded asset summary unavailable"})).toBeVisible();
  const link = page.getByRole("link", {name: "Open asset inventory"});
  await expect(link).toHaveAttribute("href", "/inventory?scan=locked-snapshot&environment=production&provider=aws&type=agent&min_severity=high");
});
