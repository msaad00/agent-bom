import { expect, test, type Page } from "@playwright/test";

const source = {
  source_id: "src-prod-cloud",
  tenant_id: "default",
  display_name: "Prod cloud account",
  kind: "scan.cloud",
  description: "Production cloud discovery source",
  owner: "security-platform",
  connector_name: "aws",
  credential_mode: "none",
  credential_ref: null,
  enabled: true,
  status: "healthy",
  config: {},
  last_tested_at: "2026-05-28T10:00:00Z",
  last_test_status: "healthy",
  last_test_message: "OK",
  last_run_at: "2026-05-28T10:12:00Z",
  last_run_status: "done",
  last_job_id: "job-prod-cloud",
  created_at: "2026-05-28T09:00:00Z",
  updated_at: "2026-05-28T10:12:00Z",
};

const job = {
  job_id: "job-prod-cloud",
  tenant_id: "default",
  source_id: source.source_id,
  status: "done",
  created_at: "2026-05-28T10:12:00Z",
  completed_at: "2026-05-28T10:14:00Z",
  request: {
    source_id: source.source_id,
    k8s: true,
  },
  summary: {
    total_agents: 2,
    total_servers: 3,
    total_packages: 8,
    total_vulnerabilities: 3,
    critical_findings: 1,
    high_findings: 1,
    medium_findings: 1,
    low_findings: 0,
  },
};

const jobWithoutTelemetry = {
  ...job,
  job_id: "job-no-telemetry",
  source_id: undefined,
  created_at: "2026-05-28T08:00:00Z",
  completed_at: "2026-05-28T08:02:00Z",
  request: {},
};

async function routeJobs(page: Page) {
  await page.route("**/health", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ status: "ok" }),
    });
  });

  await page.route("**/v1/auth/me", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        authenticated: true,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: null,
        role_summary: null,
        tenant_id: "default",
        memberships: [],
        request_id: "req-jobs-e2e",
        trace_id: "trace-jobs-e2e",
        span_id: "span-jobs-e2e",
      }),
    });
  });

  await page.route("**/v1/posture/counts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
        total: 3,
        kev: 0,
        compound_issues: 0,
      }),
    });
  });

  await page.route("**/v1/jobs**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema_version: "v1",
        jobs: [job, jobWithoutTelemetry],
        count: 2,
        total: 2,
        limit: 200,
        offset: 0,
      }),
    });
  });

  await page.route("**/v1/sources", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        sources: [source],
        count: 1,
      }),
    });
  });

  await page.route("**/v1/schedules", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        {
          schedule_id: "schedule-prod-cloud",
          name: "Prod cloud daily",
          cron_expression: "0 8 * * *",
          scan_config: { source_id: source.source_id },
          enabled: true,
          last_run: "2026-05-28T10:12:00Z",
          next_run: "2026-05-29T08:00:00Z",
          last_job_id: job.job_id,
          created_at: "2026-05-28T09:00:00Z",
          updated_at: "2026-05-28T10:12:00Z",
          tenant_id: "default",
        },
      ]),
    });
  });

  await page.route("**/v1/scan/job-prod-cloud", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        job_id: job.job_id,
        status: "done",
        created_at: job.created_at,
        started_at: job.created_at,
        completed_at: job.completed_at,
        request: job.request,
        progress: [
          JSON.stringify({
            type: "step",
            step_id: "discovery",
            status: "done",
            message: "Discovered 2 agents",
            started_at: "2026-05-28T10:12:00Z",
            completed_at: "2026-05-28T10:12:10Z",
            stats: { agents: 2 },
          }),
          JSON.stringify({
            type: "step",
            step_id: "extraction",
            status: "done",
            message: "Extracted 8 packages",
            started_at: "2026-05-28T10:12:10Z",
            completed_at: "2026-05-28T10:12:25Z",
            stats: { packages: 8 },
          }),
          JSON.stringify({
            type: "step",
            step_id: "scanning",
            status: "done",
            message: "Scanned collected inventory",
            started_at: "2026-05-28T10:12:25Z",
            completed_at: "2026-05-28T10:13:05Z",
            stats: { findings: 3 },
          }),
          JSON.stringify({
            type: "step",
            step_id: "enrichment",
            status: "done",
            message: "Enriched observed findings",
            started_at: "2026-05-28T10:13:05Z",
            completed_at: "2026-05-28T10:13:25Z",
            stats: { findings: 3 },
          }),
          JSON.stringify({
            type: "step",
            step_id: "analysis",
            status: "done",
            message: "Analyzed evidence relationships",
            started_at: "2026-05-28T10:13:25Z",
            completed_at: "2026-05-28T10:13:50Z",
            stats: { critical_findings: 1 },
          }),
          JSON.stringify({
            type: "step",
            step_id: "output",
            status: "done",
            message: "Report generated",
            started_at: "2026-05-28T10:13:50Z",
            completed_at: "2026-05-28T10:14:00Z",
          }),
        ],
        result: { summary: job.summary },
      }),
    });
  });
  await page.route("**/v1/scan/job-no-telemetry", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...jobWithoutTelemetry,
        started_at: jobWithoutTelemetry.created_at,
        progress: [],
        result: { summary: jobWithoutTelemetry.summary },
      }),
    });
  });

}

test("jobs page links sources to completed evidence surfaces", async ({ page }) => {
  await routeJobs(page);
  await page.goto("/jobs");
  await page.waitForLoadState("networkidle");

  await expect(page.getByRole("heading", { name: "Jobs" })).toBeVisible();
  await expect(page.getByTestId("source-job-evidence-workflow")).toContainText("Source → job → evidence");
  await expect(page.getByTestId("job-pipeline-job-prod-cloud")).toBeVisible();
  await expect(page.getByText("Prod cloud account")).toBeVisible();
  await expect(page.getByText("3 CVEs · 1 critical · 8 packages").first()).toBeVisible();

  const prodRow = page.getByRole("row").filter({ hasText: "Prod cloud account" });
  await expect(prodRow.getByRole("link", { name: "Findings", exact: true })).toHaveAttribute("href", "/findings?scan=job-prod-cloud");
  await expect(prodRow.getByRole("link", { name: "Graph", exact: true })).toHaveAttribute("href", "/security-graph?scan=job-prod-cloud");
  await expect(prodRow.getByRole("link", { name: "Compliance", exact: true })).toHaveAttribute("href", "/compliance?scan=job-prod-cloud");

  await page.getByRole("button", { name: "Expand pipeline" }).last().click();
  const unavailable = page.getByTestId("job-pipeline-job-no-telemetry");
  await expect(unavailable.getByText("Stage telemetry unavailable", { exact: true })).toBeVisible();
  await expect(unavailable.getByText("Per-stage telemetry unavailable", { exact: true })).toBeVisible();
  await expect(unavailable).toContainText("The scan result is available, but this executor did not emit stage events or stage timestamps.");
});


for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    test(`pipeline labels and controls remain readable at ${width}px ${theme}`, async ({ page }, testInfo) => {
      await routeJobs(page);
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/jobs");
      await page.evaluate((value) => document.documentElement.setAttribute("data-theme", value), theme);
      const panel = page.getByTestId("job-pipeline-job-prod-cloud");
      await expect(panel.getByRole("navigation", { name: "Scan stages" })).toBeVisible();
      const firstLabel = panel.locator('.react-flow__node[data-id="discovery"]').getByText("Discovery", { exact: true });
      const renderedSize = () => firstLabel.evaluate((element) =>
        Number.parseFloat(getComputedStyle(element).fontSize) *
        new DOMMatrixReadOnly(getComputedStyle(element.closest(".react-flow__viewport")!).transform).a);
      const discoveryInset = () => firstLabel.evaluate(element => {
        const node = element.closest(".react-flow__node")!.getBoundingClientRect();
        const frame = element.closest(".react-flow")!.getBoundingClientRect();
        return node.left - frame.left;
      });
      const flow = panel.locator(".react-flow");
      if (width >= 1024) {
        // Wide frames open on the whole DAG: every stage node sits inside the canvas.
        await expect(panel.getByRole("button", { name: "Readable view", exact: true })).toBeVisible();
        const outside = () => flow.evaluate(frame => {
          const box = frame.getBoundingClientRect();
          return [...frame.querySelectorAll(".react-flow__node")].filter(node => {
            const r = node.getBoundingClientRect();
            return r.left < box.left || r.right > box.right || r.top < box.top || r.bottom > box.bottom;
          }).length;
        });
        await expect.poll(outside).toBe(0);
        await panel.getByRole("button", { name: "Readable view", exact: true }).click();
      }
      await expect.poll(renderedSize).toBeGreaterThanOrEqual(12);
      await expect.poll(discoveryInset).toBeGreaterThanOrEqual(16);
      await expect.poll(discoveryInset).toBeLessThanOrEqual(32);
      await flow.scrollIntoViewIfNeeded();
      await expect(firstLabel).toBeInViewport();
      const zoom = panel.getByRole("button", { name: "Zoom In", exact: true });
      const colors = await zoom.evaluate((element) => {
        const background = getComputedStyle(element).backgroundColor;
        const text = getComputedStyle(element).color;
        const luminance = (color: string) => {
          const channels = color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(value => {
            const normalized = value / 255;
            return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
          });
          return channels[0]! * 0.2126 + channels[1]! * 0.7152 + channels[2]! * 0.0722;
        };
        const bright = Math.max(luminance(background), luminance(text));
        const dark = Math.min(luminance(background), luminance(text));
        return { background, text, contrast: (bright + 0.05) / (dark + 0.05) };
      });
      await testInfo.attach("control-colors", { body: JSON.stringify(colors), contentType: "application/json" });
      expect(colors.contrast).toBeGreaterThanOrEqual(3);
      if (theme === "dark") expect(colors.background).not.toBe("rgb(254, 254, 254)");
      await panel.getByRole("navigation", { name: "Scan stages" }).getByRole("button", { name: "Cloud posture", exact: true }).click();
      await expect(panel.getByRole("complementary", { name: "Stage details" })).toContainText("Cloud posture");
      await panel.locator(".react-flow").scrollIntoViewIfNeeded();
      await expect(panel.getByRole("button", { name: "Inspect Cloud posture" })).toBeInViewport();
      await panel.getByRole("button", { name: "Close stage detail" }).click();
      if (width >= 1024) {
        await expect(panel.getByRole("button", { name: "Readable view", exact: true })).toBeVisible();
        await panel.getByRole("button", { name: "Readable view", exact: true }).click();
      }
      await expect.poll(renderedSize).toBeGreaterThanOrEqual(12);
      await panel.getByRole("button", { name: "Fit overview", exact: true }).click();
      await expect(panel.getByRole("button", { name: "Readable view", exact: true })).toBeVisible();
      await panel.getByRole("button", { name: "Readable view", exact: true }).click();
      await expect.poll(renderedSize).toBeGreaterThanOrEqual(12);
      await expect.poll(discoveryInset).toBeGreaterThanOrEqual(16);
      await expect.poll(discoveryInset).toBeLessThanOrEqual(32);
      await panel.locator(".react-flow").scrollIntoViewIfNeeded();
      await expect(firstLabel).toBeInViewport();
      await panel.scrollIntoViewIfNeeded();
      await panel.screenshot({ path: testInfo.outputPath(`pipeline-${theme}-${width}.png`) });
    });
  }
}
