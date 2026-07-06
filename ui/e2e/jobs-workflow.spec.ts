import { expect, test } from "@playwright/test";

const source = {
  source_id: "src-prod-cloud",
  tenant_id: "default",
  display_name: "Prod cloud account",
  kind: "scan.cloud",
  description: "Production cloud discovery source",
  owner: "security-platform",
  connector_name: "aws",
  credential_mode: "credential_ref",
  credential_ref: "aws/prod/read-only",
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

test("jobs page links sources to completed evidence surfaces", async ({ page }) => {
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
        jobs: [job],
        count: 1,
        total: 1,
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

  await page.goto("/jobs");
  await page.waitForLoadState("networkidle");

  await expect(page.getByRole("heading", { name: "Jobs" })).toBeVisible();
  await expect(page.getByTestId("source-job-evidence-workflow")).toContainText("Source → job → evidence");
  await expect(page.getByTestId("source-job-evidence-workflow")).toContainText("Evidence-ready");
  await expect(page.getByText("Prod cloud account")).toBeVisible();
  await expect(page.getByText("3 CVEs · 1 critical · 8 packages")).toBeVisible();

  const mainContent = page.locator("#main-content");
  await expect(mainContent.getByRole("link", { name: "Findings", exact: true })).toHaveAttribute("href", "/findings?scan=job-prod-cloud");
  await expect(mainContent.getByRole("link", { name: "Graph", exact: true })).toHaveAttribute("href", "/security-graph?scan=job-prod-cloud");
  await expect(mainContent.getByRole("link", { name: "Compliance", exact: true })).toHaveAttribute("href", "/compliance?scan=job-prod-cloud");
});
