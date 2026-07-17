import { expect, test } from "@playwright/test";

const job = {
  job_id: "job-sast-status",
  status: "done",
  created_at: "2026-07-17T12:00:00Z",
  completed_at: "2026-07-17T12:00:01Z",
  request: { repo_url: "https://github.com/example/agent-app" },
  progress: [],
  result: {
    agents: [],
    blast_radius: [],
    warnings: ["SAST failed: semgrep_failed"],
    sast: {
      scanner_driver_id: "sast-semgrep",
      execution_status: "failed",
      status_reason: "semgrep_failed",
      status_detail: "SAST execution failed.",
      findings: [],
    },
    summary: {
      total_agents: 0,
      total_packages: 0,
      total_vulnerabilities: 0,
      critical_findings: 0,
    },
  },
};

test("repo overview renders failed SAST as failed rather than clean", async ({ page }) => {
  await page.route("**/v1/auth/me", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ authenticated: true, auth_required: false, configured_modes: [] }),
    }),
  );
  await page.route(`**/v1/scan/${job.job_id}/status`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        job_id: job.job_id,
        status: job.status,
        created_at: job.created_at,
        completed_at: job.completed_at,
        request: job.request,
        summary: job.result.summary,
      }),
    }),
  );
  await page.route(`**/v1/scan/${job.job_id}`, (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify(job) }),
  );
  await page.route(`**/v1/scan/${job.job_id}/stream`, (route) =>
    route.fulfill({ contentType: "text/event-stream", body: `data: {"type":"done","status":"done"}\n\n` }),
  );

  await page.goto(`/scan?id=${job.job_id}`);

  const overview = page.getByTestId("repo-scan-overview");
  await expect(overview).toBeVisible();
  await expect(overview.getByText("Semgrep SAST")).toBeVisible();
  await expect(overview.getByText("failed", { exact: true })).toBeVisible();
  await expect(overview.getByText("clean", { exact: true })).toHaveCount(0);
});
