import { expect, test } from "@playwright/test";

const scanJob = {
  job_id: "job-e2e",
  status: "done",
  created_at: "2026-04-20T12:00:00Z",
  request: {
    images: ["nginx:1.25"],
  },
  progress: [],
  result: {
    agents: [
      {
        name: "Claude Desktop",
        agent_type: "desktop",
        source: "local",
        status: "configured",
        mcp_servers: [
          {
            name: "filesystem",
            has_credentials: false,
            packages: [
              {
                name: "requests",
                version: "2.32.3",
                ecosystem: "pypi",
                vulnerabilities: [],
              },
            ],
          },
        ],
      },
    ],
    blast_radius: [
      {
        vulnerability_id: "CVE-2026-0001",
        package: "requests",
        ecosystem: "pypi",
        severity: "high",
        blast_score: 8.1,
        affected_agents: ["Claude Desktop"],
        exposed_credentials: [],
        reachable_tools: ["filesystem"],
        owasp_tags: [],
        atlas_tags: [],
      },
    ],
    remediation_plan: [],
    summary: {
      total_agents: 1,
      total_packages: 1,
      total_vulnerabilities: 1,
      critical_findings: 0,
    },
  },
};

test("scan flow reaches result view and exports graph JSON", async ({ page }) => {
  await page.route("**/health", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ status: "ok" }),
    });
  });

  await page.route("**/v1/posture/counts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
        kev: 0,
        compound_issues: 0,
      }),
    });
  });

  await page.route("**/v1/auth/debug", async (route) => {
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
        tenant_id: "default",
        oidc_issuer_suffix: null,
        api_key_id_prefix: null,
        request_id: "req-e2e",
        trace_id: "trace-e2e",
        span_id: "span-e2e",
      }),
    });
  });

  await page.route("**/v1/scan", async (route) => {
    if (route.request().method() !== "POST") {
      await route.fallback();
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        job_id: scanJob.job_id,
        status: "pending",
        created_at: scanJob.created_at,
        request: scanJob.request,
        progress: [],
      }),
    });
  });

  await page.route(`**/v1/scan/${scanJob.job_id}`, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify(scanJob),
    });
  });

  await page.route(`**/v1/scan/${scanJob.job_id}/stream`, async (route) => {
    await route.fulfill({
      contentType: "text/event-stream",
      body: [
        'data: {"type":"step","step_id":"analysis","status":"done","message":"Analysis complete"}',
        "",
        `data: {"type":"done","status":"done","job_id":"${scanJob.job_id}"}`,
        "",
      ].join("\n"),
    });
  });

  await page.route(`**/v1/scan/${scanJob.job_id}/graph-export?format=json`, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      headers: {
        "content-disposition": `attachment; filename="scan-${scanJob.job_id}-graph.json"`,
      },
      body: JSON.stringify({
        nodes: [{ id: "agent:Claude Desktop", label: "Claude Desktop" }],
        edges: [],
      }),
    });
  });

  await page.goto("/scan");
  await page.getByPlaceholder("nginx:1.25 or ghcr.io/org/app:v1").fill("nginx:1.25");
  await page.getByPlaceholder("nginx:1.25 or ghcr.io/org/app:v1").press("Enter");
  await page.getByRole("button", { name: /start scan/i }).click();

  await expect(page).toHaveURL(/\/scan\?id=job-e2e/);
  await expect(page.getByRole("heading", { name: "Scan Results" })).toBeVisible();
  await expect(page.getByText("Vulnerabilities")).toBeVisible();
  await expect(page.getByText("Blast Radius (1)")).toBeVisible();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /export graph json/i }).click();
  const download = await downloadPromise;

  await expect(download.suggestedFilename()).toContain("scan-job-e2e-graph.json");
});
