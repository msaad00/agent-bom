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

  await page.route(`**/v1/scan/${scanJob.job_id}/status`, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        job_id: scanJob.job_id,
        status: scanJob.status,
        created_at: scanJob.created_at,
        completed_at: "2026-04-20T12:00:13Z",
        request: scanJob.request,
        summary: scanJob.result.summary,
      }),
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

  // Capture browser console + pageerror so a CSP violation or hydration
  // failure surfaces with a real error in the test log instead of an
  // opaque locator.fill timeout. This is what made the #1982 strict-CSP
  // regression hard to diagnose downstream — the e2e timed out on `fill`
  // without the underlying CSP block being visible to anyone.
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/scan");
  // Wait for the page to fully load AND hydrate. Without this the e2e can
  // race the React hydration cycle and time out on the next .fill() with
  // no actionable error.
  await page.waitForLoadState("networkidle");

  const imageInput = page.getByPlaceholder("nginx:1.25 or ghcr.io/org/app:v1");
  try {
    await expect(imageInput, "image input must be visible after hydration").toBeVisible({ timeout: 15_000 });
    await expect(imageInput, "image input must be enabled after hydration").toBeEnabled({ timeout: 15_000 });
  } catch (err) {
    // If the page never hydrated, surface the captured browser errors before
    // letting the implicit fill timeout swallow them. Do not fail a hydrated
    // scan page for unrelated Next.js background prefetch noise.
    if (consoleErrors.length > 0) {
      throw new Error(
        "Browser reported errors before scan flow could start (likely CSP block or hydration failure):\n" +
          consoleErrors.map((e) => `  - ${e}`).join("\n"),
      );
    }
    throw err;
  }

  await imageInput.fill("nginx:1.25");
  await imageInput.press("Enter");
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
