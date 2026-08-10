import { expect, test, type Page } from "@playwright/test";

const CREATED_AT = "2026-07-17T12:00:00Z";

async function routeShell(page: Page) {
  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok", version: "0.98.1" } }));
  await page.route("**/version", (route) => route.fulfill({ json: { version: "0.98.1" } }));
  await page.route("**/v1/auth/me", (route) => route.fulfill({ json: {
    authenticated: true,
    auth_required: false,
    configured_modes: [],
    recommended_ui_mode: "no_auth",
    auth_method: null,
    subject: null,
    role: "admin",
    role_summary: { role: "admin", ui_role: "admin", display_name: "Admin", capabilities: ["scan.write", "audit.read"] },
    tenant_id: "default",
    memberships: [],
  } }));
  await page.route("**/v1/posture/counts", (route) => route.fulfill({ json: {
    critical: 1, high: 1, medium: 0, low: 0, total: 2, kev: 0, compound_issues: 0,
  } }));
}

const campaign = {
  id: "campaign-browser",
  tenant_id: "default",
  title: "Upgrade openssl to 3.0.14",
  finding_ids: ["DEMO-VULN-21441"],
  finding_count: 1,
  severity: "critical",
  priority_score: 9.2,
  priority_score_method: "bounded model over explicit evidence",
  priority_score_components: {
    base_risk: 8.2,
    exploitability_boost: 0,
    reachability_boost: 1,
    crown_jewel_boost: 0,
    cap: 10,
  },
  score_factors: {
    severity: { value: "critical", status: "observed", bands_present: ["critical"] },
    exploitability: { value: null, status: "unknown" },
    reachability: { value: true, status: "observed" },
    business_context: { value: "Synthetic production service", status: "observed" },
    crown_jewel: { value: null, status: "unknown" },
  },
  expected_risk_reduction: {
    modeled_window_percent: 20,
    modeled_risk_points: 9.2,
    assumption: "The original finding is remediated and verified.",
    method: "bounded campaign risk divided by the complete evidence window",
    scope: "last 90 days",
    portfolio_complete: true,
  },
  owner: "appsec",
  sla_due_at: "2026-07-28T00:00:00Z",
  state: "in_progress",
  verification_status: "pending",
  updated_at: CREATED_AT,
  source: "canonical_findings_spine",
  membership_fingerprint: "sha256:synthetic-membership",
  generation: 1,
  version: 4,
  active: true,
  membership_complete: true,
  membership_provisional: false,
};

const REMEDIATION_PLAN = [{
      package: "openssl",
      ecosystem: "generic",
      current_version: "3.0.13",
      fixed_version: "3.0.14",
      severity: "critical",
      impact_score: 9.2,
      priority: 1,
      action: "upgrade",
      reason: "Synthetic reachable package finding.",
      command: "upgrade openssl to 3.0.14",
      verify_command: "agent-bom scan .",
      vulnerabilities: ["DEMO-VULN-21441"],
      affected_agents: ["developer-copilot"],
      agents_pct: 100,
      exposed_credentials: [],
      credentials_pct: 0,
      reachable_tools: ["create_pull_request"],
      tools_pct: 100,
      owasp_tags: ["LLM05"],
      atlas_tags: [],
      references: [],
      risk_narrative: "Patch the package, then regenerate evidence.",
    }];

async function routeRemediation(page: Page) {
  await routeShell(page);
  await page.route("**/v1/jobs**", (route) => route.fulfill({ json: {
    jobs: [{ job_id: "job-remediation", status: "done", created_at: CREATED_AT, completed_at: CREATED_AT, request: {}, summary: {} }],
    count: 1, total: 1, limit: 25, offset: 0, status_counts: { done: 1 },
  } }));
  // The page reads the plan from `/v1/scan/{id}/remediation`, which serves the
  // plan alone rather than the whole 8.7 MB scan document. Playwright's
  // `**/v1/scan/job-remediation` glob does NOT match that sub-path, so this
  // route has to be declared separately -- and it is declared FIRST, because
  // the broader pattern would otherwise claim the request and answer it with a
  // whole-job payload the caller no longer reads.
  await page.route("**/v1/scan/job-remediation/remediation", (route) => route.fulfill({ json: {
    job_id: "job-remediation",
    remediation_plan: REMEDIATION_PLAN,
    total: REMEDIATION_PLAN.length,
  } }));
  await page.route("**/v1/scan/job-remediation", (route) => route.fulfill({ json: {
    job_id: "job-remediation",
    status: "done",
    created_at: CREATED_AT,
    completed_at: CREATED_AT,
    request: {},
    progress: [],
    result: { remediation_plan: REMEDIATION_PLAN },
  } }));
  await page.route("**/v1/ticketing/tickets", (route) => route.fulfill({ json: {
    schema_version: "ticketing.tickets.v1", tenant_id: "default", tickets: [], count: 0,
  } }));
  await page.route("**/v1/ticketing/connections", (route) => route.fulfill({ json: {
    schema_version: "ticketing.connections.v1", tenant_id: "default", connections: [], count: 0,
  } }));
  await page.route("**/v1/campaigns/verification-queue**", (route) => route.fulfill({ json: {
    schema_version: "risk-campaign-verification-queue.v1",
    tenant_id: "default",
    entries: [{
      campaign_id: "campaign-retired",
      title: "Retired synthetic campaign",
      original_member_count: 2,
      owner: "appsec",
      sla_due_at: "2026-07-28T00:00:00Z",
      state: "in_progress",
      verification_status: "unverified",
      active: false,
      version: 7,
      updated_at: CREATED_AT,
    }],
    count: 1, has_more: false, next_cursor: null, limit: 25,
  } }));
  await page.route("**/v1/campaigns/campaign-retired/verify", (route) => route.fulfill({ json: {
    schema_version: "risk-campaign-verification.v1",
    campaign_id: "campaign-retired",
    verification_status: "verified",
    state: "done",
    remaining_finding_ids: [],
    remaining_count: 0,
    original_member_count: 2,
    evidence_scope: { source: "canonical_findings_spine", finding_window_days: 90, finding_limit: 1000, membership_complete: true },
    version: 8,
    verified_at: "2026-07-17T13:00:00Z",
  } }));
  await page.route("**/v1/campaigns", (route) => route.fulfill({ json: {
    schema_version: "risk-campaigns.v1",
    tenant_id: "default",
    campaigns: [campaign],
    count: 1,
    finding_window_days: 90,
    finding_limit: 1000,
    truncated: false,
    total_findings: 1,
    total_approximate: false,
    membership_complete: true,
  } }));
}

test("remediation compact rows disclose detail and durable re-verification", async ({ page }) => {
  await routeRemediation(page);
  await page.goto("/remediation");
  await expect(page.getByRole("heading", { name: "Risk campaigns" })).toBeVisible();

  const campaignSummary = page.getByText(campaign.title, { exact: true });
  await expect(campaignSummary).toBeVisible();
  await expect(page.getByRole("button", { name: /Why this priority/i })).toBeHidden();
  await campaignSummary.click();
  await page.getByRole("button", { name: /Why this priority/i }).click();
  await expect(page.getByText("Observed priority evidence", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Details", exact: true }).click();
  await expect(page.getByText("Patch the package, then regenerate evidence.", { exact: true })).toBeVisible();

  const verifyRequest = page.waitForRequest((request) =>
    request.url().endsWith("/v1/campaigns/campaign-retired/verify") && request.method() === "POST",
  );
  await page.getByRole("button", { name: "Re-verify Retired synthetic campaign" }).click();
  await verifyRequest;
  await expect(page.getByText("0 waiting", { exact: true })).toBeVisible();
  await expect(page.getByText("Retired synthetic campaign", { exact: true })).toBeHidden();
  await page.getByText("Awaiting re-verification", { exact: true }).click();
  await expect(page.getByText(/verified: no original findings remain/i)).toBeVisible();
});

test("remediation remains horizontally contained on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await routeRemediation(page);
  await page.goto("/remediation");
  await expect(page.getByRole("heading", { name: "Risk campaigns" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1)).toBe(false);
});

const control = (code: string, name: string, status: "pass" | "warning" | "fail", findings: number) => ({
  code, name, status, findings, severity_breakdown: {}, affected_packages: [], affected_agents: [],
});

async function routeCompliance(page: Page) {
  await routeShell(page);
  const emptySummary = Object.fromEntries(
    ["owasp", "owasp_mcp", "atlas", "nist", "owasp_agentic", "eu_ai_act", "nist_csf", "iso_27001", "soc2", "cis", "cmmc", "nist_800_53", "fedramp", "pci_dss"]
      .flatMap((key) => [[`${key}_pass`, 0], [`${key}_warn`, 0], [`${key}_fail`, 0]]),
  );
  await page.route("**/v1/compliance/report/pack", (route) => route.fulfill({
    contentType: "application/json",
    headers: { "content-disposition": 'attachment; filename="compliance-pack.json"' },
    body: JSON.stringify({ schema_version: "compliance-pack.v1", synthetic: true }),
  }));
  await page.route("**/v1/frameworks/catalogs", (route) => route.fulfill({ json: { frameworks: {} } }));
  await page.route("**/v1/compliance/hub/posture", (route) => route.fulfill({ json: { totals: { combined: 0, native: 0, hub: 0 } } }));
  await page.route("**/v1/compliance/nist-800-53**", (route) => route.fulfill({ status: 503, json: { detail: "Not part of this focused fixture" } }));
  await page.route("**/v1/compliance", (route) => route.fulfill({ json: {
    overall_score: 72,
    overall_status: "warning",
    scan_count: 3,
    latest_scan: CREATED_AT,
    has_mcp_context: true,
    has_agent_context: true,
    scan_sources: ["synthetic-e2e"],
    owasp_llm_top10: [
      control("LLM01", "Prompt Injection", "fail", 4),
      control("LLM02", "Insecure Output Handling", "pass", 0),
    ],
    owasp_mcp_top10: [control("MCP01", "Tool Poisoning", "warning", 1)],
    mitre_atlas: [], nist_ai_rmf: [], owasp_agentic_top10: [], eu_ai_act: [], nist_csf: [],
    iso_27001: [], soc2: [], cis_controls: [], cmmc: [], nist_800_53: [], fedramp: [], pci_dss: [],
    aisvs_benchmark: { checks: [], summary: {} },
    summary: { ...emptySummary, owasp_pass: 1, owasp_fail: 1, owasp_mcp_warn: 1, aisvs_pass: 0, aisvs_fail: 0, aisvs_error: 0, aisvs_not_applicable: 0 },
  } }));
}

test("compliance view, filter, search, and evidence-pack actions are wired", async ({ page }) => {
  await routeCompliance(page);
  await page.goto("/compliance");
  await expect(page.getByTestId("compliance-kpi-strip")).toBeVisible();

  await page.getByRole("button", { name: "Heatmap", exact: true }).click();
  await expect(page.getByText("Compliance Heatmap", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Detail", exact: true }).click();

  await page.getByRole("button", { name: "Fail", exact: true }).click();
  await expect(page.getByText("Prompt Injection", { exact: true })).toBeVisible();
  await expect(page.getByText("Insecure Output Handling", { exact: true })).toBeHidden();
  await page.getByPlaceholder("Search control, package, agent").fill("Prompt");
  await expect(page.getByText("Prompt Injection", { exact: true })).toBeVisible();

  const packRequest = page.waitForRequest((request) =>
    request.url().endsWith("/v1/compliance/report/pack") && request.method() === "GET",
  );
  await page.getByTestId("compliance-export-pack").click();
  await packRequest;
  await expect(page.getByTestId("compliance-export-pack")).toContainText("Export pack");
});
