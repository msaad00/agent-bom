import { expect, test, type Page } from "@playwright/test";

const finding = {
  id: "finding-workspace-e2e",
  finding_class: "vulnerability",
  finding_type: "vulnerability",
  severity: "critical",
  effective_severity: "critical",
  cve_id: "CVE-2026-4242",
  title: "Synthetic deserialization finding",
  description: "Synthetic evidence used to verify task-specific workspaces.",
  asset: {
    name: "pyyaml",
    identifier: "pkg:pypi/pyyaml@5.3",
    stable_id: "pkg:pypi/pyyaml@5.3",
    asset_type: "package",
  },
  source: "osv",
  scan_sources: ["synthetic-e2e"],
  scan_id: "scan-workspace-e2e",
  cvss_score: 9.8,
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  epss_score: 0.72,
  is_kev: true,
  fixed_version: "6.0.2",
  remediation_versions: ["6.0.2"],
  status: "open",
  first_seen: "2026-07-01T12:00:00Z",
  last_seen: "2026-07-26T16:00:00Z",
  last_observed: "2026-07-26T16:00:00Z",
  occurrence_count: 4,
  compliance_tags: ["SOC2-CC7.1", "NIST-SI-2"],
  owner: "security-platform",
  sla_due_at: "2026-07-29T12:00:00Z",
  affected_agents: ["review-agent"],
  evidence: {
    package_version: "5.3",
    epss_percentile: 98.2,
    severity_source: "nvd",
    match_confidence_tier: "osv_range",
  },
};

async function routeFindings(page: Page) {
  await page.route("**/v1/**", (route) =>
    route.fulfill({ status: 503, json: { detail: "Unavailable outside focused fixture" } }),
  );
  await page.route("**/health", (route) =>
    route.fulfill({ json: { status: "ok", version: "0.98.1" } }),
  );
  await page.route("**/version", (route) =>
    route.fulfill({ json: { version: "0.98.1" } }),
  );
  await page.route("**/v1/auth/me", (route) =>
    route.fulfill({
      json: {
        authenticated: true,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: "analyst",
        role_summary: {
          role: "analyst",
          ui_role: "analyst",
          display_name: "Analyst",
          capabilities: ["findings.read", "findings.write"],
        },
        tenant_id: "synthetic-e2e",
        memberships: [],
      },
    }),
  );
  await page.route("**/v1/posture/counts", (route) =>
    route.fulfill({
      json: {
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        total: 1,
        kev: 1,
        compound_issues: 0,
      },
    }),
  );
  await page.route("**/v1/jobs**", (route) =>
    route.fulfill({
      json: {
        schema_version: "v1",
        jobs: [],
        count: 0,
        total: 0,
        limit: 200,
        offset: 0,
        status_counts: {},
      },
    }),
  );
  await page.route("**/v1/findings/triage**", (route) =>
    route.fulfill({
      json: {
        triage: [
          {
            id: "triage-workspace-e2e",
            vulnerability_id: "CVE-2026-4242",
            package: "pyyaml",
            server_name: "",
            queue_state: "decided",
            decision: "not_affected",
            decision_reason: "Synthetic browser contract.",
            justification: "vulnerable_code_not_in_execute_path",
            assignee: "security-platform",
            created_by: "operator",
            created_at: "2026-07-26T16:05:00Z",
            reviewed_at: "2026-07-26T16:10:00Z",
            expires_at: "2026-08-09T16:10:00Z",
            tenant_id: "synthetic-e2e",
            vex_eligible: true,
          },
        ],
        count: 1,
      },
    }),
  );
  await page.route("**/v1/findings?**", (route) =>
    route.fulfill({
      json: {
        schema_version: "v1",
        findings: [finding],
        count: 1,
        total: 1,
        total_approximate: false,
        limit: 25,
        offset: 0,
        sort: "severity",
        cursor: "",
        next_cursor: "",
        has_more: false,
        warnings: [],
        window: {
          days: 90,
          since: "2026-04-27T00:00:00Z",
          applied: true,
          label: "Last 90 days",
        },
        facets: {
          finding_class: {
            vulnerability: 1,
            misconfiguration: 0,
            secret: 0,
            identity: 0,
            unclassified: 0,
          },
          severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
          status: { open: 1, resolved: 0 },
          domain: { cspm: 0, vuln: 1, aspm: 0, dspm: 0, aispm: 0 },
          freshness: {
            last_24_hours: 1,
            last_7_days: 0,
            last_30_days: 0,
            older: 0,
            unavailable: 0,
          },
        },
        facets_approximate: false,
      },
    }),
  );
}

test("engineering and compliance findings expose different task workflows", async ({ page }) => {
  await routeFindings(page);
  await page.goto("/findings?scope=all");

  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Engineering findings summary" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Reach / exploit" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Fix & verify" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Control mapping" })).toHaveCount(0);

  await page.getByRole("button", { name: "Compliance", exact: true }).click();
  await expect.poll(() => new URL(page.url()).searchParams.get("lens")).toBe("trust");
  await expect(page.getByRole("region", { name: "Compliance findings summary" })).toBeVisible();
  await expect(page.getByText("Disposition queue", { exact: true })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Control mapping" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Evidence freshness" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Disposition / attestation" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Reach / exploit" })).toHaveCount(0);

  await page.getByRole("button", { name: "Open details for CVE-2026-4242" }).click();
  const drawer = page.getByRole("dialog", { name: "Finding details for CVE-2026-4242" });
  await expect(drawer.getByText("Evidence & disposition")).toBeVisible();
  await expect(drawer.getByRole("tab", { name: "Evidence" })).toHaveAttribute("aria-selected", "true");
});
