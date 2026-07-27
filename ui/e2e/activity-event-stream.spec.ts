import { expect, test, type Page } from "@playwright/test";

async function routeActivity(page: Page) {
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
        role: "admin",
        role_summary: {
          role: "admin",
          ui_role: "admin",
          display_name: "Admin",
          capabilities: ["audit.read"],
        },
        tenant_id: "synthetic-e2e",
        memberships: [],
      },
    }),
  );
  await page.route("**/v1/posture/counts", (route) =>
    route.fulfill({
      json: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
        kev: 0,
        compound_issues: 0,
      },
    }),
  );
  await page.route("**/v1/gateway/feed**", (route) =>
    route.fulfill({
      json: {
        schema_version: "gateway.feed.v1",
        tenant_id: "synthetic-e2e",
        generated_at: "2026-07-26T17:00:02Z",
        count: 1,
        events: [
          {
            event_id: "gateway-browser",
            ts: "2026-07-26T17:00:00Z",
            agent: "build-agent",
            action_type: "tool_call_blocked",
            target: "filesystem.write_file",
            decision: "deny",
            policy_source: "runtime-policy",
            trace_id: "trace-gateway-browser",
            detail: "blocked by gateway policy",
            tenant: "synthetic-e2e",
            shadow: false,
            source: "gateway",
          },
        ],
        health: {
          state: "live",
          live: true,
          heartbeat_at: "2026-07-26T17:00:01Z",
          age_seconds: 1,
          stale_after_seconds: 120,
          reason: "recent_transport_heartbeat",
        },
      },
    }),
  );
  await page.route("**/v1/activity**", (route) =>
    route.fulfill({
      json: {
        account: "synthetic-account",
        discovered_at: "2026-07-26T17:00:02Z",
        summary: {
          total_queries: 1,
          agent_queries: 1,
          observability_events: 1,
          unique_agents: 2,
          tool_calls: 2,
        },
        query_history: [
          {
            query_id: "query-browser",
            query_text: "select synthetic evidence",
            user_name: "audit-reader",
            role_name: "read_only",
            start_time: "2026-07-26T16:58:00Z",
            execution_status: "SUCCESS",
            query_type: "SELECT",
            is_agent_query: true,
            agent_pattern: "evidence-read",
            execution_time_ms: 24,
          },
        ],
        observability_events: [
          {
            event_id: "observation-browser",
            event_type: "TOOL_CALL",
            agent_name: "review-agent",
            timestamp: "2026-07-26T16:59:00Z",
            duration_ms: 42,
            status: "SUCCESS",
            model_name: "",
            tool_name: "repository.read",
            trace_id: "trace-observation-browser",
            input_tokens: 12,
            output_tokens: 8,
          },
        ],
        warnings: [],
      },
    }),
  );
}

test("activity merges observed events and opens evidence details", async ({ page }) => {
  await routeActivity(page);
  await page.goto("/activity");

  await expect(page.getByRole("heading", { name: "Agent Activity Timeline" })).toBeVisible();
  await expect(page.getByText("Live gateway")).toBeVisible();
  await expect(page.getByText("build-agent → filesystem.write_file")).toBeVisible();
  await expect(page.getByText("review-agent → repository.read")).toBeVisible();

  await page.getByText("build-agent → filesystem.write_file").click();
  const drawer = page.getByRole("dialog", { name: "Activity event details" });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText("runtime-policy")).toBeVisible();
  await expect(drawer.getByText("trace-gateway-browser")).toBeVisible();
  await expect(drawer.getByText("Unavailable").first()).toBeVisible();

  await drawer.getByRole("button", { name: "Close" }).last().click();
  await expect(drawer).toBeHidden();
  await expect(page.getByRole("heading", { name: /Query history/ })).toBeVisible();
});
