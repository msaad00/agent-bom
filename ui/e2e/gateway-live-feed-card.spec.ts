import { expect, test } from "@playwright/test";

// Renders the unified activity stream against mocked gateway data — including
// a deliberately overlong agent/target path — and captures it at a narrow
// (390px) and wide (1280px) viewport to prove text stays contained.

const SHOTS = `${process.env.LIVE_FEED_SHOT_DIR ?? "screenshots"}`;

const feedEvents = [
  {
    ts: "2026-06-26T14:31:07Z",
    agent: "payroll-agent",
    action_type: "data_filter_applied",
    target: "snowflake.query",
    detail: "Resume data masked",
    tenant: "eng-team",
    shadow: false,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:30:52Z",
    agent: "extremely-long-undeclared-shadow-mcp-client-instance-name-0xdeadbeef",
    action_type: "tool_call_blocked",
    target: "github.create_pull_request_with_a_very_long_action_identifier_overflow_probe",
    detail: "Shadow AI detected",
    tenant: "platform",
    shadow: true,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:30:41Z",
    agent: "support-copilot",
    action_type: "tool_call_authorized",
    target: "zendesk.update_ticket",
    detail: "authorized",
    tenant: "support",
    shadow: false,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:30:18Z",
    agent: "finance-reconciliation-agent",
    action_type: "tool_call_blocked",
    target: "stripe.create_refund",
    detail: "Amount exceeds policy ceiling",
    tenant: "finance",
    shadow: false,
    source: "proxy",
  },
  {
    ts: "2026-06-26T14:29:55Z",
    agent: "data-analyst-agent",
    action_type: "llm_call",
    target: "anthropic/claude-opus-4",
    detail: "$0.0142 · 3,210 tokens",
    tenant: "analytics",
    shadow: false,
    source: "observability",
  },
];

test("unified activity stream renders without overflow at both widths", async ({
  page,
}) => {
  await page.route("**/health", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ status: "ok" }) }),
  );
  await page.route("**/v1/auth/me", (route) =>
    route.fulfill({
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
        request_id: "req-feed-e2e",
        trace_id: "trace-feed-e2e",
        span_id: "span-feed-e2e",
      }),
    }),
  );
  await page.route("**/v1/activity**", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema_version: "activity.timeline.v2",
        tenant_id: "default",
        window_days: 30,
        event_count: 0,
        truncated: false,
        status: "empty",
        events: [],
        sources: [
          { source: "runtime", status: "empty", event_count: 0, detail: "" },
          {
            source: "snowflake",
            status: "active",
            event_count: 0,
            detail: "",
            timeline: {
              account: "synthetic-responsive-fixture",
              discovered_at: "2026-06-26T14:31:07Z",
              summary: {
                total_queries: 0,
                agent_queries: 0,
                observability_events: 0,
                unique_agents: 5,
                tool_calls: 5,
              },
              query_history: [],
              observability_events: [],
              warnings: [],
            },
          },
        ],
      }),
    }),
  );
  await page.route("**/v1/gateway/feed*", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema_version: "1.0",
        tenant_id: "default",
        generated_at: "2026-06-26T14:31:07Z",
        count: feedEvents.length,
        events: feedEvents,
        health: {
          state: "live",
          live: true,
          heartbeat_at: "2026-06-26T14:31:07Z",
          age_seconds: 0,
          stale_after_seconds: 120,
          reason: "fresh_transport_heartbeat",
        },
      }),
    }),
  );

  const stream = page.getByTestId("activity-event-stream");

  // Narrow (mobile) viewport.
  await page.setViewportSize({ width: 390, height: 900 });
  await page.goto("/activity");
  await expect(stream).toBeVisible();
  await expect(stream.getByRole("heading", { name: "Event stream" })).toBeVisible();
  await expect(stream.getByText("Live gateway")).toBeVisible();
  await expect(stream.getByText(/extremely-long-undeclared-shadow/)).toBeVisible();

  // No event row extends past the stream's right edge.
  const streamBox = await stream.boundingBox();
  const rows = stream.locator("li > button");
  const rowCount = await rows.count();
  expect(rowCount).toBeGreaterThan(0);
  for (let i = 0; i < rowCount; i++) {
    const box = await rows.nth(i).boundingBox();
    if (box && streamBox) {
      expect(box.x + box.width).toBeLessThanOrEqual(streamBox.x + streamBox.width + 1);
    }
  }
  await stream.screenshot({ path: `${SHOTS}/activity-event-stream-390.png` });

  // Wide (desktop) viewport.
  await page.setViewportSize({ width: 1280, height: 900 });
  await expect(stream).toBeVisible();
  await stream.screenshot({ path: `${SHOTS}/activity-event-stream-1280.png` });
});
