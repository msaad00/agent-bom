import { expect, test } from "@playwright/test";

// Renders the gateway live-feed card (#54) against mocked live data — including
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

const kpis = {
  schema_version: "1.0",
  tenant_id: "default",
  generated_at: "2026-06-26T14:31:07Z",
  calls_today: 4485,
  blocked_today: 312,
  shadow_ai_blocked: 247,
  data_filters_applied: 1893,
  tool_calls_authorized: 4173,
  llm_calls: 1204,
  uptime_seconds: 18732,
};

test("gateway live feed card renders without overflow at both widths", async ({
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
  await page.route("**/v1/gateway/feed/kpis", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify(kpis) }),
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
      }),
    }),
  );

  const card = page.getByTestId("gateway-live-feed");

  // Narrow (mobile) viewport.
  await page.setViewportSize({ width: 390, height: 900 });
  await page.goto("/activity");
  await expect(card).toBeVisible();
  await expect(card.getByText("Gateway Live Feed")).toBeVisible();
  await expect(card.getByText(/4,485 calls today/)).toBeVisible();

  // No row's content extends past the card's right edge.
  const cardBox = await card.boundingBox();
  const codeEls = card.locator("code");
  const codeCount = await codeEls.count();
  expect(codeCount).toBeGreaterThan(0);
  for (let i = 0; i < codeCount; i++) {
    const box = await codeEls.nth(i).boundingBox();
    if (box && cardBox) {
      expect(box.x + box.width).toBeLessThanOrEqual(cardBox.x + cardBox.width + 1);
    }
  }
  await card.screenshot({ path: `${SHOTS}/live-feed-card-390.png` });

  // Wide (desktop) viewport.
  await page.setViewportSize({ width: 1280, height: 900 });
  await expect(card).toBeVisible();
  await card.screenshot({ path: `${SHOTS}/live-feed-card-1280.png` });
});
