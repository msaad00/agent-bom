import { expect, test } from "@playwright/test";

const profile = { config_id: "finance-prod", tenant_id: "tenant-a", name: "Finance production", identity_id: "identity-a", profile_id: "finance", revision: 3, status: "active", revoked: false, issuer: "agent-bom", environment: "prod", connector_ids: ["filesystem"], allowed_tools: ["read_file"], required_scopes: ["tools:read"], policy_ids: ["policy-finance"], connection_ids: [], expires_at: "" };
const event = (i: number) => ({ tenant_id: "tenant-a", event_id: `event-${i}`, ingest_ordinal: i, event_type: i % 3 ? "gateway.tool_call.allowed" : "gateway.runtime_profile.blocked", event_timestamp: "2026-09-08T12:00:00Z", ingested_at: "2026-09-08T12:00:01Z", agent_id: i === 3 ? "extremely-long-payroll-agent-name-used-to-verify-mobile-wrapping" : "payroll-agent", identity_id: "identity-a", upstream: "filesystem", tool: "read_file", decision: i % 3 ? "allow" : "deny", profile_id: "finance-prod", profile_revision: 3, blueprint_id: "finance", blueprint_revision: 1, policy_ids: ["policy-finance"], policy_id: "policy-finance", evidence_id: "evidence-7", trace_id: "trace-7", reason_code: i % 3 ? "resolved" : "environment_mismatch", data_action: "", development_mode: false });
const frame = (start: number, count: number, cursor: string) => `event: activity\nid: ${cursor}\ndata: ${JSON.stringify({ schema_version: "gateway.activity.stream.v1", tenant_id: "tenant-a", events: Array.from({ length: count }, (_, i) => event(start + i)), next_cursor: cursor, has_more: false, retention_floor_ordinal: 1, latest_ordinal: start + count - 1 })}\n\n`;

for (const theme of ["light", "dark"] as const) {
  test(`profile lifecycle and resumed activity in authenticated ${theme} fixture`, async ({ page }, testInfo) => {
    await page.addInitScript(value => { localStorage.setItem("agent-bom-theme", value); document.cookie = "agent_bom_csrf=runtime-fixture; path=/"; }, theme);
    let streamRequests = 0;
    let revision = 3;
    let revoked = false;
    let created = false;
    const cursors: (string | undefined)[] = [];
    const writes: string[] = [];
    const sockets: string[] = [];
    page.on("websocket", socket => sockets.push(socket.url()));
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", async route => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      const method = request.method();
      let body: unknown = {};
      if (path === "/v1/auth/me") body = { authenticated: true, auth_required: true, configured_modes: ["session"], auth_method: "session", subject: "fixture-operator", tenant_id: "tenant-a", role: "admin", role_summary: { role: "admin", capabilities: ["inventory.read", "policy.manage"] }, memberships: [] };
      else if (path === "/v1/gateway/feed/stream") {
        cursors.push(request.headers()["last-event-id"]);
        expect(request.headers()["x-agent-bom-csrf"]).toBe("runtime-fixture");
        streamRequests += 1;
        const body = streamRequests === 1 ? frame(1, 3, "cursor-3") : streamRequests === 2 ? frame(4, 3, "cursor-6") : 'event: gap\ndata: {"reason":"cursor_expired"}\n\n';
        return route.fulfill({ contentType: "text/event-stream", body });
      } else if (path === "/v1/gateway/feed/kpis") body = { calls_today: 6, blocked_today: 2, shadow_ai_blocked: 1, data_filters_applied: 0, health: { state: "live", live: true, heartbeat_at: "2026-09-08T12:00:01Z", age_seconds: 1, stale_after_seconds: 120 }, by_action_type: {}, by_source: {} };
      else if (path === "/v1/gateway/policies") body = { policies: [], count: 0 };
      else if (path === "/v1/gateway/stats") body = null;
      else if (path === "/v1/gateway/audit") body = { entries: [], count: 0 };
      else if (path === "/v1/posture/counts") body = { has_gateway: true, has_proxy: false, has_traces: true, scan_count: 1, deployment_mode: "local" };
      else if (path === "/v1/mcp-config/assignments" && method === "POST") {
        expect(request.postDataJSON()).toMatchObject({ identity_id: "identity-b", profile_id: "finance", connector_ids: ["filesystem"] });
        created = true; writes.push("create"); body = { assignment: { ...profile, config_id: "analytics-prod", name: "Analytics production" } };
      } else if (path === "/v1/mcp-config/assignments") body = { assignments: [{ ...profile, revision, revoked, status: revoked ? "revoked" : "active" }, ...(created ? [{ ...profile, config_id: "analytics-prod", name: "Analytics production" }] : [])] };
      else if (path === "/v1/identities") body = { identities: [{ identity_id: "identity-b", agent_id: "analytics-agent", blueprint_id: "finance", status: "active" }] };
      else if (path === "/v1/runtime/profiles/evaluate") body = { profile_allowed: true, reason_code: "resolved", scope: "profile_contract_only", executed: false };
      else if (path === "/v1/mcp-config/assignments/finance-prod" && method === "PUT") {
        expect(request.postDataJSON().expected_revision).toBe(3); revision = 4; writes.push("update"); body = { assignment: { ...profile, revision } };
      } else if (path.endsWith("/finance-prod/revoke")) { revoked = true; writes.push("revoke"); body = { assignment: { ...profile, revoked } }; }
      if (["POST", "PUT"].includes(method)) expect(request.headers()["x-agent-bom-csrf"]).toBe("runtime-fixture");
      return route.fulfill({ json: body });
    });
    await page.setViewportSize({ width: 1280, height: 1000 });
    await page.goto("/runtime?tab=gateway");
    const feed = page.getByRole("region", { name: "Gateway activity", exact: true });
    await expect(feed.getByTestId("gateway-activity-row")).toHaveCount(6);
    await expect(feed.getByText(/Activity gap:/)).toBeVisible();
    expect(cursors.slice(0, 3)).toEqual([undefined, "cursor-3", "cursor-6"]);
    expect(sockets.filter(url => url.includes("proxy/metrics"))).toEqual([]);
    await expect(feed.getByText(/Evidence: evidence-7/).first()).toBeVisible();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ fullPage: true, path: testInfo.outputPath(`activity-${theme}-desktop.png`) });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.locator("#main-content")).toHaveCSS("padding-left", "0px");
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ fullPage: true, path: testInfo.outputPath(`activity-${theme}-mobile.png`) });
    await page.getByRole("button", { name: "Runtime profiles", exact: true }).click();
    const profiles = page.getByRole("region", { name: "Runtime profiles", exact: true });
    await profiles.getByRole("button", { name: "Validate profile" }).click();
    await expect(profiles.getByText(/Simulation only/)).toBeVisible();
    await profiles.getByRole("button", { name: "Inspect profile" }).click();
    await profiles.getByLabel("Environment", { exact: true }).fill("staging");
    await profiles.getByRole("button", { name: "Save profile revision" }).click();
    await expect(profiles.getByText(/Finance production · active · revision 4/)).toBeVisible();
    await profiles.getByRole("button", { name: "Create profile", exact: true }).click();
    await profiles.getByLabel("Managed identity").selectOption("identity-b");
    await profiles.getByLabel("Profile name").fill("Analytics production");
    await profiles.getByLabel("Upstream connector IDs (comma separated)").fill("filesystem");
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ fullPage: true, path: testInfo.outputPath(`profiles-${theme}-mobile.png`) });
    await page.setViewportSize({ width: 1280, height: 1000 });
    await expect(page.locator("#main-content")).toHaveCSS("padding-left", "240px");
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ fullPage: true, path: testInfo.outputPath(`profiles-${theme}-desktop.png`) });
    await profiles.getByRole("button", { name: "Create managed profile" }).click();
    await expect(profiles.getByRole("heading", { name: /Analytics production/ })).toBeVisible();
    await profiles.getByRole("article").filter({ hasText: "Finance production" }).getByRole("button", { name: "Revoke profile", exact: true }).click();
    expect(writes).toEqual(["update", "create"]);
    await profiles.getByRole("button", { name: "Confirm revoke" }).click();
    await expect(profiles.getByText(/Finance production · revoked/)).toBeVisible();
    expect(writes).toEqual(["update", "create", "revoke"]);
  });
}
