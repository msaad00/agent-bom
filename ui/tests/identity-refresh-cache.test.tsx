import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import IdentityPage from "@/app/identity/page";
import { api, _clearApiCacheForTests } from "@/lib/api";

vi.mock("@/lib/auth", () => ({ getSessionAuthHeaders: () => ({}) }));

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); _clearApiCacheForTests(); });

it("Refresh evidence bypasses a successful cached list before its five-second expiry", async () => {
  _clearApiCacheForTests();
  vi.spyOn(Date, "now").mockReturnValue(1_000);
  let active = false;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(String(input), "http://localhost").pathname;
    const responses: Record<string, unknown> = {
      "/v1/identities": { identities: [] },
      "/v1/identity-jit-grants": { grants: active ? [{ grant_id: "one", agent_id: "billing", status: "active", tool_name: "read_record" }] : [] },
      "/v1/conditional-access-policies": { policies: [] },
      "/v1/auth/secrets/credential-expiry": { status: "ok", evaluated: 0, counts: {}, credentials: [], action_required: [] },
      "/v1/identities/access-reviews": { campaigns: [] },
      "/v1/identities/discover": { count: 0, providers: [{ provider: "okta", status: "disabled", count: 0 }], warnings: [] },
      "/v1/graph/nhi/governance": { scan_id: "fixture", counts: {}, identities: [] },
    };
    if (!(path in responses)) throw new Error("Unexpected fixture request");
    return new Response(JSON.stringify(responses[path]), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  await api.listJitGrants(true, 200);
  render(<IdentityPage />);
  await screen.findByRole("button", { name: "Refresh evidence" });
  const tile = () => within(screen.getByText("Active JIT grants").closest("div")!.parentElement!);
  expect(tile().getByText("0")).toBeVisible();
  active = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh evidence" }));
  await waitFor(() => expect(tile().getByText("1")).toBeVisible());
  for (const path of ["/v1/identities", "/v1/identity-jit-grants", "/v1/conditional-access-policies",
    "/v1/auth/secrets/credential-expiry", "/v1/identities/access-reviews", "/v1/graph/nhi/governance"]) {
    await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => new URL(String(url), "http://localhost").pathname === path)).toHaveLength(2));
  }
});
