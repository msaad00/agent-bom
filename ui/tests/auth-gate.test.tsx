import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthGate } from "@/components/auth-gate";
import { AuthProvider } from "@/components/auth-provider";
import { clearSessionApiKey } from "@/lib/auth";

const mockReplace = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockReplace, push: vi.fn() }),
  usePathname: () => "/agents",
  useSearchParams: () => new URLSearchParams(),
}));

const originalFetch = global.fetch;

afterEach(() => {
  window.history.replaceState({}, "", "/");
  global.fetch = originalFetch;
  window.__AGENT_BOM_CONFIG__ = undefined;
  clearSessionApiKey();
  mockReplace.mockReset();
  vi.restoreAllMocks();
});

describe("AuthGate", () => {
  it("renders protected content when auth is not required", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: () => Promise.resolve({
        authenticated: false,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: null,
        tenant_id: "default",
        role_summary: null,
        memberships: [],
        request_id: null,
        trace_id: null,
        span_id: null,
      }),
    }) as typeof fetch;

    render(
      <AuthProvider>
        <AuthGate>
          <div>protected surface</div>
        </AuthGate>
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.getByText("protected surface")).toBeInTheDocument());
  });

  it("redirects unauthenticated users to /login", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: () => Promise.resolve({ detail: "Unauthorized — invalid API key" }),
    }) as typeof fetch;

    render(
      <AuthProvider>
        <AuthGate>
          <div>protected surface</div>
        </AuthGate>
      </AuthProvider>,
    );

    await waitFor(() =>
      expect(mockReplace).toHaveBeenCalledWith("/login?returnTo=%2Fagents"),
    );
    expect(screen.queryByText("protected surface")).not.toBeInTheDocument();
  });

  it("preserves the login query and selected-path anchor", async () => {
    window.history.replaceState({}, "", "/agents?scan=scan-2&path=13#selected-path");
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401, json: async () => ({detail: "Unauthorized"}) });
    render(<AuthProvider><AuthGate><div>private</div></AuthGate></AuthProvider>);
    await waitFor(() => expect(mockReplace).toHaveBeenCalledWith("/login?returnTo=%2Fagents%3Fscan%3Dscan-2%26path%3D13%23selected-path"));
  });

  it("recovers a separately served loopback UI through the ephemeral dev session", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        json: () => Promise.resolve({ detail: "Unauthorized" }),
      })
      .mockResolvedValueOnce({ ok: true, status: 204, statusText: "No Content" })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: "OK",
        json: () => Promise.resolve({
          authenticated: true,
          auth_required: true,
          configured_modes: ["api_key"],
          recommended_ui_mode: "session_api_key",
          auth_method: "browser_session_dev_key",
          subject: "loopback-dev-key",
          role: "admin",
          tenant_id: "default",
          role_summary: { capabilities: [] },
          memberships: [],
          request_id: null,
          trace_id: null,
          span_id: null,
        }),
      }) as typeof fetch;

    render(
      <AuthProvider>
        <AuthGate>
          <div>local dev surface</div>
        </AuthGate>
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.getByText("local dev surface")).toBeInTheDocument());
    expect(global.fetch).toHaveBeenNthCalledWith(
      2,
      "/v1/auth/dev-session",
      expect.objectContaining({ method: "POST", credentials: "include" }),
    );
  });

  it("recovers silently from a single aborted probe without flashing the fatal state", async () => {
    const abortError = Object.assign(new Error("Fetch is aborted"), { name: "AbortError" });
    global.fetch = vi
      .fn()
      .mockRejectedValueOnce(abortError)
      .mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: () =>
          Promise.resolve({
            authenticated: false,
            auth_required: false,
            configured_modes: [],
            recommended_ui_mode: "no_auth",
            auth_method: null,
            subject: null,
            role: null,
            tenant_id: "default",
            role_summary: null,
            memberships: [],
            request_id: null,
            trace_id: null,
            span_id: null,
          }),
      }) as typeof fetch;

    render(
      <AuthProvider>
        <AuthGate>
          <div>protected surface</div>
        </AuthGate>
      </AuthProvider>,
    );

    // The retry lands on the second attempt; the fatal screen never renders.
    await waitFor(() => expect(screen.getByText("protected surface")).toBeInTheDocument());
    expect(screen.queryByText("Control plane unreachable")).not.toBeInTheDocument();
  });

  it("shows the fatal control-plane state after the probe keeps aborting", async () => {
    const abortError = Object.assign(new Error("Fetch is aborted"), { name: "AbortError" });
    global.fetch = vi.fn().mockRejectedValue(abortError) as typeof fetch;

    render(
      <AuthProvider>
        <AuthGate>
          <div>protected surface</div>
        </AuthGate>
      </AuthProvider>,
    );

    await waitFor(
      () => expect(screen.getByText("Control plane unreachable")).toBeInTheDocument(),
      { timeout: 3000 },
    );
    expect(screen.queryByText("protected surface")).not.toBeInTheDocument();
  });

  it("blocks protected content when auth discovery gets a server error", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: () => Promise.resolve({ detail: "500 Internal Server Error" }),
      headers: new Headers(),
      url: "/v1/auth/me",
    }) as typeof fetch;

    render(
      <AuthProvider>
        <AuthGate>
          <div>page-level offline state</div>
        </AuthGate>
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.getByText("Control plane unreachable")).toBeInTheDocument());
    expect(screen.queryByText("page-level offline state")).not.toBeInTheDocument();
  });
});
