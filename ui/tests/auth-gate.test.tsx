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
