import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, afterEach } from "vitest";

import { AuthGate } from "@/components/auth-gate";
import { AuthProvider } from "@/components/auth-provider";
import { clearSessionApiKey } from "@/lib/auth";

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  window.__AGENT_BOM_CONFIG__ = undefined;
  clearSessionApiKey();
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

  it("shows the browser session form when the API returns 401 without prefilled browser storage", async () => {
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

    await waitFor(() => expect(screen.getByText("Control-plane authentication required")).toBeInTheDocument());
    expect(screen.getByLabelText("API key")).toHaveValue("");
  });
});
